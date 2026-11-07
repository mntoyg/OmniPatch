"""Opt-in synthetic-only auditing for serialized Ollama request bodies."""

from __future__ import annotations

import json
import os
import re
from contextvars import ContextVar, Token
from pathlib import Path
from typing import Literal

from omnipatch.errors import PatchGenerationError

RequestPhase = Literal["initial", "repair"]
ObservedPhase = Literal["initial", "repair", "not_observed"]

_REQUEST_PHASE: ContextVar[RequestPhase | None] = ContextVar(
    "omnipatch_request_phase", default=None
)
_CANARY_ENV = "OP_SYNTHETIC_CANARY_AUDIT_VALUE"
_RECORD_ENV = "OP_SYNTHETIC_CANARY_AUDIT_RECORD"
_TRIAL_ENV = "OP_SYNTHETIC_CANARY_AUDIT_TRIAL_ID"
_CANARY_PATTERN = re.compile(r"OMNIPATCH_SYNTHETIC_CANARY_[A-Za-z0-9_-]{8,128}\Z")
_TRIAL_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_FAILURE_CATEGORIES = {"canary_match", "phase_not_observed", "auditor_error"}


class SyntheticCanaryAuditError(PatchGenerationError):
    """A value-free failure raised before an audited request is sent."""


def request_phase(phase: RequestPhase) -> Token[RequestPhase | None]:
    """Set an explicit internal phase around one completion call."""
    return _REQUEST_PHASE.set(phase)


def reset_request_phase(token: Token[RequestPhase | None]) -> None:
    """Restore the previous request phase after a completion call."""
    _REQUEST_PHASE.reset(token)


class SyntheticCanaryAuditor:
    """Check serialized request bytes and append allowlisted outcome records."""

    def __init__(self, canary: str, record_path: Path, trial_id: str) -> None:
        self._canary = canary.encode("utf-8")
        self._record_path = record_path
        self._trial_id = trial_id
        self._record_created = False

    @classmethod
    def from_environment(cls) -> SyntheticCanaryAuditor | None:
        """Load an opt-in synthetic canary without adding it to Settings."""
        values = (os.environ.get(_CANARY_ENV), os.environ.get(_RECORD_ENV))
        trial_id = os.environ.get(_TRIAL_ENV)
        if all(value is None for value in (*values, trial_id)):
            return None
        canary, record_value = values
        if (
            canary is None
            or record_value is None
            or trial_id is None
            or not _CANARY_PATTERN.fullmatch(canary)
            or not _TRIAL_PATTERN.fullmatch(trial_id)
        ):
            raise SyntheticCanaryAuditError(
                "Synthetic canary audit blocked request (auditor_error)"
            )
        try:
            configured_path = Path(record_value)
            if not configured_path.is_absolute() or configured_path.is_symlink():
                raise ValueError
            record_path = configured_path.resolve()
            target_root = Path.cwd().resolve()
            if (
                not record_path.parent.is_dir()
                or record_path.exists()
                or record_path.is_relative_to(target_root)
            ):
                raise ValueError
        except (OSError, RuntimeError, TypeError, ValueError):
            raise SyntheticCanaryAuditError(
                "Synthetic canary audit blocked request (auditor_error)"
            ) from None
        return cls(canary, record_path, trial_id)

    def check(self, request_body: bytes) -> None:
        """Record a sanitized verdict and refuse any unsafe or unobserved phase."""
        phase: ObservedPhase = _REQUEST_PHASE.get() or "not_observed"
        matched = self._canary in request_body
        failure_category = (
            "canary_match"
            if matched
            else "phase_not_observed"
            if phase == "not_observed"
            else None
        )
        outcome = "fail" if failure_category is not None else "pass"
        record: dict[str, str | int] = {
            "schema_version": 1,
            "trial_id": self._trial_id,
            "phase": phase,
            "surface": "serialized_ollama_request_body",
            "outcome": outcome,
        }
        if failure_category is not None:
            record["failure_category"] = failure_category
        try:
            encoded_record = json.dumps(record, sort_keys=True) + "\n"
            mode = "a" if self._record_created else "x"
            with self._record_path.open(mode, encoding="utf-8", newline="\n") as stream:
                stream.write(encoded_record)
            self._record_created = True
        except (OSError, RuntimeError, UnicodeError, TypeError, ValueError):
            self._raise_block("auditor_error")
        if failure_category is not None:
            self._raise_block(failure_category)

    @staticmethod
    def _raise_block(category: str) -> None:
        if category not in _FAILURE_CATEGORIES:
            category = "auditor_error"
        raise SyntheticCanaryAuditError(
            f"Synthetic canary audit blocked request ({category})"
        ) from None
