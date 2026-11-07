"""Immutable data contracts for OmniPatch."""

from dataclasses import dataclass
from enum import StrEnum
from hashlib import blake2b
from pathlib import PurePosixPath

from omnipatch.codebase.redaction import redact


class Severity(StrEnum):
    """Severity levels ordered for filtering."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Return LOW=0 through CRITICAL=3."""
        return (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL).index(
            self
        )


@dataclass(frozen=True, slots=True)
class Finding:
    """One security issue located in the target repository."""

    id: str
    rule_id: str
    title: str
    severity: Severity
    file: PurePosixPath
    line_start: int
    line_end: int
    message: str
    source: str
    cwe: str | None = None

    def __post_init__(self) -> None:
        """Validate repository-relative location and line range."""
        if self.file.is_absolute() or ".." in self.file.parts:
            raise ValueError(
                "Finding.file must be relative and contain no '..' segment"
            )
        if self.line_start < 1 or self.line_end < self.line_start:
            raise ValueError("Finding line range is invalid")

    def to_json_dict(self) -> dict[str, object]:
        """Serialize the finding to JSON-compatible values."""
        title = message = (
            "Hardcoded credential finding" if self.rule_id == "B105" else None
        )
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title if title is None else title,
            "severity": self.severity.value,
            "file": self.file.as_posix(),
            "line_start": self.line_start,
            "line_end": self.line_end,
            "message": self.message if message is None else message,
            "source": self.source,
            "cwe": self.cwe,
        }

    def __repr__(self) -> str:
        """Keep scanner-supplied B105 diagnostics out of representations."""
        title = "Hardcoded credential finding" if self.rule_id == "B105" else self.title
        message = (
            "Hardcoded credential finding" if self.rule_id == "B105" else self.message
        )
        return (
            f"Finding(id={self.id!r}, rule_id={self.rule_id!r}, title={title!r}, "
            f"severity={self.severity!r}, file={self.file!r}, "
            f"line_start={self.line_start!r}, line_end={self.line_end!r}, "
            f"message={message!r}, source={self.source!r}, cwe={self.cwe!r})"
        )

    @classmethod
    def from_json_dict(cls, raw: dict[str, object]) -> "Finding":
        """Parse a finding from JSON-compatible values."""
        return cls(
            id=str(raw["id"]),
            rule_id=str(raw["rule_id"]),
            title=str(raw["title"]),
            severity=Severity(str(raw["severity"])),
            file=PurePosixPath(str(raw["file"])),
            line_start=_require_int(raw, "line_start"),
            line_end=_require_int(raw, "line_end"),
            message=str(raw["message"]),
            source=str(raw["source"]),
            cwe=None if raw.get("cwe") is None else str(raw["cwe"]),
        )


def _require_int(raw: dict[str, object], key: str) -> int:
    """Return raw[key] as an int, rejecting bools and non-numeric values."""
    value = raw[key]
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(  # noqa: TRY004 -- JSON schema failures use ValueError
            f"{key} must be an integer, got {type(value).__name__}"
        )
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{key} must be an integer, got {value}")
    return int(value)


@dataclass(frozen=True, slots=True)
class CodeContext:
    """Source context associated with a finding."""

    finding_id: str
    snippet: str
    snippet_line_start: int
    symbol: str | None
    imports: tuple[str, ...]

    def to_json_dict(self) -> dict[str, object]:
        """Serialize context using JSON-compatible field values."""
        return {
            "finding_id": self.finding_id,
            "snippet": self.snippet,
            "snippet_line_start": self.snippet_line_start,
            "symbol": self.symbol,
            "imports": list(self.imports),
        }


@dataclass(frozen=True, slots=True)
class Patch:
    """Proposed unified diff for a finding."""

    finding_id: str
    unified_diff: str
    explanation: str
    touched_files: tuple[PurePosixPath, ...]
    model: str

    def __post_init__(self) -> None:
        """Validate minimum patch contents."""
        if not self.unified_diff.strip():
            raise ValueError("Patch.unified_diff must be non-empty")
        if not self.touched_files:
            raise ValueError("Patch.touched_files must be non-empty")

    def to_json_dict(self) -> dict[str, object]:
        """Serialize the proposed patch using JSON-compatible values."""
        safe_diff = redact(self.unified_diff)
        return {
            "finding_id": self.finding_id,
            "unified_diff": safe_diff,
            "unified_diff_redacted": safe_diff != self.unified_diff,
            "explanation": self.explanation,
            "touched_files": [path.as_posix() for path in self.touched_files],
            "model": self.model,
        }

    def __repr__(self) -> str:
        """Avoid placing source text from a diff into logs or diagnostics."""
        return (
            f"Patch(finding_id={self.finding_id!r}, unified_diff=<omitted>, "
            f"explanation={self.explanation!r}, touched_files={self.touched_files!r}, "
            f"model={self.model!r})"
        )


@dataclass(frozen=True, slots=True)
class PatchResult:
    """Result of applying and verifying a patch."""

    patch: Patch
    applied: bool
    verified: bool
    error: str | None = None
    introduced: tuple[str, ...] = ()

    def to_json_dict(self) -> dict[str, object]:
        """Serialize patch verification status using JSON-compatible values."""
        return {
            "patch": self.patch.to_json_dict(),
            "applied": self.applied,
            "verified": self.verified,
            "error": None if self.error is None else redact(self.error),
            "introduced": list(self.introduced),
        }

    def __repr__(self) -> str:
        """Avoid logging provider or scanner error text by default."""
        error = "<omitted>" if self.error is not None else None
        return (
            f"PatchResult(patch={self.patch!r}, applied={self.applied!r}, "
            f"verified={self.verified!r}, error={error!r}, "
            f"introduced={self.introduced!r})"
        )


def make_finding_id(rule_id: str, file: PurePosixPath, line_start: int) -> str:
    """Return a stable 12-hex-char identifier for a finding location."""
    payload = f"{rule_id}:{file}:{line_start}".encode()
    return blake2b(payload, digest_size=6).hexdigest()
