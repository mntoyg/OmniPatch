"""Ollama chat completion transport implemented with the Python standard library."""

from __future__ import annotations

import errno
import json
import socket
import urllib.error
import urllib.request
from typing import Protocol, cast

from omnipatch.agents.request_audit import SyntheticCanaryAuditor
from omnipatch.config import validate_local_ollama_endpoint
from omnipatch.defaults import (
    DEFAULT_LLM_MAX_TOKENS,
    DEFAULT_OLLAMA_ENDPOINT,
    DEFAULT_OLLAMA_TIMEOUT_SECONDS,
)
from omnipatch.errors import PatchGenerationError


class UrlResponse(Protocol):
    """Response surface returned by urllib's URL opener."""

    def read(self) -> bytes:
        """Read the response body."""

    def close(self) -> None:
        """Release response resources."""


class UrlOpener(Protocol):
    """Callable transport compatible with urllib.request.urlopen."""

    def __call__(
        self, request: urllib.request.Request, *, timeout: float
    ) -> UrlResponse:
        """Open a request and return its response."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so prompt bodies remain bound to the local endpoint."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


class OllamaCompletionClient:
    """Call Ollama's non-streaming chat API and return response content."""

    def __init__(
        self,
        model: str,
        endpoint: str = DEFAULT_OLLAMA_ENDPOINT,
        timeout_seconds: int = DEFAULT_OLLAMA_TIMEOUT_SECONDS,
        max_tokens: int = DEFAULT_LLM_MAX_TOKENS,
        opener: UrlOpener | None = None,
        request_auditor: SyntheticCanaryAuditor | None = None,
    ) -> None:
        """Configure the local model, request budget, timeout, and optional opener."""
        if not model.strip():
            raise PatchGenerationError("Ollama model name is required")
        if timeout_seconds < 1:
            raise PatchGenerationError("Ollama timeout must be at least one second")
        if max_tokens < 1:
            raise PatchGenerationError("Ollama token budget must be at least one")
        self.model = model
        try:
            self._endpoint = validate_local_ollama_endpoint(endpoint)
        except ValueError:
            raise PatchGenerationError(
                "OMNIPATCH_OLLAMA_ENDPOINT must be a local HTTP loopback /api/chat URL"
            ) from None
        self._timeout_seconds = timeout_seconds
        self._max_tokens = max_tokens
        self._opener = opener
        self._request_auditor = request_auditor

    def __repr__(self) -> str:
        """Return a representation containing only non-sensitive client settings."""
        return (
            f"{type(self).__name__}(model={self.model!r}, endpoint={self._endpoint!r})"
        )

    def complete(self, system: str, user: str) -> str:
        """Return Ollama message content or raise an actionable generation error."""
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        options: dict[str, int] = {
            "temperature": 0,
            "num_predict": self._max_tokens,
        }
        request_body: dict[str, object] = {
            "model": self.model,
            "stream": False,
            "messages": messages,
            "options": options,
        }
        body = json.dumps(request_body).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            if self._opener is None:
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}), _NoRedirectHandler()
                )
                open_request = cast(UrlOpener, opener.open)
            else:
                open_request = self._opener
            if self._request_auditor is not None:
                self._request_auditor.check(body)
            response = open_request(request, timeout=self._timeout_seconds)
            try:
                raw_response = response.read()
            finally:
                response.close()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise PatchGenerationError(
                    f"Ollama model '{self.model}' is not pulled; run `ollama pull {self.model}`"
                ) from None
            raise PatchGenerationError(
                f"Ollama returned HTTP {exc.code} at {self._endpoint}"
            ) from None
        except TimeoutError:
            raise PatchGenerationError(
                f"Ollama request timed out after {self._timeout_seconds} seconds; "
                "increase OMNIPATCH_OLLAMA_TIMEOUT_SECONDS or reduce "
                "OMNIPATCH_LLM_MAX_TOKENS"
            ) from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise PatchGenerationError(
                    f"Ollama request timed out after {self._timeout_seconds} seconds; "
                    "increase OMNIPATCH_OLLAMA_TIMEOUT_SECONDS or reduce "
                    "OMNIPATCH_LLM_MAX_TOKENS"
                ) from None
            if isinstance(exc.reason, ConnectionRefusedError) or (
                isinstance(exc.reason, OSError)
                and exc.reason.errno == errno.ECONNREFUSED
            ):
                raise PatchGenerationError(
                    f"Ollama is not running at {self._endpoint}; start Ollama and retry"
                ) from None
            raise PatchGenerationError(
                f"Could not connect to Ollama at {self._endpoint}"
            ) from None
        except OSError:
            raise PatchGenerationError(
                f"Could not connect to Ollama at {self._endpoint}"
            ) from None

        try:
            response_text = raw_response.decode("utf-8")
            decoded: object = cast(object, json.loads(response_text))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PatchGenerationError("Ollama returned malformed JSON") from None
        payload = _string_object_mapping(decoded)
        if payload is None:
            raise PatchGenerationError("Ollama returned malformed JSON")
        reason = payload.get("done_reason")
        if reason != "stop":
            raise PatchGenerationError(
                "Ollama output was truncated or unfinished; no response content was accepted"
            )
        message = _string_object_mapping(payload.get("message"))
        if message is None or "content" not in message:
            raise PatchGenerationError("Ollama response is missing message.content")
        content = message["content"]
        if not isinstance(content, str):
            raise PatchGenerationError("Ollama message.content is not text")
        if not content.strip():
            raise PatchGenerationError("Ollama returned empty message.content")
        return content


def _string_object_mapping(value: object) -> dict[str, object] | None:
    """Validate a decoded JSON object and narrow it without exposing Any."""
    if not isinstance(value, dict):
        return None
    entries = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in entries):
        return None
    return {cast(str, key): item for key, item in entries.items()}
