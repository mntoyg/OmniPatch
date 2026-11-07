"""Regression tests for the configured Ollama completion-token budget."""

import json
import urllib.error
import urllib.request
from typing import cast

import pytest

from omnipatch.agents.ollama_client import (
    OllamaCompletionClient,
    UrlOpener,
    UrlResponse,
)
from omnipatch.agents.registry import build_llm_client
from omnipatch.config import Settings
from omnipatch.errors import PatchGenerationError


class _Response:
    """Minimal HTTP response for offline Ollama transport tests."""

    def __init__(self, payload: object) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def close(self) -> None:
        pass


class _Opener:
    """Capture a request and provide a deterministic response or error."""

    def __init__(self, payload: object | None = None, error: Exception | None = None):
        self.payload = payload or {
            "done_reason": "stop",
            "message": {"content": "completion"},
        }
        self.error = error
        self.request: urllib.request.Request | None = None

    def __call__(
        self, request: urllib.request.Request, *, timeout: float
    ) -> UrlResponse:
        self.request = request
        if self.error is not None:
            raise self.error
        return _Response(self.payload)

    def open(self, request: urllib.request.Request, *, timeout: float) -> UrlResponse:
        """Match the opener-director method used by the hardened client."""
        return self(request, timeout=timeout)


def _options(request: urllib.request.Request) -> dict[str, object]:
    body = json.loads(cast(bytes, request.data))
    return cast(dict[str, object], body["options"])


def test_registry_sends_non_default_configured_token_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public factory carries Settings.llm_max_tokens to Ollama's request."""
    opener = _Opener()
    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)
    client = build_llm_client(
        Settings(
            _env_file=None,
            llm_provider="ollama",
            llm_model="qwen-ctx8k:latest",
            llm_output="function",
            llm_max_tokens=3072,
        )
    )

    client.complete("system", "user")

    assert opener.request is not None
    options = _options(opener.request)
    assert options["num_predict"] == 3072
    assert options["temperature"] == 0


def test_client_sends_constructed_token_budget() -> None:
    """A directly configured client sends its own budget in the transport body."""
    opener = _Opener()
    client = OllamaCompletionClient(
        "qwen-ctx8k:latest", max_tokens=4096, opener=cast(UrlOpener, opener)
    )

    client.complete("system", "user")

    assert opener.request is not None
    assert _options(opener.request)["num_predict"] == 4096


def test_client_rejects_invalid_token_budget() -> None:
    """A non-positive completion budget is rejected at the client boundary."""
    with pytest.raises(PatchGenerationError, match="token budget"):
        OllamaCompletionClient("qwen-ctx8k:latest", max_tokens=0)


def test_truncated_response_remains_fatal_without_echoing_request() -> None:
    """Truncation is fatal and request contents are not reflected in its error."""
    sentinel = "OP13_REQUEST_SENTINEL_DO_NOT_DISCLOSE"
    opener = _Opener({"done_reason": "length", "message": {"content": "partial"}})
    client = OllamaCompletionClient("qwen-ctx8k:latest", opener=cast(UrlOpener, opener))

    with pytest.raises(PatchGenerationError, match="truncated or unfinished") as error:
        client.complete("system", sentinel)

    assert sentinel not in str(error.value)


def test_timeout_error_names_settings_without_request_data() -> None:
    """Timeout diagnostics name the existing controls without leaking prompts."""
    sentinel = "OP13_TIMEOUT_SENTINEL_DO_NOT_DISCLOSE"
    opener = _Opener(error=TimeoutError())
    client = OllamaCompletionClient(
        "qwen-ctx8k:latest",
        timeout_seconds=17,
        opener=cast(UrlOpener, opener),
    )

    with pytest.raises(PatchGenerationError) as error:
        client.complete("system", sentinel)

    message = str(error.value)
    assert "OMNIPATCH_OLLAMA_TIMEOUT_SECONDS" in message
    assert "OMNIPATCH_LLM_MAX_TOKENS" in message
    assert sentinel not in message


def test_ollama_truncation_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """The transport makes one request and never salvages a partial completion."""
    opener = _Opener({"done_reason": "length", "message": {"content": "partial"}})
    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)
    client = build_llm_client(
        Settings(_env_file=None, llm_provider="ollama", llm_max_tokens=2048)
    )

    with pytest.raises(PatchGenerationError, match="truncated or unfinished"):
        client.complete("system", "user")

    assert opener.request is not None
