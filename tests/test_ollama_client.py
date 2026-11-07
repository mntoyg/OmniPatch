"""Offline tests for Ollama transport and provider construction."""

import json
import socket
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import cast

import pytest
from typer.testing import CliRunner

import omnipatch.agents.ollama_client as transport_module
from omnipatch.agents.llm_agent import LLMPatchAgent
from omnipatch.agents.ollama_client import (
    OllamaCompletionClient,
    UrlOpener,
    UrlResponse,
)
from omnipatch.agents.registry import build_llm_client
from omnipatch.cli import app
from omnipatch.codebase.ast_tools import extract_context
from omnipatch.config import Settings
from omnipatch.errors import ConfigError, PatchGenerationError
from omnipatch.scanners.bandit_scanner import BanditScanner

ENDPOINT = "http://127.0.0.1:11434/api/chat"
MODEL = "qwen-ctx8k:latest"


class FakeResponse:
    """Return a fixed JSON response body to the injected opener."""

    def __init__(self, payload: object) -> None:
        """Encode the provided JSON-compatible response object."""
        self.body = (
            payload
            if isinstance(payload, bytes)
            else json.dumps(payload).encode("utf-8")
        )
        self.closed = False

    def read(self) -> bytes:
        """Return the encoded response body."""
        return self.body

    def close(self) -> None:
        """Record closure of the response."""
        self.closed = True


class FakeOpener:
    """Record HTTP requests and return or raise a configured result."""

    def __init__(
        self, response: UrlResponse | None = None, error: Exception | None = None
    ) -> None:
        """Configure a response or transport exception."""
        self.response = response or FakeResponse(
            {
                "done_reason": "stop",
                "message": {"role": "assistant", "content": "fixed"},
            }
        )
        self.error = error
        self.request: urllib.request.Request | None = None
        self.timeout: float | None = None

    def __call__(
        self, request: urllib.request.Request, *, timeout: float
    ) -> UrlResponse:
        """Capture the request then return the configured response."""
        self.request = request
        self.timeout = timeout
        if self.error is not None:
            raise self.error
        return self.response


def _client(
    payload: object | None = None,
    error: Exception | None = None,
    endpoint: str = ENDPOINT,
) -> tuple[OllamaCompletionClient, FakeOpener]:
    """Build a client backed by an offline response or exception."""
    opener = FakeOpener(
        FakeResponse(payload) if payload is not None else None,
        error,
    )
    return (
        OllamaCompletionClient(
            MODEL, endpoint=endpoint, opener=cast(UrlOpener, opener)
        ),
        opener,
    )


def test_module_does_not_bind_urlopen_at_import() -> None:
    """The transport uses the monkeypatchable urllib module attribute at call time."""
    assert "urlopen" not in vars(transport_module)


def test_completion_returns_content_and_sends_measured_request_shape() -> None:
    """The non-streaming request includes both roles and deterministic options."""
    client, opener = _client()

    assert client.complete("system prompt", "user prompt") == "fixed"

    assert opener.request is not None
    assert opener.request.full_url == ENDPOINT
    assert opener.request.get_method() == "POST"
    payload = json.loads(cast(bytes, opener.request.data))
    assert payload == {
        "model": MODEL,
        "stream": False,
        "messages": [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "user prompt"},
        ],
        "options": {"temperature": 0, "num_predict": 16000},
    }
    assert opener.timeout == 300


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:11434/api/chat",
        "http://192.0.2.10:11434/api/chat",
        "http://user:SELF_LABELLED_ENDPOINT_CREDENTIAL@localhost:11434/api/chat",
        "http://localhost:11434/api/generate",
    ],
)
def test_ollama_client_rejects_unsupported_endpoint_before_transport(
    endpoint: str,
) -> None:
    """Invalid endpoints are refused before the injected transport can run."""
    calls: list[urllib.request.Request] = []

    def opener(request: urllib.request.Request, *, timeout: float) -> UrlResponse:
        calls.append(request)
        return FakeResponse({"done_reason": "stop", "message": {"content": "x"}})

    with pytest.raises(PatchGenerationError) as error:
        OllamaCompletionClient(MODEL, endpoint=endpoint, opener=opener)
    assert calls == []
    assert "SELF_LABELLED_ENDPOINT_CREDENTIAL" not in str(error.value)


def test_default_transport_refuses_redirect_without_forwarding_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default opener disables proxies and refuses redirect requests."""
    prompt = "SELF_LABELLED_REDIRECT_PROMPT_DO_NOT_FORWARD"
    remote_target = "https://redirect.example/api/chat"
    captured: dict[str, object] = {}

    class FakeOpenerDirector:
        def __init__(self, handlers: tuple[object, ...]) -> None:
            self.handlers = handlers
            self.requests: list[urllib.request.Request] = []
            self.redirected_request: urllib.request.Request | None = None

        def open(
            self, request: urllib.request.Request, *, timeout: float
        ) -> UrlResponse:
            self.requests.append(request)
            redirect_handler = next(
                handler
                for handler in self.handlers
                if isinstance(handler, urllib.request.HTTPRedirectHandler)
            )
            self.redirected_request = redirect_handler.redirect_request(
                request, None, 307, "Temporary Redirect", {}, remote_target
            )
            raise urllib.error.HTTPError(
                request.full_url, 307, "redirect refused", {}, None
            )

    def build_opener(*handlers: object) -> FakeOpenerDirector:
        director = FakeOpenerDirector(handlers)
        captured["director"] = director
        return director

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    client = OllamaCompletionClient(MODEL)
    with pytest.raises(PatchGenerationError, match="HTTP 307"):
        client.complete("synthetic system", prompt)

    director = captured["director"]
    assert isinstance(director, FakeOpenerDirector)
    assert len(director.requests) == 1
    assert director.redirected_request is None
    assert remote_target not in director.requests[0].full_url
    request_payload = json.loads(cast(bytes, director.requests[0].data))
    assert request_payload["messages"][1]["content"] == prompt
    proxy_handler = next(
        handler
        for handler in director.handlers
        if isinstance(handler, urllib.request.ProxyHandler)
    )
    assert proxy_handler.proxies == {}


@pytest.mark.parametrize(
    ("payload", "error", "message"),
    [
        (
            None,
            urllib.error.URLError(ConnectionRefusedError()),
            "Ollama is not running",
        ),
        (
            None,
            urllib.error.HTTPError(ENDPOINT, 404, "missing", {}, None),
            "ollama pull qwen-ctx8k:latest",
        ),
        (
            None,
            urllib.error.HTTPError(ENDPOINT, 503, "unavailable", {}, None),
            "HTTP 503",
        ),
        (None, TimeoutError(), "timed out after 300 seconds"),
        (b"{", None, "malformed JSON"),
        ({"done_reason": "stop", "message": {}}, None, "missing message.content"),
        (
            {"done_reason": "stop", "message": {"content": "  \n"}},
            None,
            "empty message.content",
        ),
        (
            {"done_reason": "length", "message": {"content": "truncated"}},
            None,
            "truncated or unfinished",
        ),
    ],
)
def test_transport_failures_have_actionable_distinct_messages(
    payload: object | None, error: Exception | None, message: str
) -> None:
    """Every measured network or response failure is translated distinctly."""
    client, _ = _client(payload, error)
    with pytest.raises(PatchGenerationError, match=message):
        client.complete("system", "user")


def test_ollama_untrusted_completion_metadata_is_not_echoed() -> None:
    """Response metadata is not copied into a public error message."""
    canary = "SELF_LABELLED_OLLAMA_ERROR_CANARY_DO_NOT_USE"
    client, _ = _client({"done_reason": canary, "message": {"content": "ignored"}})

    with pytest.raises(PatchGenerationError) as caught:
        client.complete("system", "synthetic request")

    if canary in str(caught.value):
        pytest.fail("synthetic canary appeared in provider error")


@pytest.mark.integration
def test_extracted_b105_context_is_safe_in_ollama_serialization(tmp_path: Path) -> None:
    """Ollama's serialized request contains redacted B105 context only."""
    canary = "SELF_LABELLED_OLLAMA_REQUEST_CANARY_DO_NOT_USE"
    public_literal = "PUBLIC_OLLAMA_CONTEXT_REMAINS"
    source = f'settings["pass"] = "{canary}"\npublic_label = "{public_literal}"\n'
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    finding = next(
        item
        for item in BanditScanner().scan(tmp_path)
        if item.rule_id == "B105" and item.file == PurePosixPath("app.py")
    )
    context = extract_context(finding, tmp_path)
    client, opener = _client()

    client.complete("synthetic system", json.dumps(context.to_json_dict()))
    assert opener.request is not None
    payload = json.loads(cast(bytes, opener.request.data))
    serialized = json.dumps(payload)

    if canary in serialized:
        pytest.fail("synthetic canary appeared in Ollama request")
    assert public_literal in serialized


def test_provider_factory_selects_ollama_and_anthropic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provider factory builds both transports and rejects unknown names."""
    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        llm_model=MODEL,
        llm_output="function",
    )
    assert isinstance(build_llm_client(settings), OllamaCompletionClient)

    class FakeAnthropicClient:
        """Provide the completion protocol used to verify Anthropic selection."""

        model = "anthropic-model"

        def __init__(self, **kwargs: object) -> None:
            """Accept configured Anthropic options without constructing a client."""

        def complete(self, system: str, user: str) -> str:
            """Return a test completion."""
            return "completion"

    monkeypatch.setattr(
        "omnipatch.agents.registry.AnthropicCompletionClient", FakeAnthropicClient
    )
    anthropic_settings = Settings(
        _env_file=None, llm_api_key="test-key", llm_provider="anthropic"
    )
    assert isinstance(build_llm_client(anthropic_settings), FakeAnthropicClient)
    with pytest.raises(ConfigError, match="Unknown LLM provider"):
        build_llm_client(settings, provider="unknown")


@pytest.mark.integration
@pytest.mark.protected
@pytest.mark.live_provider
def test_real_ollama_patch_for_fixture() -> None:
    """A local Qwen call returns a B608 patch accepted by the normal validator."""
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=1):
            pass
    except OSError:
        pytest.skip("Ollama is unreachable at http://127.0.0.1:11434")

    fixture_root = Path("tests/fixtures/vulnerable_app").resolve()
    finding = next(
        item for item in BanditScanner().scan(fixture_root) if item.rule_id == "B608"
    )
    context = extract_context(finding, fixture_root)
    original_source = (fixture_root / finding.file.as_posix()).read_text(
        encoding="utf-8"
    )
    patch = LLMPatchAgent(
        OllamaCompletionClient(MODEL),
        output_mode="function",
        sql_paramstyle={"app.py::load_user": "qmark"},
    ).propose(finding, context, original_source)
    assert patch.finding_id == finding.id
    assert patch.touched_files == (finding.file,)


@pytest.mark.integration
@pytest.mark.protected
@pytest.mark.live_provider
def test_real_ollama_b602_sandbox_respects_import_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real sandbox run either verifies or reports a contained rejection."""
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=1):
            pass
    except OSError:
        pytest.skip("Ollama is unreachable at http://127.0.0.1:11434")

    sandbox = Path("D:/code-project/omnipatch-sandbox")
    assert sandbox.is_dir(), f"Expected the Task 5.4 sandbox at {sandbox}"
    monkeypatch.setenv("OMNIPATCH_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OMNIPATCH_LLM_OUTPUT", "function")
    monkeypatch.setenv("OMNIPATCH_LLM_MODEL", MODEL)
    result = CliRunner().invoke(
        app,
        ["verify", "--repo", str(sandbox), "--rule", "B602", "--json"],
    )

    if result.exit_code == 0:
        outcome = json.loads(result.stdout)[0]
        assert outcome["verified"] is True
        assert "+import subprocess" not in outcome["patch"]["unified_diff"]
    else:
        assert result.exit_code == 1, result.output
        if "Target finding B602 in app.py survived." in result.output:
            outcome = json.loads(result.stdout)[0]
            assert "+import subprocess" not in outcome["patch"]["unified_diff"]
        else:
            assert "imports are supplied separately in the request" in result.output
