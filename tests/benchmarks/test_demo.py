"""Offline safety tests for the one-case local Ollama demo."""

import json
import os
from pathlib import Path
from typing import cast
from urllib.error import HTTPError, URLError

import pytest

from benchmarks.v1.demo import (
    CASE_ID,
    MODEL_TAG,
    TAGS_FIRST_TIMEOUT_SECONDS,
    TAGS_RETRY_TIMEOUT_SECONDS,
    preflight,
    run_demo,
)

MODEL_DIGEST = "sha256:" + "a" * 64


def _settings() -> dict[str, str]:
    return {
        "OMNIPATCH_LLM_PROVIDER": "ollama",
        "OMNIPATCH_LLM_OUTPUT": "function",
        "OMNIPATCH_LLM_MODEL": MODEL_TAG,
    }


def _tags(_: str, timeout_seconds: float) -> dict[str, object]:
    assert timeout_seconds in {
        TAGS_FIRST_TIMEOUT_SECONDS,
        TAGS_RETRY_TIMEOUT_SECONDS,
    }
    return {"models": [{"name": MODEL_TAG, "digest": MODEL_DIGEST}]}


def _write_success_artifacts(output: Path) -> None:
    (output / "cases" / CASE_ID).mkdir(parents=True)
    (output / "run.json").write_text(
        json.dumps({"source_revision": {"head": "a" * 40, "dirty": True}}),
        encoding="utf-8",
    )
    (output / "cases" / CASE_ID / "result.json").write_text(
        json.dumps(
            {
                "verification_passed": True,
                "regression_test": {"status": "passed"},
                "latency_seconds": 12.5,
                "introduced_findings_by_severity": {"LOW": [], "HIGH": []},
            }
        ),
        encoding="utf-8",
    )
    (output / "cases" / CASE_ID / "post-bandit-meta.json").write_text(
        json.dumps({"errors": [], "findings": []}), encoding="utf-8"
    )


def test_preflight_records_exact_local_model_digest() -> None:
    urls: list[str] = []

    def fetch(url: str, timeout_seconds: float) -> dict[str, object]:
        urls.append(url)
        return _tags(url, timeout_seconds)

    result = preflight(_settings(), fetch)
    assert result.model_digest == MODEL_DIGEST
    assert result.endpoint == "http://127.0.0.1:11434/api/chat"
    assert urls == ["http://127.0.0.1:11434/api/tags"]


def test_preflight_retries_transient_timeout_once_and_records_digest() -> None:
    attempts: list[tuple[str, float]] = []

    def fetch(url: str, timeout_seconds: float) -> dict[str, object]:
        attempts.append((url, timeout_seconds))
        if len(attempts) == 1:
            raise TimeoutError("sensitive transient detail")
        return _tags(url, timeout_seconds)

    result = preflight(_settings(), fetch)
    assert result.model_digest == MODEL_DIGEST
    assert [timeout for _, timeout in attempts] == [
        TAGS_FIRST_TIMEOUT_SECONDS,
        TAGS_RETRY_TIMEOUT_SECONDS,
    ]
    assert all(url == "http://127.0.0.1:11434/api/tags" for url, _ in attempts)


def test_preflight_retries_transient_connection_failure_once() -> None:
    attempts: list[float] = []

    def fetch(url: str, timeout_seconds: float) -> dict[str, object]:
        attempts.append(timeout_seconds)
        if len(attempts) == 1:
            raise ConnectionError("private connection detail")
        return _tags(url, timeout_seconds)

    result = preflight(_settings(), fetch)
    assert result.model_digest == MODEL_DIGEST
    assert attempts == [TAGS_FIRST_TIMEOUT_SECONDS, TAGS_RETRY_TIMEOUT_SECONDS]


def test_preflight_retries_wrapped_urllib_transport_failure() -> None:
    attempts: list[float] = []

    def fetch(url: str, timeout_seconds: float) -> dict[str, object]:
        attempts.append(timeout_seconds)
        if len(attempts) == 1:
            raise URLError("transient transport failure")
        return _tags(url, timeout_seconds)

    result = preflight(_settings(), fetch)
    assert result.model_digest == MODEL_DIGEST
    assert attempts == [TAGS_FIRST_TIMEOUT_SECONDS, TAGS_RETRY_TIMEOUT_SECONDS]


def test_preflight_stops_after_one_transient_retry_with_sanitized_error() -> None:
    attempts: list[float] = []

    def fetch(_: str, timeout_seconds: float) -> dict[str, object]:
        attempts.append(timeout_seconds)
        raise TimeoutError("DO_NOT_EXPOSE_TRANSIENT_DETAIL")

    with pytest.raises(ValueError, match="unavailable after one retry") as error:
        preflight(_settings(), fetch)
    assert attempts == [TAGS_FIRST_TIMEOUT_SECONDS, TAGS_RETRY_TIMEOUT_SECONDS]
    assert "DO_NOT_EXPOSE_TRANSIENT_DETAIL" not in str(error.value)


def test_preflight_does_not_retry_malformed_json_or_redirect() -> None:
    attempts: list[float] = []

    def malformed(_: str, timeout_seconds: float) -> dict[str, object]:
        attempts.append(timeout_seconds)
        raise json.JSONDecodeError("private response body", "SECRET_BODY", 0)

    with pytest.raises(ValueError, match="tags response is invalid") as error:
        preflight(_settings(), malformed)
    assert attempts == [TAGS_FIRST_TIMEOUT_SECONDS]
    assert "SECRET_BODY" not in str(error.value)

    attempts.clear()

    def redirected(_: str, timeout_seconds: float) -> dict[str, object]:
        attempts.append(timeout_seconds)
        raise HTTPError(
            "http://127.0.0.1:11434/api/tags",
            302,
            "private redirect target",
            None,
            None,
        )

    with pytest.raises(ValueError, match="request failed") as error:
        preflight(_settings(), redirected)
    assert attempts == [TAGS_FIRST_TIMEOUT_SECONDS]
    assert "private redirect target" not in str(error.value)


def test_preflight_does_not_retry_invalid_model_metadata() -> None:
    attempts: list[float] = []

    def invalid_metadata(_: str, timeout_seconds: float) -> dict[str, object]:
        attempts.append(timeout_seconds)
        return {"models": [{"name": MODEL_TAG, "digest": "not-a-digest"}]}

    with pytest.raises(ValueError, match="digest is missing or invalid"):
        preflight(_settings(), invalid_metadata)
    assert attempts == [TAGS_FIRST_TIMEOUT_SECONDS]


@pytest.mark.parametrize(
    "key,value,message",
    [
        ("OMNIPATCH_LLM_PROVIDER", "anthropic", "LLM_PROVIDER=ollama"),
        ("OMNIPATCH_LLM_OUTPUT", "diff", "LLM_OUTPUT=function"),
        ("OMNIPATCH_LLM_MODEL", "other", "qwen-ctx8k:latest"),
    ],
)
def test_preflight_rejects_unintended_settings_before_network(
    key: str, value: str, message: str
) -> None:
    settings = _settings()
    settings[key] = value
    calls: list[str] = []
    with pytest.raises(ValueError, match=message):
        preflight(
            settings, lambda url, timeout: calls.append(url) or _tags(url, timeout)
        )
    assert calls == []


def test_preflight_rejects_remote_endpoint_without_request() -> None:
    settings = _settings() | {
        "OMNIPATCH_OLLAMA_ENDPOINT": "https://ollama.example/api/chat"
    }
    calls: list[str] = []
    with pytest.raises(ValueError, match="local"):
        preflight(
            settings, lambda url, timeout: calls.append(url) or _tags(url, timeout)
        )
    assert calls == []


def test_preflight_sanitizes_unavailable_and_missing_model_errors() -> None:
    with pytest.raises(ValueError, match="tags API is unavailable"):
        preflight(
            _settings(),
            lambda _, __: (_ for _ in ()).throw(ConnectionError("private detail")),
        )
    with pytest.raises(ValueError, match="not installed"):
        preflight(_settings(), lambda _, __: {"models": []})


def test_demo_invokes_only_static_b608_and_strips_credentials(
    tmp_path: Path,
) -> None:
    working = tmp_path / "clean-cwd"
    working.mkdir()
    output = tmp_path / "new-output"
    sentinel_api = "DO_NOT_PERSIST_ANTHROPIC_SENTINEL"
    sentinel_github = "DO_NOT_PERSIST_GITHUB_SENTINEL"
    environment = _settings() | {
        "ANTHROPIC_API_KEY": sentinel_api,
        "OMNIPATCH_GITHUB_TOKEN": sentinel_github,
        "PATH": "safe-path",
    }
    calls: list[list[str]] = []

    def fake_evaluator(arguments: list[str]) -> int:
        calls.append(arguments)
        assert "--apply" not in arguments
        assert "--case" in arguments
        assert arguments[arguments.index("--case") + 1] == CASE_ID
        assert "ANTHROPIC_API_KEY" not in os.environ
        assert "OMNIPATCH_GITHUB_TOKEN" not in os.environ
        assert sentinel_api not in repr(os.environ)
        assert sentinel_github not in repr(os.environ)
        _write_success_artifacts(output)
        return 0

    result = run_demo(
        output,
        environ=environment,
        cwd=working,
        tags_fetcher=_tags,
        evaluator=fake_evaluator,
    )
    assert result.verifier and result.oracle == "passed"
    assert result.target_finding is False
    assert calls == [
        [
            "--live",
            "--allow-dirty",
            "--case",
            CASE_ID,
            "--output-dir",
            str(output.resolve()),
        ]
    ]
    metadata = json.loads((output / "demo-metadata.json").read_text(encoding="utf-8"))
    serialized = json.dumps(metadata)
    assert metadata["model_digest"] == MODEL_DIGEST
    assert metadata["provider"] == "ollama"
    assert metadata["case_id"] == CASE_ID
    assert sentinel_api not in serialized
    assert sentinel_github not in serialized


def test_demo_refuses_dotenv_existing_or_repository_output_before_preflight(
    tmp_path: Path,
) -> None:
    working = tmp_path / "with-env"
    working.mkdir()
    (working / ".env").write_text("not loaded", encoding="utf-8")
    calls: list[str] = []
    with pytest.raises(ValueError, match="must not contain a .env"):
        run_demo(
            tmp_path / "never-created",
            environ=_settings(),
            cwd=working,
            tags_fetcher=lambda url, timeout: calls.append(url) or _tags(url, timeout),
            evaluator=lambda _: 0,
        )
    assert calls == []

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(ValueError, match="already exists"):
        run_demo(existing, environ=_settings(), cwd=tmp_path, tags_fetcher=_tags)

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".git").mkdir()
    with pytest.raises(ValueError, match="outside every Git repository"):
        run_demo(
            repository / "artifacts",
            environ=_settings(),
            cwd=tmp_path,
            tags_fetcher=_tags,
        )


def test_powershell_launcher_is_single_case_and_never_publishes() -> None:
    repository = Path(__file__).resolve().parents[2]
    launcher = (repository / "scripts" / "run-b608-demo.ps1").read_text(
        encoding="utf-8"
    )
    assert "-m benchmarks.v1.demo --output-dir $output" in launcher
    assert 'Remove-Item -LiteralPath "Env:$($entry.Name)"' in launcher
    assert "--apply" not in launcher
    assert "github.com" not in launcher.lower()
    assert "githubpullrequest" not in launcher.lower()


def test_failed_demo_never_claims_success(tmp_path: Path) -> None:
    working = tmp_path / "cwd"
    working.mkdir()
    output = tmp_path / "failed-output"

    def evaluator(_: list[str]) -> int:
        _write_success_artifacts(output)
        result_path = output / "cases" / CASE_ID / "result.json"
        result = cast(dict[str, object], json.loads(result_path.read_text()))
        result["verification_passed"] = False
        result_path.write_text(json.dumps(result), encoding="utf-8")
        return 1

    with pytest.raises(ValueError, match="did not produce a verified"):
        run_demo(
            output,
            environ=_settings(),
            cwd=working,
            tags_fetcher=_tags,
            evaluator=evaluator,
        )
