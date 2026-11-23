"""Tests for settings validation and secret safety."""

import json
from pathlib import Path

import pytest

from omnipatch.config import Settings, load_settings
from omnipatch.errors import ConfigError


def test_github_token_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing token raises ConfigError."""
    monkeypatch.delenv("OMNIPATCH_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("OMNIPATCH_LLM_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        Settings(_env_file=None).require_github_token()


def test_blank_llm_key_is_rejected() -> None:
    """An empty optional key is not accepted as an Anthropic credential."""
    with pytest.raises(ConfigError, match="OMNIPATCH_LLM_API_KEY is required"):
        Settings(llm_api_key="", _env_file=None).require_llm_api_key()


def test_settings_repr_redacts_secrets() -> None:
    """Secret values do not appear in repr."""
    settings = Settings(github_token="supersecret", _env_file=None)
    assert "supersecret" not in repr(settings)
    assert "supersecret" not in str(settings)


def test_scan_exclude_dirs_parses_and_drops_blank_entries() -> None:
    """Scan exclusions parse comma-separated values and allow an empty list."""
    settings = Settings(scan_exclude="a, b ,,c", _env_file=None)
    assert settings.scan_exclude_dirs == ("a", "b", "c")
    empty_settings = Settings(scan_exclude="", _env_file=None)
    assert empty_settings.scan_exclude_dirs == ()


def test_context_max_lines_defaults_and_has_minimum() -> None:
    """Context line budget defaults to 120 and rejects values below 10."""
    assert Settings(_env_file=None).context_max_lines == 120
    with pytest.raises(ValueError):
        Settings(context_max_lines=9, _env_file=None)


def test_snapshot_limits_have_bounded_positive_defaults() -> None:
    """Snapshot controls have explicit positive bounds and documented defaults."""
    settings = Settings(_env_file=None)
    assert settings.snapshot_max_bytes == 1 << 30
    assert settings.snapshot_max_file_bytes == 1 << 27
    assert settings.snapshot_max_entries == 100_000
    assert settings.snapshot_max_metadata_entries == 100_000
    assert settings.snapshot_timeout_seconds == 120
    with pytest.raises(ValueError):
        Settings(snapshot_max_bytes=0, _env_file=None)
    with pytest.raises(ValueError):
        Settings(snapshot_max_file_bytes=1 << 39, _env_file=None)


def test_verification_policy_defaults_to_severity_and_accepts_strict() -> None:
    """Severity comparison is the default and strict remains configurable."""
    assert Settings(_env_file=None).verify_policy == "severity"
    assert Settings(verify_policy="strict", _env_file=None).verify_policy == "strict"


def test_verification_policy_rejects_unknown_value() -> None:
    """Invalid policy values are translated at the settings boundary."""
    with pytest.raises(ValueError):
        Settings(verify_policy="loose", _env_file=None)


@pytest.mark.parametrize(
    ("endpoint", "canonical"),
    [
        ("http://127.0.0.1:11434/api/chat", "http://127.0.0.1:11434/api/chat"),
        ("http://127.0.0.1/api/chat", "http://127.0.0.1:11434/api/chat"),
        ("http://localhost:11434/api/chat", "http://localhost:11434/api/chat"),
        ("http://[::1]:11434/api/chat", "http://[::1]:11434/api/chat"),
    ],
)
def test_ollama_endpoint_accepts_only_documented_loopback_forms(
    endpoint: str, canonical: str
) -> None:
    """Supported local endpoint spellings normalize to the chat endpoint."""
    assert (
        Settings(_env_file=None, ollama_endpoint=endpoint).ollama_endpoint == canonical
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:11434/api/chat",
        "http://192.0.2.10:11434/api/chat",
        "http://localhost:11434/api/generate",
        "http://user:SELF_LABELLED_ENDPOINT_CREDENTIAL@localhost:11434/api/chat",
        "http://localhost:11434/api/chat?",
        "http://localhost:11434/api/chat?key=SELF_LABELLED_QUERY_VALUE",
        "http://localhost:11434/api/chat#",
        "http://localhost:11434/api/chat#fragment",
        "http://localhost:11433/api/chat",
        "http://localhost:invalid/api/chat",
        "http://localhost.example:11434/api/chat",
    ],
)
def test_load_settings_rejects_unsupported_ollama_endpoint_without_echo(
    monkeypatch: pytest.MonkeyPatch, endpoint: str
) -> None:
    """Unsupported endpoints fail closed without echoing submitted values."""
    monkeypatch.setenv("OMNIPATCH_OLLAMA_ENDPOINT", endpoint)
    with pytest.raises(ConfigError) as error:
        load_settings(env_file=None)
    assert "Invalid OmniPatch configuration" in str(error.value)
    assert endpoint not in str(error.value)


def test_load_settings_wraps_invalid_max_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid max findings is reported through ConfigError."""
    monkeypatch.delenv("OMNIPATCH_UNKNOWN_SETTING", raising=False)
    monkeypatch.setenv("OMNIPATCH_MAX_FINDINGS", "0")
    with pytest.raises(ConfigError):
        load_settings(env_file=None)


def test_load_settings_rejects_unknown_prefixed_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown OmniPatch environment keys are rejected."""
    monkeypatch.setenv("OMNIPATCH_UNKNOWN_SETTING", "value")
    with pytest.raises(ConfigError):
        load_settings(env_file=None)


def test_secret_environment_mapping_loads_explicit_target_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mappings bind normalized source targets to variable names only."""
    monkeypatch.setenv(
        "OMNIPATCH_SECRET_ENVIRONMENT",
        json.dumps(
            {
                "app.py::configured_password": "APP_PASSWORD",
                "credentials.py::Credentials.read_password": "VAULT_PASSWORD",
                "settings.py::<module>": "DATABASE_PASSWORD",
            }
        ),
    )
    settings = load_settings(env_file=None)
    assert settings.secret_environment == {
        "app.py::configured_password": "APP_PASSWORD",
        "credentials.py::Credentials.read_password": "VAULT_PASSWORD",
        "settings.py::<module>": "DATABASE_PASSWORD",
    }


def test_secret_environment_mapping_loads_from_dotenv(tmp_path: Path) -> None:
    """The documented .env JSON setting follows existing configuration loading."""
    env_file = tmp_path / "omnipatch.env"
    env_file.write_text(
        "OMNIPATCH_SECRET_ENVIRONMENT='"
        '{"app.py::configured_password":"APP_PASSWORD"}'
        "'\n",
        encoding="utf-8",
    )
    assert load_settings(env_file=str(env_file)).secret_environment == {
        "app.py::configured_password": "APP_PASSWORD"
    }


def test_sql_paramstyle_mapping_loads_explicit_target_styles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "OMNIPATCH_SQL_PARAMSTYLE",
        json.dumps({"app.py::lookup_item": "qmark", "db.py::<module>": "pyformat"}),
    )
    assert load_settings(env_file=None).sql_paramstyle == {
        "app.py::lookup_item": "qmark",
        "db.py::<module>": "pyformat",
    }


@pytest.mark.parametrize(
    "mapping",
    [
        {"../app.py::lookup_item": "qmark"},
        {"app.py::lookup_item": "unknown-style"},
    ],
)
def test_invalid_sql_paramstyle_is_rejected_without_echoing_values(
    monkeypatch: pytest.MonkeyPatch, mapping: dict[str, str]
) -> None:
    submitted = json.dumps(mapping)
    monkeypatch.setenv("OMNIPATCH_SQL_PARAMSTYLE", submitted)
    with pytest.raises(ConfigError) as caught:
        load_settings(env_file=None)
    assert submitted not in str(caught.value)
    assert "unknown-style" not in str(caught.value)


@pytest.mark.parametrize(
    "mapping",
    [
        {"../app.py::configured_password": "APP_PASSWORD"},
        {"C:/app.py::configured_password": "APP_PASSWORD"},
        {"app.py::not-valid-symbol!": "APP_PASSWORD"},
        {"app.py::configured_password": "not an environment name"},
        {"app.py::configured_password": "FAKE SECRET VALUE MUST NOT LEAK"},
    ],
)
def test_invalid_secret_environment_mapping_is_rejected_without_echoing_values(
    monkeypatch: pytest.MonkeyPatch,
    mapping: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Invalid targets and non-name values fail without exposing submitted text."""
    monkeypatch.setenv("OMNIPATCH_SECRET_ENVIRONMENT", json.dumps(mapping))
    with pytest.raises(ConfigError) as caught:
        load_settings(env_file=None)
    assert "FAKE SECRET VALUE MUST NOT LEAK" not in str(caught.value)
    assert "FAKE SECRET VALUE MUST NOT LEAK" not in caplog.text
