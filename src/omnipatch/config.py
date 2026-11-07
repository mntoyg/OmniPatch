"""Secret-safe OmniPatch settings."""

import os
import re
from pathlib import PurePosixPath
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from omnipatch.defaults import (
    DEFAULT_CONTEXT_MAX_LINES,
    DEFAULT_LLM_EFFORT,
    DEFAULT_LLM_MAX_TOKENS,
    DEFAULT_LLM_MODEL,
    DEFAULT_LLM_TIMEOUT_SECONDS,
    DEFAULT_OLLAMA_ENDPOINT,
    DEFAULT_OLLAMA_TIMEOUT_SECONDS,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
    EXCLUDED_DIRS,
)
from omnipatch.errors import ConfigError


def validate_local_ollama_endpoint(endpoint: str) -> str:
    """Return a canonical local chat URL or raise a value-free error."""
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except (TypeError, ValueError):
        raise ValueError(
            "OMNIPATCH_OLLAMA_ENDPOINT must be a local HTTP loopback /api/chat URL"
        ) from None

    if (
        not endpoint
        or endpoint != endpoint.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in endpoint)
        or "?" in endpoint
        or "#" in endpoint
        or parsed.scheme != "http"
        or hostname not in {"127.0.0.1", "localhost", "::1"}
        or username is not None
        or password is not None
        or parsed.path != "/api/chat"
        or port not in (None, 11434)
    ):
        raise ValueError(
            "OMNIPATCH_OLLAMA_ENDPOINT must be a local HTTP loopback /api/chat URL"
        )

    host = f"[{hostname}]" if hostname == "::1" else hostname
    return f"http://{host}:{port or 11434}/api/chat"


class Settings(BaseSettings):
    """Application settings loaded from environment and .env."""

    model_config = SettingsConfigDict(
        env_prefix="OMNIPATCH_", env_file=".env", extra="forbid"
    )

    github_token: SecretStr | None = None
    github_repo: str | None = None
    github_timeout_seconds: int = Field(default=15, ge=1)
    llm_api_key: SecretStr | None = None
    llm_provider: Literal["anthropic", "ollama"] = "anthropic"
    llm_output: Literal["diff", "function"] = "diff"
    verify_policy: Literal["severity", "strict"] = "severity"
    llm_model: str = DEFAULT_LLM_MODEL
    llm_max_tokens: int = Field(default=DEFAULT_LLM_MAX_TOKENS, ge=1024)
    llm_effort: Literal["low", "medium", "high", "xhigh", "max"] = DEFAULT_LLM_EFFORT
    llm_timeout_seconds: int = Field(default=DEFAULT_LLM_TIMEOUT_SECONDS, ge=1)
    llm_enable_fallbacks: bool = True
    ollama_endpoint: str = DEFAULT_OLLAMA_ENDPOINT
    ollama_timeout_seconds: int = Field(default=DEFAULT_OLLAMA_TIMEOUT_SECONDS, ge=1)
    dry_run: bool = True
    max_findings: int = Field(default=10, ge=1)
    scanner: str = "bandit"
    scan_timeout_seconds: int = Field(default=DEFAULT_SCAN_TIMEOUT_SECONDS, ge=1)
    scan_exclude: str = ",".join(EXCLUDED_DIRS)
    context_max_lines: int = Field(default=DEFAULT_CONTEXT_MAX_LINES, ge=10)
    secret_environment: dict[str, str] = Field(default_factory=dict)
    sql_paramstyle: dict[str, str] = Field(default_factory=dict)

    @field_validator("ollama_endpoint")
    @classmethod
    def validate_ollama_endpoint_setting(cls, value: str) -> str:
        """Restrict model requests to the approved local Ollama endpoint."""
        return validate_local_ollama_endpoint(value)

    @field_validator("secret_environment")
    @classmethod
    def validate_secret_environment(cls, value: dict[str, str]) -> dict[str, str]:
        """Accept only repository-relative target keys and environment names."""
        for key, variable in value.items():
            if not _is_secret_mapping_key(key):
                raise ValueError("secret environment mapping key is invalid")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable):
                raise ValueError("secret environment values must be variable names")
        return value

    @field_validator("sql_paramstyle")
    @classmethod
    def validate_sql_paramstyle(cls, value: dict[str, str]) -> dict[str, str]:
        """Accept repository-relative targets and supported PEP 249 styles."""
        allowed = {"qmark", "numeric", "named", "format", "pyformat"}
        for key, style in value.items():
            if not _is_secret_mapping_key(key):
                raise ValueError("SQL parameter style mapping key is invalid")
            if style not in allowed:
                raise ValueError("SQL parameter style is unsupported")
        return value

    @property
    def scan_exclude_dirs(self) -> tuple[str, ...]:
        """Parse comma-separated scan exclusions, dropping blank entries."""
        return tuple(
            directory.strip()
            for directory in self.scan_exclude.split(",")
            if directory.strip()
        )

    def require_github_token(self) -> str:
        """Return the GitHub token or raise ConfigError."""
        if self.github_token is None:
            raise ConfigError("OMNIPATCH_GITHUB_TOKEN is required")
        token = self.github_token.get_secret_value()
        if not token.strip():
            raise ConfigError("OMNIPATCH_GITHUB_TOKEN is required")
        return token

    def require_github_repo(self) -> str:
        """Return the explicitly configured target repository or raise ConfigError."""
        if self.github_repo is None or not self.github_repo.strip():
            raise ConfigError("OMNIPATCH_GITHUB_REPO or --github-repo is required")
        repository = self.github_repo.strip()
        if not _is_repository_name(repository):
            raise ConfigError("GitHub repository must be explicit as owner/name")
        return repository

    def require_llm_api_key(self) -> str:
        """Return the LLM API key or raise ConfigError."""
        if self.llm_api_key is None or not self.llm_api_key.get_secret_value().strip():
            raise ConfigError("OMNIPATCH_LLM_API_KEY is required")
        return self.llm_api_key.get_secret_value()


def load_settings(env_file: str | None = ".env") -> Settings:
    """Build Settings, translating any validation failure into ConfigError."""
    prefix = Settings.model_config.get("env_prefix", "")
    known_env = {f"{prefix}{name.upper()}" for name in Settings.model_fields}
    unknown_env = sorted(
        key for key in os.environ if key.startswith(prefix) and key not in known_env
    )
    if unknown_env:
        raise ConfigError(
            f"Invalid OmniPatch configuration: unknown setting {unknown_env[0]}"
        )
    try:
        return Settings(  # type: ignore[call-arg]  # _env_file is a runtime kwarg BaseSettings does not declare
            _env_file=env_file
        )
    except ValidationError as exc:
        # Pydantic errors can echo submitted values; configuration may contain
        # accidental secret values, so expose only a value-free diagnostic.
        raise ConfigError(
            "Invalid OmniPatch configuration; check setting names and formats"
        ) from exc


def _is_repository_name(value: str) -> bool:
    """Check the explicit owner/name form without consulting Git remotes."""
    parts = value.split("/")
    return len(parts) == 2 and all(
        part and not any(c.isspace() for c in part) for part in parts
    )


def _is_secret_mapping_key(value: str) -> bool:
    """Validate ``relative.py::symbol`` keys without normalizing user input."""
    if value.count("::") != 1:
        return False
    file_name, symbol = value.split("::", maxsplit=1)
    path = PurePosixPath(file_name)
    if (
        not file_name
        or "\\" in file_name
        or ":" in file_name
        or path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or path.suffix != ".py"
        or path.as_posix() != file_name
    ):
        return False
    return symbol == "<module>" or all(
        part.isidentifier() for part in symbol.split(".")
    )
