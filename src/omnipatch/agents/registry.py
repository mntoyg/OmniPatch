"""Configured completion-client factory for supported model providers."""

from omnipatch.agents.anthropic_client import AnthropicCompletionClient
from omnipatch.agents.base import PatchCompletionClient
from omnipatch.agents.ollama_client import OllamaCompletionClient
from omnipatch.agents.request_audit import (
    SyntheticCanaryAuditError,
    SyntheticCanaryAuditor,
)
from omnipatch.config import Settings
from omnipatch.errors import ConfigError


def build_llm_client(
    settings: Settings, provider: str | None = None
) -> PatchCompletionClient:
    """Build the selected completion transport or raise ConfigError."""
    selected_provider = settings.llm_provider if provider is None else provider
    request_auditor = SyntheticCanaryAuditor.from_environment()
    if selected_provider == "anthropic":
        if request_auditor is not None:
            raise SyntheticCanaryAuditError(
                "Synthetic canary audit is supported only by local Ollama"
            )
        return AnthropicCompletionClient(
            api_key=settings.require_llm_api_key(),
            model=settings.llm_model,
            timeout_seconds=settings.llm_timeout_seconds,
            max_tokens=settings.llm_max_tokens,
            effort=settings.llm_effort,
            enable_fallbacks=settings.llm_enable_fallbacks,
        )
    if selected_provider == "ollama":
        return OllamaCompletionClient(
            model=settings.llm_model,
            endpoint=settings.ollama_endpoint,
            timeout_seconds=settings.ollama_timeout_seconds,
            max_tokens=settings.llm_max_tokens,
            request_auditor=request_auditor,
        )
    raise ConfigError(
        f"Unknown LLM provider '{selected_provider}'. Valid providers: anthropic, ollama"
    )
