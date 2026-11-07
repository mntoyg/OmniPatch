"""Protocols for patch agents and completion transports."""

from collections.abc import Sequence
from typing import Protocol

from omnipatch.models import CodeContext, Finding, Patch


class PatchCompletionClient(Protocol):
    """Transport that turns a prompt pair into raw model text."""

    model: str

    def complete(self, system: str, user: str) -> str:
        """Return model text or raise PatchGenerationError on failure."""
        ...


class PatchAgent(Protocol):
    """Propose a validated patch for one finding."""

    name: str

    def propose(
        self, finding: Finding, context: CodeContext, original_source: str
    ) -> Patch:
        """Return a validated patch or raise PatchGenerationError."""
        ...


class AnthropicContentBlock(Protocol):
    """Minimal content block discriminator returned by Anthropic."""

    @property
    def type(self) -> str: ...


class AnthropicTextBlock(AnthropicContentBlock, Protocol):
    """Text response block returned by the Anthropic messages API."""

    @property
    def text(self) -> str: ...


class AnthropicStopDetails(Protocol):
    """Non-sensitive refusal metadata returned for a refusal stop reason."""

    @property
    def category(self) -> str | None: ...


class AnthropicMessageLike(Protocol):
    """Narrow message fields consumed by the Anthropic transport."""

    @property
    def stop_reason(self) -> str | None: ...

    @property
    def stop_details(self) -> AnthropicStopDetails | None: ...

    @property
    def content(self) -> Sequence[AnthropicContentBlock]: ...


class AnthropicMessagesApi(Protocol):
    """Narrow beta messages operation used by the transport."""

    def create(self, **kwargs: object) -> AnthropicMessageLike:
        """Create a message with the explicitly built request parameters."""
        ...


class AnthropicBetaNamespace(Protocol):
    """Beta namespace exposed by the SDK client."""

    @property
    def messages(self) -> AnthropicMessagesApi: ...


class AnthropicSdkLike(Protocol):
    """Minimal injected SDK surface used by the completion client."""

    @property
    def beta(self) -> AnthropicBetaNamespace: ...
