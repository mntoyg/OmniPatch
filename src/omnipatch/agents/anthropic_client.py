"""Anthropic SDK completion transport with secret-safe error translation."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeGuard, cast

# Keep this module import style paired with tests/conftest.py's offline guard.
import anthropic
from pydantic import SecretStr

from omnipatch.agents.base import AnthropicSdkLike
from omnipatch.defaults import (
    DEFAULT_LLM_EFFORT,
    DEFAULT_LLM_MAX_TOKENS,
    DEFAULT_LLM_TIMEOUT_SECONDS,
)
from omnipatch.errors import PatchGenerationError

if TYPE_CHECKING:
    from omnipatch.agents.base import (
        AnthropicContentBlock,
        AnthropicMessageLike,
        AnthropicTextBlock,
    )


def _is_text_block(block: AnthropicContentBlock) -> TypeGuard[AnthropicTextBlock]:
    """Narrow a heterogeneous SDK content block to text by its discriminator."""
    return block.type == "text"


class AnthropicCompletionClient:
    """Call Anthropic messages API and return only text response blocks."""

    def __init__(
        self,
        api_key: str,
        model: str,
        timeout_seconds: int = DEFAULT_LLM_TIMEOUT_SECONDS,
        max_tokens: int = DEFAULT_LLM_MAX_TOKENS,
        effort: str = DEFAULT_LLM_EFFORT,
        enable_fallbacks: bool = True,
        sdk_client: AnthropicSdkLike | None = None,
    ) -> None:
        """Create a client without exposing its API key in representations."""
        self._model = model
        self._api_key = SecretStr(api_key)
        self.model = model
        self._max_tokens = max_tokens
        self._effort = effort
        self._enable_fallbacks = enable_fallbacks
        if sdk_client is not None:
            self._sdk: AnthropicSdkLike = sdk_client
        else:
            try:
                self._sdk = cast(
                    AnthropicSdkLike,
                    anthropic.Anthropic(api_key=api_key, timeout=timeout_seconds),
                )
            except anthropic.AnthropicError:
                raise PatchGenerationError(
                    "Could not initialize Anthropic client"
                ) from None

    def __repr__(self) -> str:
        """Return a representation that contains no credential material."""
        return f"{type(self).__name__}(model={self._model!r})"

    def complete(self, system: str, user: str) -> str:
        """Return joined response text or a sanitized generation error."""
        request: dict[str, object] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "output_config": {"effort": self._effort},
        }
        if self._enable_fallbacks:
            request["betas"] = ["server-side-fallback-2026-07-01"]
            request["fallbacks"] = "default"
        try:
            response: AnthropicMessageLike = self._sdk.beta.messages.create(**request)
        except anthropic.NotFoundError as exc:
            raise PatchGenerationError(
                f"Anthropic model was not found (HTTP {exc.status_code})"
            ) from None
        except anthropic.AuthenticationError as exc:
            raise PatchGenerationError(
                f"Anthropic authentication failed (HTTP {exc.status_code})"
            ) from None
        except anthropic.PermissionDeniedError as exc:
            raise PatchGenerationError(
                f"Anthropic request was denied (HTTP {exc.status_code})"
            ) from None
        except anthropic.BadRequestError as exc:
            raise PatchGenerationError(
                f"Anthropic rejected the request shape (HTTP {exc.status_code})"
            ) from None
        except anthropic.RateLimitError as exc:
            retry_after = exc.response.headers.get("retry-after")
            detail = f"; retry after {retry_after} seconds" if retry_after else ""
            raise PatchGenerationError(
                f"Anthropic rate limit reached (HTTP {exc.status_code}){detail}"
            ) from None
        except anthropic.APITimeoutError:
            raise PatchGenerationError("Anthropic request timed out") from None
        except anthropic.APIStatusError as exc:
            raise PatchGenerationError(
                f"Anthropic returned an API error (HTTP {exc.status_code})"
            ) from None
        except anthropic.APIConnectionError:
            raise PatchGenerationError("Could not connect to Anthropic") from None
        except anthropic.AnthropicError:
            raise PatchGenerationError("Anthropic completion failed") from None
        if response.stop_reason == "refusal":
            details = response.stop_details
            category = details.category if details is not None else None
            detail = f" (category: {category})" if category else ""
            raise PatchGenerationError(f"Anthropic refused the patch request{detail}")
        if response.stop_reason == "max_tokens":
            raise PatchGenerationError("Model output was truncated at max_tokens")
        text = "".join(
            block.text for block in response.content if _is_text_block(block)
        )
        if not text.strip():
            raise PatchGenerationError("Anthropic returned no text content")
        return text
