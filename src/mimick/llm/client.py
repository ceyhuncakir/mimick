from __future__ import annotations

import os

from pydantic_ai import ModelSettings
from pydantic_ai.models import Model
from pydantic_ai.models.anthropic import AnthropicModelSettings
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider

from mimick.logger import get_logger

log = get_logger("llm")


def _is_anthropic_model(model_str: str) -> bool:
    lower = model_str.lower()
    return "claude" in lower or "anthropic" in lower


def get_cache_settings(model_str: str) -> ModelSettings | None:
    """Build provider-specific ModelSettings that enable prompt caching."""
    if model_str.startswith("anthropic:") or (
        model_str.startswith("openrouter/") and _is_anthropic_model(model_str)
    ):
        log.debug("Enabling Anthropic prompt caching for %s", model_str)
        return AnthropicModelSettings(
            anthropic_cache_instructions=True,
            anthropic_cache_tool_definitions=True,
            anthropic_cache_messages=True,
        )

    return None


def get_model(model_str: str) -> Model | str:
    """Convert a model config string to a PydanticAI model."""
    if model_str.startswith("openrouter/"):
        model_name = model_str.removeprefix("openrouter/")
        api_key = os.environ.get("OPENROUTER_API_KEY", "")

        log.debug("Using OpenRouter model: %s", model_name)
        return OpenAIModel(
            model_name,
            provider=OpenAIProvider(
                base_url="https://openrouter.ai/api/v1",
                api_key=api_key,
            ),
        )

    log.debug("Using model: %s", model_str)
    return model_str
