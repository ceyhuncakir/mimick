"""Model helpers for PydanticAI multi-provider support."""

from __future__ import annotations

import os

from pydantic_ai.models import Model

from mimick.logger import get_logger

log = get_logger("llm")


def get_model(model_str: str) -> Model | str:
    """Convert a model config string to a PydanticAI model.

    Supports:
      - Native PydanticAI strings: "openai:gpt-4o", "anthropic:claude-sonnet-4-20250514"
      - OpenRouter strings: "openrouter/anthropic/claude-sonnet-4-20250514"
    """
    # OpenRouter uses OpenAI-compatible API
    if model_str.startswith("openrouter/"):
        from pydantic_ai.models.openai import OpenAIModel
        from pydantic_ai.providers.openai import OpenAIProvider

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

    # Pass through native PydanticAI model strings (openai:..., anthropic:..., etc.)
    log.debug("Using model: %s", model_str)
    return model_str
