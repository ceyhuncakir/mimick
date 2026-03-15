"""Configuration management via pydantic-settings and .env files."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CANNON_",
        extra="ignore",
    )

    # LLM — supports PydanticAI model strings and OpenRouter:
    #   "openai:gpt-4o", "anthropic:claude-sonnet-4-20250514",
    #   "openrouter/anthropic/claude-sonnet-4-20250514"
    model: str = "openrouter/anthropic/claude-sonnet-4-20250514"
    max_iterations: int = 50
    timeout: int = 300

    # Logging
    log_level: str = "INFO"
    log_file: bool = True

    # Output
    output_dir: Path = Path("./results")

    # API keys read from env vars:
    #   OPENAI_API_KEY, ANTHROPIC_API_KEY, OPENROUTER_API_KEY


settings = Settings()
