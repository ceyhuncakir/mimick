from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="MIMICK_",
        extra="ignore",
    )

    model: str = "openrouter/anthropic/claude-sonnet-4-20250514"
    max_iterations: int = 50
    timeout: int = 300

    log_level: str = "INFO"
    log_file: bool = True

    output_dir: Path = Path("./results")

    experience_db_dir: Path = Path.home() / ".mimick" / "experience_db"
    experience_collection: str = "experiences"
    experience_enabled: bool = True
    experience_top_k: int = 2


settings = Settings()
