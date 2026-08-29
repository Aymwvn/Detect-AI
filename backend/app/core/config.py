"""
Application configuration.

Everything environment-specific (DB connection, secrets, AI provider choice)
lives here and nowhere else — no module should read os.environ directly.
This is also the single place that decides what's safe to log: `Settings`
deliberately does NOT implement __repr__/__str__ with secret values exposed.
"""

from functools import lru_cache
from typing import Literal, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- app ---------------------------------------------------------------
    app_name: str = "DetectAI"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # --- security ------------------------------------------------------------
    secret_key: str = Field(default="CHANGE-ME-IN-PRODUCTION", description="JWT signing key")
    access_token_expire_minutes: int = 60
    algorithm: str = "HS256"

    # --- database ------------------------------------------------------------
    database_url: str = "postgresql+asyncpg://detectai:detectai@localhost:5432/detectai"

    # --- redis (queue / dedup state) -------------------------------------------
    redis_url: str = "redis://localhost:6379/0"

    # --- AI provider ---------------------------------------------------------
    # "none" keeps the pipeline fully functional with rule-based scoring only,
    # per architecture doc section 13.
    ai_provider: Literal["none", "openai", "anthropic", "ollama"] = "none"
    ai_model: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_base_url: Optional[str] = None  # used for Ollama / self-hosted OpenAI-compatible endpoints

    # --- rate limiting ---------------------------------------------------------
    rate_limit_per_minute: int = 120

    # --- cors ---------------------------------------------------------------
    cors_allowed_origins: list[str] = ["http://localhost:5173"]


@lru_cache
def get_settings() -> Settings:
    """Cached so Settings() -> env parsing only happens once per process."""
    return Settings()
