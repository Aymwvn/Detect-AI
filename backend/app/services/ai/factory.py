"""
Builds the LLMProvider configured via Settings.ai_provider. Returns None
for AI_PROVIDER=none — callers must handle that case by skipping AI
analysis entirely (architecture doc section 13: the pipeline stays fully
functional without one)."""

from __future__ import annotations

from app.core.config import Settings
from app.services.ai.base import LLMProvider
from app.services.ai.providers import AnthropicCompatibleProvider, OllamaProvider, OpenAICompatibleProvider


def get_llm_provider(settings: Settings) -> LLMProvider | None:
    if settings.ai_provider == "none":
        return None

    if settings.ai_provider == "ollama":
        return OllamaProvider(
            base_url=settings.ai_base_url or "http://localhost:11434",
            model=settings.ai_model or "llama3",
        )

    if settings.ai_provider == "openai":
        return OpenAICompatibleProvider(
            base_url=settings.ai_base_url or "https://api.openai.com/v1",
            api_key=settings.ai_api_key,
            model=settings.ai_model or "gpt-4o-mini",
        )

    if settings.ai_provider == "anthropic":
        return AnthropicCompatibleProvider(
            base_url=settings.ai_base_url or "https://api.anthropic.com",
            api_key=settings.ai_api_key,
            model=settings.ai_model or "claude-sonnet-4-6",
        )

    raise ValueError(f"Unknown AI_PROVIDER: {settings.ai_provider!r}")
