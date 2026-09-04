"""Exceptions for the AI analysis layer (app/services/ai/)."""


class LLMProviderError(Exception):
    """Raised by any LLMProvider on network/auth/response failure. Callers
    handle this one type regardless of which concrete provider is
    configured (openai/anthropic/ollama)."""


class LLMNotConfiguredError(Exception):
    """Raised when a provider is requested but required config (base_url,
    api_key, model) is missing."""


class AIAnalysisValidationError(Exception):
    """Raised when an LLM's raw response is not valid JSON, or doesn't
    match the strict AIAnalysisOutput schema (architecture doc section
    16). This is the "reject malformed AI output" requirement — callers
    must NOT fall back to guessing at a partial parse."""
