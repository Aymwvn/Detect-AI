"""
LLMProvider — the abstraction every AI backend implements (architecture
doc section 13). Nothing outside app/services/ai/ should ever call
OpenAI/Anthropic/Ollama directly; everything goes through this interface,
so switching providers is a config change, not a code change.

`complete()` is intentionally the ONLY method: raw system prompt + user
prompt in, raw text out. Prompt construction, JSON parsing, schema
validation, and evidence reconciliation are all provider-agnostic concerns
that live in app/services/ai/analysis.py instead — keeping providers this
thin means adding a new one is a small, easily-reviewed diff.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    #: Short identifier ("openai", "anthropic", "ollama") — stored on
    #: AIAnalysis rows for audit purposes, so "which provider produced
    #: this conclusion" is always answerable later.
    provider_type: str = "unknown"
    model: str = ""

    @abstractmethod
    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Sends the two prompts to the underlying model and returns its
        raw text response. Must raise LLMProviderError (not a bare
        provider-specific exception) on any failure — network, auth, rate
        limit, malformed response — so callers have one exception type to
        handle regardless of which provider is configured."""
        raise NotImplementedError
