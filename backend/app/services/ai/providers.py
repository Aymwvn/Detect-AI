"""
Concrete LLMProvider implementations.

All three follow the same pattern established by the connectors
(connectors/elastic.py, splunk.py, wazuh.py): lazy httpx client
construction so the package is only required if that provider is actually
used, and a `client=` constructor param for test injection since none of
these can be tested against a real endpoint in this environment (no
network access, and definitely no real API keys).

Uses httpx.AsyncClient (not the sync Client the connectors use) since
these are called from async FastAPI request handlers.
"""

from __future__ import annotations

from typing import Any

from app.services.ai.base import LLMProvider
from app.services.ai.exceptions import LLMNotConfiguredError, LLMProviderError


class OllamaProvider(LLMProvider):
    """Local, zero-egress option — the differentiator called out in
    docs/ARCHITECTURE.md's MVP definition (section 16). No API key
    required; talks to a local (or self-hosted) Ollama server."""

    provider_type = "ollama"

    def __init__(self, base_url: str, model: str, client: Any | None = None, timeout_seconds: float = 60.0):
        if not base_url:
            raise LLMNotConfiguredError("OllamaProvider requires a base_url")
        if not model:
            raise LLMNotConfiguredError("OllamaProvider requires a model")
        self.base_url = base_url
        self.model = model
        self._client = client
        self._timeout_seconds = timeout_seconds

    def _build_client(self) -> Any:
        try:
            import httpx
        except ImportError as exc:
            raise LLMProviderError(
                "The 'httpx' package is required for OllamaProvider. Install with: pip install httpx"
            ) from exc
        return httpx.AsyncClient(base_url=self.base_url, timeout=self._timeout_seconds)

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
        }
        try:
            response = await self.client.post("/api/chat", json=body)
        except Exception as exc:
            raise LLMProviderError(f"OllamaProvider request failed: {exc}") from exc

        if response.status_code >= 400:
            raise LLMProviderError(f"OllamaProvider returned HTTP {response.status_code}: {response.text}")

        try:
            return response.json()["message"]["content"]
        except (KeyError, ValueError) as exc:
            raise LLMProviderError(f"OllamaProvider returned an unexpected response shape: {exc}") from exc


class OpenAICompatibleProvider(LLMProvider):
    """Works with OpenAI itself or any OpenAI-compatible endpoint
    (self-hosted vLLM, LM Studio, etc.) — anything implementing the
    /chat/completions contract."""

    provider_type = "openai"

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        model: str,
        client: Any | None = None,
        timeout_seconds: float = 60.0,
    ):
        if not base_url:
            raise LLMNotConfiguredError("OpenAICompatibleProvider requires a base_url")
        if not api_key:
            raise LLMNotConfiguredError("OpenAICompatibleProvider requires an api_key")
        if not model:
            raise LLMNotConfiguredError("OpenAICompatibleProvider requires a model")
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self._client = client
        self._timeout_seconds = timeout_seconds

    def _build_client(self) -> Any:
        try:
            import httpx
        except ImportError as exc:
            raise LLMProviderError(
                "The 'httpx' package is required for OpenAICompatibleProvider. Install with: pip install httpx"
            ) from exc
        return httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self._timeout_seconds,
        )

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        try:
            response = await self.client.post("/chat/completions", json=body)
        except Exception as exc:
            raise LLMProviderError(f"OpenAICompatibleProvider request failed: {exc}") from exc

        if response.status_code >= 400:
            raise LLMProviderError(
                f"OpenAICompatibleProvider returned HTTP {response.status_code}: {response.text}"
            )

        try:
            return response.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as exc:
            raise LLMProviderError(
                f"OpenAICompatibleProvider returned an unexpected response shape: {exc}"
            ) from exc


class AnthropicCompatibleProvider(LLMProvider):
    """Anthropic's Messages API shape: system prompt is a top-level field,
    not a message with role="system"."""

    provider_type = "anthropic"

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        model: str,
        client: Any | None = None,
        timeout_seconds: float = 60.0,
        max_tokens: int = 2048,
    ):
        if not base_url:
            raise LLMNotConfiguredError("AnthropicCompatibleProvider requires a base_url")
        if not api_key:
            raise LLMNotConfiguredError("AnthropicCompatibleProvider requires an api_key")
        if not model:
            raise LLMNotConfiguredError("AnthropicCompatibleProvider requires a model")
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self._client = client
        self._timeout_seconds = timeout_seconds

    def _build_client(self) -> Any:
        try:
            import httpx
        except ImportError as exc:
            raise LLMProviderError(
                "The 'httpx' package is required for AnthropicCompatibleProvider. Install with: pip install httpx"
            ) from exc
        return httpx.AsyncClient(
            base_url=self.base_url,
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
            timeout=self._timeout_seconds,
        )

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        try:
            response = await self.client.post("/v1/messages", json=body)
        except Exception as exc:
            raise LLMProviderError(f"AnthropicCompatibleProvider request failed: {exc}") from exc

        if response.status_code >= 400:
            raise LLMProviderError(
                f"AnthropicCompatibleProvider returned HTTP {response.status_code}: {response.text}"
            )

        try:
            return response.json()["content"][0]["text"]
        except (KeyError, IndexError, ValueError) as exc:
            raise LLMProviderError(
                f"AnthropicCompatibleProvider returned an unexpected response shape: {exc}"
            ) from exc
