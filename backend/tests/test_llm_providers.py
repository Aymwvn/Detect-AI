"""
Tests for app/services/ai/providers.py and factory.py.

No real LLM endpoint is reachable from this environment (and definitely no
real API keys), so these use fake async clients shaped like
httpx.AsyncClient. Verifies request construction and response parsing for
each provider's specific API shape.
"""

import pytest

from app.core.config import Settings
from app.services.ai.exceptions import LLMNotConfiguredError, LLMProviderError
from app.services.ai.factory import get_llm_provider
from app.services.ai.providers import AnthropicCompatibleProvider, OllamaProvider, OpenAICompatibleProvider


class FakeResponse:
    def __init__(self, status_code: int, json_body: dict, text: str = ""):
        self.status_code = status_code
        self._json_body = json_body
        self.text = text or str(json_body)

    def json(self):
        return self._json_body


class FakeAsyncClient:
    def __init__(self, response_body: dict, status_code: int = 200):
        self._response_body = response_body
        self._status_code = status_code
        self.post_calls: list[tuple[str, dict]] = []

    async def post(self, path, json=None):
        self.post_calls.append((path, json or {}))
        return FakeResponse(self._status_code, self._response_body)


# --- OllamaProvider -------------------------------------------------

@pytest.mark.asyncio
async def test_ollama_complete_parses_response():
    fake = FakeAsyncClient({"message": {"role": "assistant", "content": '{"classification": "test"}'}})
    provider = OllamaProvider(base_url="http://fake-ollama:11434", model="llama3", client=fake)
    result = await provider.complete("system prompt", "user prompt")
    assert result == '{"classification": "test"}'

    path, body = fake.post_calls[0]
    assert path == "/api/chat"
    assert body["model"] == "llama3"
    assert body["messages"][0]["role"] == "system"
    assert body["messages"][1]["content"] == "user prompt"


@pytest.mark.asyncio
async def test_ollama_complete_http_error_raises_provider_error():
    fake = FakeAsyncClient({}, status_code=500)
    provider = OllamaProvider(base_url="http://fake-ollama:11434", model="llama3", client=fake)
    with pytest.raises(LLMProviderError):
        await provider.complete("s", "u")


@pytest.mark.asyncio
async def test_ollama_complete_unexpected_shape_raises_provider_error():
    fake = FakeAsyncClient({"unexpected": "shape"})
    provider = OllamaProvider(base_url="http://fake-ollama:11434", model="llama3", client=fake)
    with pytest.raises(LLMProviderError):
        await provider.complete("s", "u")


def test_ollama_missing_base_url_raises_not_configured():
    with pytest.raises(LLMNotConfiguredError):
        OllamaProvider(base_url="", model="llama3")


def test_ollama_missing_model_raises_not_configured():
    with pytest.raises(LLMNotConfiguredError):
        OllamaProvider(base_url="http://fake:11434", model="")


# --- OpenAICompatibleProvider -------------------------------------------------

@pytest.mark.asyncio
async def test_openai_complete_parses_response():
    fake = FakeAsyncClient(
        {"choices": [{"message": {"role": "assistant", "content": '{"classification": "test"}'}}]}
    )
    provider = OpenAICompatibleProvider(
        base_url="https://fake-openai", api_key="fake-key", model="gpt-4o-mini", client=fake
    )
    result = await provider.complete("system prompt", "user prompt")
    assert result == '{"classification": "test"}'

    path, body = fake.post_calls[0]
    assert path == "/chat/completions"
    assert body["messages"][0]["content"] == "system prompt"


@pytest.mark.asyncio
async def test_openai_complete_http_error_raises_provider_error():
    fake = FakeAsyncClient({}, status_code=401)
    provider = OpenAICompatibleProvider(
        base_url="https://fake-openai", api_key="bad-key", model="gpt-4o-mini", client=fake
    )
    with pytest.raises(LLMProviderError):
        await provider.complete("s", "u")


def test_openai_missing_api_key_raises_not_configured():
    with pytest.raises(LLMNotConfiguredError):
        OpenAICompatibleProvider(base_url="https://fake-openai", api_key=None, model="gpt-4o-mini")


# --- AnthropicCompatibleProvider -------------------------------------------------

@pytest.mark.asyncio
async def test_anthropic_complete_parses_response():
    fake = FakeAsyncClient({"content": [{"type": "text", "text": '{"classification": "test"}'}]})
    provider = AnthropicCompatibleProvider(
        base_url="https://fake-anthropic", api_key="fake-key", model="claude-sonnet-4-6", client=fake
    )
    result = await provider.complete("system prompt", "user prompt")
    assert result == '{"classification": "test"}'

    path, body = fake.post_calls[0]
    assert path == "/v1/messages"
    assert body["system"] == "system prompt"
    assert body["messages"][0]["role"] == "user"


@pytest.mark.asyncio
async def test_anthropic_complete_http_error_raises_provider_error():
    fake = FakeAsyncClient({}, status_code=529)
    provider = AnthropicCompatibleProvider(
        base_url="https://fake-anthropic", api_key="fake-key", model="claude-sonnet-4-6", client=fake
    )
    with pytest.raises(LLMProviderError):
        await provider.complete("s", "u")


def test_anthropic_missing_model_raises_not_configured():
    with pytest.raises(LLMNotConfiguredError):
        AnthropicCompatibleProvider(base_url="https://fake-anthropic", api_key="k", model="")


# --- factory -------------------------------------------------

def _settings(**overrides) -> Settings:
    return Settings(**overrides)


def test_factory_returns_none_for_ai_provider_none():
    assert get_llm_provider(_settings(ai_provider="none")) is None


def test_factory_builds_ollama_with_defaults():
    provider = get_llm_provider(_settings(ai_provider="ollama"))
    assert isinstance(provider, OllamaProvider)
    assert provider.base_url == "http://localhost:11434"
    assert provider.model == "llama3"


def test_factory_builds_openai_with_configured_values():
    provider = get_llm_provider(
        _settings(ai_provider="openai", ai_api_key="k", ai_model="gpt-4o-mini")
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.model == "gpt-4o-mini"


def test_factory_builds_anthropic_with_defaults():
    provider = get_llm_provider(_settings(ai_provider="anthropic", ai_api_key="k"))
    assert isinstance(provider, AnthropicCompatibleProvider)
    assert provider.model == "claude-sonnet-4-6"
