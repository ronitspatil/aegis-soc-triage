"""LLM factory: maps an abstract ROLE to a concrete, configured client.

Nodes call `get_llm(ModelRole.WORKER)`. They never know or care which vendor
or model is behind it, that is the entire point of the indirection.
"""

from __future__ import annotations

from functools import cache

from langchain_core.language_models.chat_models import BaseChatModel

from aegis.llm.config import LLMSettings, ModelRole, Provider, get_settings


def _build_client(provider: Provider, model: str, settings: LLMSettings) -> BaseChatModel:
    """Construct one vendor client. Imports are local so an unused provider's
    SDK is never a hard import-time dependency."""

    if provider is Provider.OLLAMA:
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=model,
            base_url=settings.ollama_base_url,
            temperature=settings.temperature,
        )

    if provider is Provider.OPENROUTER:
        # OpenRouter speaks the OpenAI wire protocol; only the base_url differs.
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model,
            api_key=settings.openrouter_api_key,
            base_url=settings.openrouter_base_url,
            temperature=settings.temperature,
            timeout=settings.request_timeout,
        )

    if provider is Provider.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=model,
            api_key=settings.anthropic_api_key,
            temperature=settings.temperature,
            timeout=settings.request_timeout,
        )

    # Enum exhaustiveness guard: adding a Provider without wiring it fails loudly.
    raise ValueError(f"Unsupported provider: {provider}")


@cache
def get_llm(role: ModelRole) -> BaseChatModel:
    """Return the cached client for a tier.

    Cached because the three worker nodes run in parallel per alert; rebuilding
    an HTTP client (and its connection pool) three times per alert is pure waste.
    """
    settings = get_settings()

    if role is ModelRole.WORKER:
        return _build_client(settings.worker_provider, settings.worker_model, settings)
    if role is ModelRole.REASONER:
        return _build_client(settings.reasoner_provider, settings.reasoner_model, settings)

    raise ValueError(f"Unsupported role: {role}")


def reset_llm_cache() -> None:
    """Drop cached clients.

    `get_llm` is `@lru_cache`d, so a client built from stale settings survives
    any later change to the environment or `.env`. Call this after mutating
    configuration, tests that switch providers MUST call it between cases.
    """
    get_llm.cache_clear()
