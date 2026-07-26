"""
providers.py
============

Task 2, Phase 2: replaceable AI provider abstraction.

`AIAssistant` (in `ai_assistant.py`) never talks to an LLM SDK or HTTP
API directly — it only depends on the small `AIProvider` interface
defined here. This keeps the AI assistant layer decoupled from any one
vendor and makes it trivial to add another provider later without
touching `ai_assistant.py`, `prompt_builder.py`, or
`markdown_generator.py`.

    AIProvider (abstract)
        |
        +-- NullAIProvider        (no-op / disabled — always "unavailable")
        +-- OpenAIProvider        (api.openai.com)
        +-- AzureOpenAIProvider   (Azure OpenAI Service)

Every provider either returns a non-empty string from `generate()` or
raises `AIProviderError`. There is exactly one failure type callers
need to handle, regardless of *why* the provider failed (missing API
key, missing configuration, timeout, invalid response, the provider
being unreachable, or an unknown provider name).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from scanner.config import ScannerSettings
from scanner.logger import get_logger

logger = get_logger(__name__)


class AIProviderError(Exception):
    """
    Raised whenever an `AIProvider` cannot produce a usable response.

    Callers (see `AIAssistant.generate_summary`) treat every
    `AIProviderError` the same way: log a warning and fall back to a
    deterministic, non-AI summary. This exception is never allowed to
    propagate out of `scanner.ai` and abort a scan.
    """


class AIProvider(ABC):
    """Minimal interface every AI provider implementation must satisfy."""

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """
        Generate a natural-language response for `prompt`.

        Args:
            prompt: The full prompt text, as produced by
                `scanner.ai.prompt_builder.PromptBuilder`.

        Returns:
            A non-empty response string.

        Raises:
            AIProviderError: on any failure — missing configuration,
                a timeout, an unreachable provider, or an invalid/empty
                response. Implementations must not raise anything else.
        """
        raise NotImplementedError


class NullAIProvider(AIProvider):
    """
    Fallback provider used when AI is disabled or misconfigured.

    Deliberately never performs any network call. It always raises
    `AIProviderError`, which routes every caller through the exact
    same deterministic-fallback code path used for a real provider's
    failure — there is no special-casing of "AI is off" versus "AI
    tried and failed" anywhere above this layer.
    """

    def generate(self, prompt: str) -> str:  # noqa: ARG002 - intentionally unused
        raise AIProviderError(
            "AI generation is disabled (null provider); using the "
            "deterministic fallback summary."
        )


class OpenAIProvider(AIProvider):
    """AI provider backed by the public OpenAI Chat Completions API."""

    def __init__(
        self,
        api_key: str,
        model: str,
        temperature: float,
        timeout_seconds: int,
    ) -> None:
        """
        Args:
            api_key: OpenAI API key.
            model: Chat completion model name, e.g. "gpt-4o-mini".
            temperature: Sampling temperature (0.0-2.0).
            timeout_seconds: Per-request timeout.

        Raises:
            AIProviderError: if `api_key` is missing. Validation happens
                at construction time so misconfiguration is caught
                before a prompt is ever built.
        """
        if not api_key:
            raise AIProviderError(
                "OpenAI provider selected but no API key was configured "
                "(set AI_API_KEY)."
            )
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._timeout_seconds = timeout_seconds

    def generate(self, prompt: str) -> str:
        try:
            from openai import APIError, APITimeoutError, OpenAI
        except ImportError as exc:
            raise AIProviderError(
                "The 'openai' package is not installed. Install it with "
                "`pip install openai` to use AI_PROVIDER=openai."
            ) from exc

        try:
            client = OpenAI(api_key=self._api_key, timeout=self._timeout_seconds)
            response = client.chat.completions.create(
                model=self._model,
                temperature=self._temperature,
                messages=[{"role": "user", "content": prompt}],
            )
        except APITimeoutError as exc:
            raise AIProviderError(f"OpenAI request timed out: {exc}") from exc
        except APIError as exc:
            raise AIProviderError(f"OpenAI API error: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - any SDK failure must degrade gracefully
            raise AIProviderError(f"OpenAI request failed: {exc}") from exc

        text = self._extract_text(response)
        if not text or not text.strip():
            raise AIProviderError("OpenAI returned an empty response.")
        return text

    @staticmethod
    def _extract_text(response: object) -> str:
        try:
            return response.choices[0].message.content or ""
        except (AttributeError, IndexError) as exc:
            raise AIProviderError(
                f"OpenAI returned an unexpected response shape: {exc}"
            ) from exc


class AzureOpenAIProvider(AIProvider):
    """AI provider backed by an Azure OpenAI Service deployment."""

    def __init__(
        self,
        api_key: str,
        endpoint: str,
        api_version: str,
        model: str,
        temperature: float,
        timeout_seconds: int,
    ) -> None:
        """
        Args:
            api_key: Azure OpenAI API key.
            endpoint: Azure OpenAI resource endpoint, e.g.
                "https://my-resource.openai.azure.com".
            api_version: Azure OpenAI API version.
            model: The deployment name to call.
            temperature: Sampling temperature (0.0-2.0).
            timeout_seconds: Per-request timeout.

        Raises:
            AIProviderError: if `api_key` or `endpoint` is missing.
        """
        missing = [
            name
            for name, value in (("AI_API_KEY", api_key), ("AI_AZURE_ENDPOINT", endpoint))
            if not value
        ]
        if missing:
            raise AIProviderError(
                "Azure OpenAI provider selected but required configuration "
                f"is missing: {', '.join(missing)}."
            )
        self._api_key = api_key
        self._endpoint = endpoint
        self._api_version = api_version
        self._model = model
        self._temperature = temperature
        self._timeout_seconds = timeout_seconds

    def generate(self, prompt: str) -> str:
        try:
            from openai import APIError, APITimeoutError, AzureOpenAI
        except ImportError as exc:
            raise AIProviderError(
                "The 'openai' package is not installed. Install it with "
                "`pip install openai` to use AI_PROVIDER=azure_openai."
            ) from exc

        try:
            client = AzureOpenAI(
                api_key=self._api_key,
                azure_endpoint=self._endpoint,
                api_version=self._api_version,
                timeout=self._timeout_seconds,
            )
            response = client.chat.completions.create(
                model=self._model,
                temperature=self._temperature,
                messages=[{"role": "user", "content": prompt}],
            )
        except APITimeoutError as exc:
            raise AIProviderError(f"Azure OpenAI request timed out: {exc}") from exc
        except APIError as exc:
            raise AIProviderError(f"Azure OpenAI API error: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - any SDK failure must degrade gracefully
            raise AIProviderError(f"Azure OpenAI request failed: {exc}") from exc

        text = OpenAIProvider._extract_text(response)
        if not text or not text.strip():
            raise AIProviderError("Azure OpenAI returned an empty response.")
        return text


# Provider names accepted for AI_PROVIDER="null" / disabled.
_NULL_PROVIDER_ALIASES = frozenset({"", "null", "none", "disabled", "off"})
_OPENAI_PROVIDER_ALIASES = frozenset({"openai"})
_AZURE_PROVIDER_ALIASES = frozenset({"azure", "azure_openai", "azure-openai"})


def is_null_provider_name(provider_name: str | None) -> bool:
    """Return True when `provider_name` selects the deterministic null/disabled provider."""
    return (provider_name or "null").strip().lower() in _NULL_PROVIDER_ALIASES


def get_provider(settings: ScannerSettings) -> AIProvider:
    """
    Build the `AIProvider` selected by `settings.ai_provider`.

    Args:
        settings: Application settings, providing `ai_provider` and the
            provider-specific fields (`ai_api_key`, `ai_model`, etc.)

    Returns:
        A ready-to-use `AIProvider`.

    Raises:
        AIProviderError: if `ai_provider` names an unknown provider, or
            if the selected provider is missing required configuration.
            Callers (see `AIAssistant`) must catch this and fall back
            to the deterministic summary rather than letting it abort
            the scan.
    """
    provider_name = (settings.ai_provider or "null").strip().lower()

    if is_null_provider_name(provider_name):
        return NullAIProvider()

    if provider_name in _OPENAI_PROVIDER_ALIASES:
        return OpenAIProvider(
            api_key=settings.ai_api_key,
            model=settings.ai_model,
            temperature=settings.ai_temperature,
            timeout_seconds=settings.ai_timeout_seconds,
        )

    if provider_name in _AZURE_PROVIDER_ALIASES:
        return AzureOpenAIProvider(
            api_key=settings.ai_api_key,
            endpoint=settings.ai_azure_endpoint,
            api_version=settings.ai_azure_api_version,
            model=settings.ai_model,
            temperature=settings.ai_temperature,
            timeout_seconds=settings.ai_timeout_seconds,
        )

    raise AIProviderError(f"Unknown AI provider: {settings.ai_provider!r}")
