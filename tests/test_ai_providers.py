"""
test_ai_providers.py
======================

Tests for Task 2, Phase 2's `scanner.ai.providers`: the replaceable
`AIProvider` abstraction, its Null/OpenAI/Azure implementations, and
the `get_provider` factory. Every failure mode (missing API key,
missing config, unknown provider, missing SDK) must raise
`AIProviderError` rather than any other exception type, so callers can
handle every failure identically.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.ai.providers import (
    AIProvider,
    AIProviderError,
    AzureOpenAIProvider,
    NullAIProvider,
    OpenAIProvider,
    get_provider,
)
from scanner.config import ScannerSettings


def _build_test_settings(
    tmp_path: Path,
    *,
    ai_provider: str = "null",
    ai_api_key: str = "",
    ai_azure_endpoint: str = "",
) -> ScannerSettings:
    output_directory = tmp_path / "output"
    return ScannerSettings(
        app_name="gitlab-pii-scanner-test",
        environment="test",
        log_level="DEBUG",
        working_directory=tmp_path,
        output_directory=output_directory,
        supported_extensions=(".py",),
        excluded_directories=(".git",),
        max_file_size_bytes=5 * 1024 * 1024,
        presidio_language="en",
        presidio_min_confidence=0.5,
        presidio_spacy_model="en_core_web_lg",
        clone_base_directory=output_directory / "cloned_repositories",
        clone_shallow_depth=1,
        risk_warning_threshold=20,
        risk_fail_threshold=50,
        report_output_directory=output_directory / "reports",
        report_redaction_enabled=True,
        ai_enabled=True,
        ai_provider=ai_provider,
        ai_api_key=ai_api_key,
        ai_model="gpt-4o-mini",
        ai_temperature=0.2,
        ai_timeout_seconds=30,
        ai_azure_endpoint=ai_azure_endpoint,
        ai_azure_api_version="2024-08-01-preview",
    )


# -- NullAIProvider ------------------------------------------------------


def test_null_provider_always_raises_ai_provider_error() -> None:
    with pytest.raises(AIProviderError):
        NullAIProvider().generate("any prompt")


def test_null_provider_is_an_ai_provider() -> None:
    assert isinstance(NullAIProvider(), AIProvider)


# -- get_provider() factory -----------------------------------------------


@pytest.mark.parametrize("provider_name", ["null", "none", "disabled", "off", ""])
def test_get_provider_returns_null_provider_for_disabled_aliases(
    tmp_path: Path, provider_name: str
) -> None:
    settings = _build_test_settings(tmp_path, ai_provider=provider_name)
    assert isinstance(get_provider(settings), NullAIProvider)


def test_get_provider_raises_for_unknown_provider(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path, ai_provider="not-a-real-provider")

    with pytest.raises(AIProviderError):
        get_provider(settings)


def test_get_provider_raises_for_openai_without_api_key(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path, ai_provider="openai", ai_api_key="")

    with pytest.raises(AIProviderError):
        get_provider(settings)


def test_get_provider_builds_openai_provider_with_api_key(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path, ai_provider="openai", ai_api_key="sk-test")

    provider = get_provider(settings)

    assert isinstance(provider, OpenAIProvider)


def test_get_provider_raises_for_azure_without_endpoint(tmp_path: Path) -> None:
    settings = _build_test_settings(
        tmp_path, ai_provider="azure_openai", ai_api_key="key", ai_azure_endpoint=""
    )

    with pytest.raises(AIProviderError):
        get_provider(settings)


def test_get_provider_builds_azure_provider_with_full_config(tmp_path: Path) -> None:
    settings = _build_test_settings(
        tmp_path,
        ai_provider="azure_openai",
        ai_api_key="key",
        ai_azure_endpoint="https://example.openai.azure.com",
    )

    provider = get_provider(settings)

    assert isinstance(provider, AzureOpenAIProvider)


# -- Missing SDK dependency (openai isn't installed in this environment) --


def test_openai_provider_generate_raises_when_sdk_not_installed() -> None:
    """
    A missing `openai` package must degrade to AIProviderError, not an
    unhandled ImportError, so a caller without the optional dependency
    installed still gets a graceful fallback.
    """
    provider = OpenAIProvider(
        api_key="sk-test", model="gpt-4o-mini", temperature=0.2, timeout_seconds=5
    )

    with pytest.raises(AIProviderError):
        provider.generate("any prompt")


def test_azure_openai_provider_generate_raises_when_sdk_not_installed() -> None:
    provider = AzureOpenAIProvider(
        api_key="key",
        endpoint="https://example.openai.azure.com",
        api_version="2024-08-01-preview",
        model="gpt-4o-mini",
        temperature=0.2,
        timeout_seconds=5,
    )

    with pytest.raises(AIProviderError):
        provider.generate("any prompt")
