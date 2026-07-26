"""
test_config.py
==============

Focused configuration validation tests.
"""

from __future__ import annotations

import pytest

from scanner.config import ConfigError, ScannerSettings


@pytest.fixture(autouse=True)
def _clear_settings_singleton(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scanner.config._settings_instance", None)


def test_load_accepts_default_ai_summary_filename(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AI_SUMMARY_FILENAME", raising=False)

    settings = ScannerSettings.load()

    assert settings.ai_summary_filename == "ai-summary.md"


@pytest.mark.parametrize(
    "filename",
    [
        "../escape.md",
        r"..\escape.md",
        "nested/summary.md",
        r"nested\summary.md",
        "/tmp/summary.md",
        r"C:\tmp\summary.md",
    ],
)
def test_load_rejects_unsafe_ai_summary_filename(
    monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    monkeypatch.setenv("AI_SUMMARY_FILENAME", filename)

    with pytest.raises(ConfigError, match="AI_SUMMARY_FILENAME"):
        ScannerSettings.load()
