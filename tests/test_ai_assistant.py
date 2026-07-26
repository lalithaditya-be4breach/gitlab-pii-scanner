"""
test_ai_assistant.py
=======================

Tests for Task 2, Phase 2's `AIAssistant`: the orchestrator that ties
`PromptBuilder`, an `AIProvider`, `build_recommendations`, and
`MarkdownReportGenerator` together, and the final layer `main.py`
calls after `ReportGenerator`.

Covers graceful failure handling (disabled AI, provider failure,
missing report, invalid report shape) and that the AI layer never
raises, per the project's "AI failures must never terminate the scan"
requirement.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.ai.ai_assistant import AIAssistant
from scanner.ai.providers import AIProvider, AIProviderError
from scanner.config import ScannerSettings


def _build_test_settings(
    tmp_path: Path, *, ai_enabled: bool = True, ai_provider: str = "null"
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
        ai_enabled=ai_enabled,
        ai_provider=ai_provider,
        ai_summary_filename="ai-summary.md",
    )


def _sample_report(**overrides) -> dict:
    report = {
        "repository": {"identifier": "https://gitlab.com/group/project.git"},
        "summary": {
            "total_findings": 1,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0},
            "risk_score": 7,
            "pipeline_status": "WARNING",
            "risk_thresholds": {"warning": 5, "fail": 50},
        },
        "findings": [
            {
                "file": "app.py",
                "line_number": 1,
                "entity_type": "EMAIL_ADDRESS",
                "severity": "HIGH",
                "confidence_score": 0.9,
                "matched_value": "jo***@example.com",
                "redacted": True,
            }
        ],
    }
    report.update(overrides)
    return report


class _FakeProvider(AIProvider):
    """Test double that returns a fixed response or raises on demand."""

    def __init__(self, response: str | None = None, error: Exception | None = None) -> None:
        self._response = response
        self._error = error
        self.calls: list[str] = []

    def generate(self, prompt: str) -> str:
        self.calls.append(prompt)
        if self._error is not None:
            raise self._error
        return self._response or ""


# -- Happy path -----------------------------------------------------------


def test_generate_summary_uses_provider_narrative(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    provider = _FakeProvider(response="A concise executive summary.")
    assistant = AIAssistant(settings=settings, provider=provider)

    markdown = assistant.generate_summary(_sample_report())

    assert "A concise executive summary." in markdown
    assert len(provider.calls) == 1


def test_generate_writes_markdown_file_to_output_directory(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    provider = _FakeProvider(response="Summary text.")
    assistant = AIAssistant(settings=settings, provider=provider)

    markdown, path = assistant.generate(_sample_report())

    assert path == settings.output_directory / "ai-summary.md"
    assert path.exists()
    assert path.read_text(encoding="utf-8") == markdown


def test_generate_does_not_overwrite_json_report(tmp_path: Path) -> None:
    """The AI summary must be a separate file from the Phase 1 JSON report."""
    settings = _build_test_settings(tmp_path)
    report_path = settings.report_output_directory / "latest.json"
    report_path.parent.mkdir(parents=True)
    report_path.write_text('{"already": "here"}', encoding="utf-8")

    assistant = AIAssistant(settings=settings, provider=_FakeProvider(response="x"))
    _markdown, summary_path = assistant.generate(_sample_report())

    assert summary_path != report_path
    assert report_path.read_text(encoding="utf-8") == '{"already": "here"}'


# -- Graceful failure handling ---------------------------------------------


def test_generate_summary_falls_back_when_provider_raises(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    provider = _FakeProvider(error=AIProviderError("timeout"))
    assistant = AIAssistant(settings=settings, provider=provider)

    markdown = assistant.generate_summary(_sample_report())

    # Deterministic fallback still reports the real pipeline status.
    assert "WARNING" in markdown
    assert "# AI-Assisted Security Summary" in markdown


def test_generate_summary_falls_back_when_provider_raises_unexpected_error(
    tmp_path: Path,
) -> None:
    settings = _build_test_settings(tmp_path)
    provider = _FakeProvider(error=RuntimeError("boom"))
    assistant = AIAssistant(settings=settings, provider=provider)

    markdown = assistant.generate_summary(_sample_report())

    assert "# AI-Assisted Security Summary" in markdown


def test_generate_summary_falls_back_when_provider_returns_empty_response(
    tmp_path: Path,
) -> None:
    settings = _build_test_settings(tmp_path)
    provider = _FakeProvider(response="")
    assistant = AIAssistant(settings=settings, provider=provider)

    markdown = assistant.generate_summary(_sample_report())

    assert "# AI-Assisted Security Summary" in markdown


def test_ai_disabled_never_calls_provider(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path, ai_enabled=False)
    provider = _FakeProvider(response="should never be used")
    assistant = AIAssistant(settings=settings, provider=provider)

    markdown = assistant.generate_summary(_sample_report())

    assert provider.calls == []
    assert "should never be used" not in markdown
    assert "WARNING" in markdown  # deterministic facts still present


def test_null_provider_default_skips_provider_call(tmp_path: Path) -> None:
    """AI_ENABLED=true with AI_PROVIDER=null is the expected default — no LLM call."""
    settings = _build_test_settings(tmp_path, ai_enabled=True, ai_provider="null")
    assistant = AIAssistant(settings=settings)

    with patch("scanner.ai.ai_assistant.PromptBuilder.build") as mock_build:
        markdown = assistant.generate_summary(_sample_report())

    mock_build.assert_not_called()
    assert "WARNING" in markdown
    assert "# AI-Assisted Security Summary" in markdown


def test_write_markdown_rejects_path_traversal_in_summary_filename(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    unsafe_settings = replace(settings, ai_summary_filename="..\\..\\escape.md")
    assistant = AIAssistant(settings=unsafe_settings)

    with pytest.raises(ValueError, match="must not"):
        assistant.write_markdown_report("# summary")


def test_write_markdown_rejects_subdirectory_in_summary_filename(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    unsafe_settings = replace(settings, ai_summary_filename="nested/summary.md")
    assistant = AIAssistant(settings=unsafe_settings)

    with pytest.raises(ValueError, match="single file name"):
        assistant.write_markdown_report("# summary")


def test_unknown_provider_name_falls_back_to_null_provider_without_raising(
    tmp_path: Path,
) -> None:
    settings = _build_test_settings(tmp_path, ai_provider="not-a-real-provider")

    # Constructing AIAssistant must not raise even with a bad provider name.
    assistant = AIAssistant(settings=settings)
    markdown = assistant.generate_summary(_sample_report())

    assert "# AI-Assisted Security Summary" in markdown


# -- Missing / invalid report handling ---------------------------------------


def test_generate_summary_handles_none_report(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    assistant = AIAssistant(settings=settings, provider=_FakeProvider(response="x"))

    markdown = assistant.generate_summary(None)

    assert "# AI-Assisted Security Summary" in markdown
    assert "No valid scan report was available" in markdown


def test_generate_summary_handles_empty_dict_report(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    assistant = AIAssistant(settings=settings, provider=_FakeProvider(response="x"))

    markdown = assistant.generate_summary({})

    assert "No valid scan report was available" in markdown


def test_generate_summary_handles_malformed_report_missing_findings(
    tmp_path: Path,
) -> None:
    """A report dict missing the required `findings` list is not valid."""
    settings = _build_test_settings(tmp_path)
    assistant = AIAssistant(settings=settings, provider=_FakeProvider(response="x"))

    malformed = {"summary": {"total_findings": 1}}  # no "findings" key
    markdown = assistant.generate_summary(malformed)

    assert "No valid scan report was available" in markdown


def test_generate_summary_handles_non_dict_report(tmp_path: Path) -> None:
    """A caller accidentally passing a raw JSON string must not crash."""
    settings = _build_test_settings(tmp_path)
    assistant = AIAssistant(settings=settings, provider=_FakeProvider(response="x"))

    markdown = assistant.generate_summary('{"not": "parsed"}')  # a str, not a dict

    assert "# AI-Assisted Security Summary" in markdown
    assert "No valid scan report was available" in markdown


def test_generate_summary_never_raises_for_any_bad_input(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    assistant = AIAssistant(settings=settings, provider=_FakeProvider(response="x"))

    for bad_input in (None, {}, [], "garbage", 123, {"summary": {}}):
        markdown = assistant.generate_summary(bad_input)
        assert isinstance(markdown, str)
        assert len(markdown) > 0
