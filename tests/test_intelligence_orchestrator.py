"""
test_intelligence_orchestrator.py
===================================

Tests for Task 2, Phase 4's `IntelligenceEngine`: the single
integration point `main.py` calls. Covers artifact generation and,
critically, that a failure never raises -- mirroring
`scanner.ai.AIAssistant`'s "AI must never abort the scan" guarantee.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.config import ScannerSettings
from scanner.intelligence.orchestrator import IntelligenceEngine


def _build_test_settings(tmp_path: Path) -> ScannerSettings:
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
    )


def _sample_report() -> dict:
    return {
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
                "confidence_score": 1.0,
                "severity": "HIGH",
                "matched_value": "jo***@example.com",
                "redacted": True,
            }
        ],
    }


def test_generate_all_writes_developer_guidance_and_dashboard(tmp_path: Path) -> None:
    engine = IntelligenceEngine(_build_test_settings(tmp_path))

    artifacts = engine.generate_all(_sample_report())

    assert artifacts["developer_guidance"].is_file()
    assert artifacts["dashboard"].is_file()
    assert "Developer Guidance Report" in artifacts["developer_guidance"].read_text(
        encoding="utf-8"
    )


def test_generate_all_stores_previous_report_snapshot(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    engine = IntelligenceEngine(settings)

    engine.generate_all(_sample_report())

    history_dir = settings.working_directory / "reports" / "history"

    assert history_dir.exists()

    reports = list(history_dir.glob("Report_*"))

    assert len(reports) == 1

    snapshot = reports[0] / "scan_report.json"

    assert snapshot.is_file()


def test_generate_all_second_run_reflects_trend(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    engine = IntelligenceEngine(settings)

    engine.generate_all(_sample_report())

    second_report = _sample_report()
    second_report["summary"]["total_findings"] = 3
    second_report["summary"]["risk_score"] = 15
    second_report["findings"] = second_report["findings"] * 3

    artifacts = engine.generate_all(second_report)
    dashboard_text = artifacts["dashboard"].read_text(encoding="utf-8")

    assert '"trend_available": true' in dashboard_text


def test_generate_all_none_report_returns_empty_dict_and_does_not_raise(
    tmp_path: Path,
) -> None:
    engine = IntelligenceEngine(_build_test_settings(tmp_path))

    assert engine.generate_all(None) == {}


def test_generate_all_malformed_report_returns_empty_dict_and_does_not_raise(
    tmp_path: Path,
) -> None:
    engine = IntelligenceEngine(_build_test_settings(tmp_path))

    assert engine.generate_all({"not": "a valid report"}) == {}


def test_generate_all_never_raises_even_if_guidance_builder_fails(tmp_path: Path) -> None:
    engine = IntelligenceEngine(_build_test_settings(tmp_path))
    engine._guidance_builder.generate = lambda report: (_ for _ in ()).throw(
        RuntimeError("boom")
    )

    # Must not raise -- dashboard/trend storage should still be attempted.
    artifacts = engine.generate_all(_sample_report())
    assert "developer_guidance" not in artifacts
