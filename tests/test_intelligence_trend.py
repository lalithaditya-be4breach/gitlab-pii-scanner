"""
test_intelligence_trend.py
============================

Tests for Task 2, Phase 4's `TrendAnalyzer`: comparing the current
scan's report against the previously stored report, and graceful
handling when no previous report exists yet.
"""

from __future__ import annotations

from pathlib import Path

from scanner.config import ScannerSettings
from scanner.intelligence.trend import TrendAnalyzer


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


def _report(total_findings: int, risk_score: int, findings: list[dict]) -> dict:
    return {
        "summary": {
            "total_findings": total_findings,
            "risk_score": risk_score,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "pipeline_status": "PASS",
        },
        "findings": findings,
    }


def test_analyze_with_no_previous_report_is_unavailable(tmp_path: Path) -> None:
    analyzer = TrendAnalyzer(_build_test_settings(tmp_path))

    trend = analyzer.analyze(_report(1, 5, [{"entity_type": "EMAIL_ADDRESS"}]))

    assert trend["trend_available"] is False
    assert "message" in trend


def test_store_current_report_then_analyze_detects_increase(tmp_path: Path) -> None:
    analyzer = TrendAnalyzer(_build_test_settings(tmp_path))

    previous = _report(1, 5, [{"entity_type": "EMAIL_ADDRESS"}])
    analyzer.store_current_report(previous)

    current = _report(
        3, 15, [{"entity_type": "EMAIL_ADDRESS"}] * 2 + [{"entity_type": "US_SSN"}]
    )
    trend = analyzer.analyze(current)

    assert trend["trend_available"] is True
    assert trend["previous_total_findings"] == 1
    assert trend["current_total_findings"] == 3
    assert trend["findings_delta"] == 2
    assert trend["findings_trend"] == "increased"
    assert trend["risk_score_delta"] == 10
    assert trend["risk_score_trend"] == "increased"


def test_store_current_report_then_analyze_detects_decrease(tmp_path: Path) -> None:
    analyzer = TrendAnalyzer(_build_test_settings(tmp_path))

    previous = _report(5, 20, [{"entity_type": "EMAIL_ADDRESS"}] * 5)
    analyzer.store_current_report(previous)

    current = _report(1, 5, [{"entity_type": "EMAIL_ADDRESS"}])
    trend = analyzer.analyze(current)

    assert trend["findings_trend"] == "decreased"
    assert trend["risk_score_trend"] == "decreased"


def test_most_improved_and_worst_category_are_identified(tmp_path: Path) -> None:
    analyzer = TrendAnalyzer(_build_test_settings(tmp_path))

    previous = _report(
        4,
        10,
        [{"entity_type": "EMAIL_ADDRESS"}] * 3 + [{"entity_type": "CREDIT_CARD"}],
    )
    analyzer.store_current_report(previous)

    # Personal Information (EMAIL_ADDRESS) drops from 3 to 0 (improved);
    # Financial Data (CREDIT_CARD) grows from 1 to 4 (worse).
    current = _report(4, 12, [{"entity_type": "CREDIT_CARD"}] * 4)
    trend = analyzer.analyze(current)

    assert trend["most_improved_category"] == "Personal Information"
    assert trend["worst_category"] == "Financial Data"


def test_organization_contributes_to_business_information_trend(tmp_path: Path) -> None:
    analyzer = TrendAnalyzer(_build_test_settings(tmp_path))

    previous = _report(0, 0, [])
    analyzer.store_current_report(previous)

    current = _report(1, 3, [{"entity_type": "ORGANIZATION"}])
    trend = analyzer.analyze(current)

    assert trend["category_deltas"]["Business Information"] == 1
    assert trend["worst_category"] == "Business Information"


def test_no_category_change_reports_none_for_both(tmp_path: Path) -> None:
    analyzer = TrendAnalyzer(_build_test_settings(tmp_path))

    previous = _report(1, 5, [{"entity_type": "EMAIL_ADDRESS"}])
    analyzer.store_current_report(previous)

    current = _report(1, 5, [{"entity_type": "EMAIL_ADDRESS"}])
    trend = analyzer.analyze(current)

    assert trend["most_improved_category"] is None
    assert trend["worst_category"] is None


def test_store_current_report_writes_snapshot_file(tmp_path: Path) -> None:
    analyzer = TrendAnalyzer(_build_test_settings(tmp_path))

    path = analyzer.store_current_report(
        _report(1, 5, [{"entity_type": "EMAIL_ADDRESS"}])
    )

    assert path.is_file()

    # New reporting architecture:
    # reports/history/Report_xxx/scan_report.json
    assert path.name == "scan_report.json"
    assert path.parent.name.startswith("Report_")
    assert path.parent.parent.name == "history"
    assert path.parent.parent.parent.name == "reports"


def test_analyze_gracefully_ignores_corrupt_previous_report(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    analyzer = TrendAnalyzer(settings)

    snapshot_dir = settings.output_directory / "intelligence"
    snapshot_dir.mkdir(parents=True)
    (snapshot_dir / "previous_scan_report.json").write_text("{ not valid json", encoding="utf-8")

    trend = analyzer.analyze(_report(1, 5, [{"entity_type": "EMAIL_ADDRESS"}]))

    assert trend["trend_available"] is False
