"""
test_executive_report.py
========================

Tests for the additive human-readable executive report package.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from scanner.config import ScannerSettings
from scanner.executive_report import ExecutiveReportPackage


def _build_test_settings(tmp_path: Path) -> ScannerSettings:
    output_directory = tmp_path / "output"
    return ScannerSettings(
        app_name="gitlab-pii-scanner-test",
        environment="test",
        log_level="CRITICAL",
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


def _scan_report() -> dict:
    return {
        "schema_version": "1.0",
        "scanner_version": "0.4.0",
        "repository": {"identifier": "example/repo"},
        "scan": {
            "started_at": "2026-07-27T10:00:00+00:00",
            "finished_at": "2026-07-27T10:01:00+00:00",
            "duration_seconds": 60.0,
            "files_scanned": 12,
            "files_skipped": 0,
        },
        "summary": {
            "total_findings": 2,
            "severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
            "risk_score": 22,
            "pipeline_status": "FAIL",
            "risk_thresholds": {"warning": 20, "fail": 50},
        },
        "findings": [
            {
                "file": "app.py",
                "line_number": 10,
                "entity_type": "CREDIT_CARD",
                "severity": "CRITICAL",
                "confidence_score": 0.99,
                "matched_value": "************1111",
                "redacted": True,
            },
            {
                "file": "docs.md",
                "line_number": 5,
                "entity_type": "ORGANIZATION",
                "severity": "HIGH",
                "confidence_score": 0.92,
                "matched_value": "ExampleCorp",
                "redacted": True,
            },
        ],
    }


def _dashboard() -> dict:
    return {
        "summary": {"total_findings": 2, "risk_score": 22, "pipeline_status": "FAIL"},
        "category_counts": {"Financial Data": 1, "Business Information": 1},
        "trend": {"trend_available": False},
        "top_files": [{"file": "app.py", "finding_count": 1}],
        "top_findings": [],
        "severity_distribution": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
    }


def _write_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    scan_report_path = tmp_path / "latest.json"
    ai_summary_path = tmp_path / "ai-summary.md"
    developer_guidance_path = tmp_path / "developer-guidance.md"
    dashboard_path = tmp_path / "dashboard.json"

    scan_report_path.write_text(json.dumps(_scan_report()), encoding="utf-8")
    ai_summary_path.write_text(
        "# AI-Assisted Security Summary\n\n"
        "## Recommendations\n\n"
        "- **CREDIT_CARD** (CRITICAL): Remove payment card data.\n\n"
        "## Prioritized Actions\n\n"
        "1. Address **CREDIT_CARD** findings first.\n\n"
        "## Compliance Considerations\n\n"
        "Review obligations.",
        encoding="utf-8",
    )
    developer_guidance_path.write_text("# Developer Guidance Report\n", encoding="utf-8")
    dashboard_path.write_text(json.dumps(_dashboard()), encoding="utf-8")
    return scan_report_path, ai_summary_path, developer_guidance_path, dashboard_path


def test_generate_creates_numbered_report_folder_and_expected_files(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    scan_path, ai_path, guidance_path, dashboard_path = _write_inputs(tmp_path)

    report_dir = ExecutiveReportPackage(settings).generate(
        scan_report=_scan_report(),
        scan_report_path=scan_path,
        ai_summary_path=ai_path,
        developer_guidance_path=guidance_path,
        dashboard_json_path=dashboard_path,
        now=datetime(2026, 7, 27, 10, 45, 33),
    )

    assert report_dir.name == "Report_001_2026-07-27_10-45-33"
    assert (report_dir / "Executive_Report.html").is_file()
    assert (report_dir / "Dashboard.html").is_file()
    assert (report_dir / "Developer_Guidance.md").is_file()
    assert (report_dir / "AI_Summary.md").is_file()
    assert (report_dir / "dashboard.json").is_file()
    assert (report_dir / "scan_report.json").is_file()


def test_generate_increments_report_number_without_overwrite(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    existing = tmp_path / "reports" / "Report_001_2026-07-27_10-45-33"
    existing.mkdir(parents=True)
    scan_path, ai_path, guidance_path, dashboard_path = _write_inputs(tmp_path)

    report_dir = ExecutiveReportPackage(settings).generate(
        scan_report=_scan_report(),
        scan_report_path=scan_path,
        ai_summary_path=ai_path,
        developer_guidance_path=guidance_path,
        dashboard_json_path=dashboard_path,
        now=datetime(2026, 7, 27, 14, 18, 1),
    )

    assert report_dir.name == "Report_002_2026-07-27_14-18-01"
    assert existing.is_dir()


def test_executive_report_contains_management_sections(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    scan_path, ai_path, guidance_path, dashboard_path = _write_inputs(tmp_path)

    report_dir = ExecutiveReportPackage(settings).generate(
        scan_report=_scan_report(),
        scan_report_path=scan_path,
        ai_summary_path=ai_path,
        developer_guidance_path=guidance_path,
        dashboard_json_path=dashboard_path,
        now=datetime(2026, 7, 27, 10, 45, 33),
    )

    html = (report_dir / "Executive_Report.html").read_text(encoding="utf-8")

    assert "PII Security Assessment Report" in html
    assert "Top Critical Findings" in html
    assert "AI Security Summary" in html
    assert "Prioritized Actions" in html
    assert "AI Release Recommendation" in html
    assert "DO NOT RELEASE" in html
