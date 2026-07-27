"""
test_intelligence_dashboard.py
================================

Tests for Task 2, Phase 4's `DashboardBuilder`: the backend-only
`dashboard.json` aggregate.
"""

from __future__ import annotations

import json
from pathlib import Path

from scanner.config import ScannerSettings
from scanner.intelligence.dashboard import DashboardBuilder


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
        "summary": {
            "total_findings": 3,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 2, "CRITICAL": 1},
            "risk_score": 12,
            "pipeline_status": "WARNING",
        },
        "findings": [
            {"file": "app.py", "line_number": 1, "entity_type": "EMAIL_ADDRESS", "severity": "HIGH"},
            {"file": "app.py", "line_number": 2, "entity_type": "PHONE_NUMBER", "severity": "HIGH"},
            {"file": "config.py", "line_number": 3, "entity_type": "CREDIT_CARD", "severity": "CRITICAL"},
        ],
    }


def test_build_includes_summary_from_report(tmp_path: Path) -> None:
    builder = DashboardBuilder(_build_test_settings(tmp_path))

    dashboard = builder.build(_sample_report(), {"trend_available": False})

    assert dashboard["summary"]["total_findings"] == 3
    assert dashboard["summary"]["risk_score"] == 12
    assert dashboard["summary"]["pipeline_status"] == "WARNING"


def test_build_includes_category_counts(tmp_path: Path) -> None:
    builder = DashboardBuilder(_build_test_settings(tmp_path))

    dashboard = builder.build(_sample_report(), {"trend_available": False})

    assert dashboard["category_counts"]["Financial Data"] == 1
    assert dashboard["category_counts"]["Personal Information"] == 2


def test_build_counts_organization_as_business_information(tmp_path: Path) -> None:
    builder = DashboardBuilder(_build_test_settings(tmp_path))
    report = _sample_report()
    report["findings"].append(
        {
            "file": "docs.md",
            "line_number": 5,
            "entity_type": "ORGANIZATION",
            "severity": "MEDIUM",
        }
    )

    dashboard = builder.build(report, {"trend_available": False})

    assert dashboard["category_counts"]["Business Information"] == 1


def test_build_top_files_sorted_by_finding_count(tmp_path: Path) -> None:
    builder = DashboardBuilder(_build_test_settings(tmp_path))

    dashboard = builder.build(_sample_report(), {"trend_available": False})

    assert dashboard["top_files"][0]["file"] == "app.py"
    assert dashboard["top_files"][0]["finding_count"] == 2


def test_build_top_findings_includes_finding_ids(tmp_path: Path) -> None:
    builder = DashboardBuilder(_build_test_settings(tmp_path))

    dashboard = builder.build(_sample_report(), {"trend_available": False})

    assert all("finding_id" in item for item in dashboard["top_findings"])


def test_build_missing_report_does_not_raise(tmp_path: Path) -> None:
    builder = DashboardBuilder(_build_test_settings(tmp_path))

    dashboard = builder.build(None, {"trend_available": False})

    assert dashboard["summary"]["total_findings"] == 0
    assert dashboard["top_files"] == []


def test_generate_writes_valid_json_file(tmp_path: Path) -> None:
    builder = DashboardBuilder(_build_test_settings(tmp_path))

    dashboard, path = builder.generate(_sample_report(), {"trend_available": False})

    assert path.is_file()
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk == dashboard
