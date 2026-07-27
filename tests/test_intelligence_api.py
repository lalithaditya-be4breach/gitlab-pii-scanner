"""
test_intelligence_api.py
==========================

Tests for Task 2, Phase 4's `ExplainService` (the `/api/explain`
logic): answers about a single finding derived only from an
already-written JSON report, never re-running the scanner.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.intelligence.api import ExplainService, ExplainServiceError
from scanner.intelligence.finding_ids import compute_finding_id


def _sample_report() -> dict:
    return {
        "summary": {
            "total_findings": 1,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0},
            "risk_score": 7,
            "pipeline_status": "WARNING",
        },
        "findings": [
            {
                "file": "app.py",
                "line_number": 10,
                "entity_type": "EMAIL_ADDRESS",
                "confidence_score": 1.0,
                "severity": "HIGH",
                "matched_value": "jo***@example.com",
                "redacted": True,
            }
        ],
    }


def test_explain_returns_expected_fields_for_valid_id() -> None:
    service = ExplainService(_sample_report())

    result = service.explain(compute_finding_id(0))

    assert result is not None
    assert result["finding_id"] == compute_finding_id(0)
    assert result["entity_type"] == "EMAIL_ADDRESS"
    assert result["file"] == "app.py"
    assert result["line_number"] == 10
    assert "root_cause" in result
    assert "explanation" in result
    assert "recommendation" in result
    assert "best_practice" in result
    assert result["confidence"] == 1.0


def test_explain_returns_none_for_unknown_id() -> None:
    service = ExplainService(_sample_report())

    assert service.explain("F-999999") is None
    assert service.explain("not-an-id") is None


def test_from_report_path_loads_report_from_disk(tmp_path: Path) -> None:
    report_path = tmp_path / "latest.json"
    report_path.write_text(json.dumps(_sample_report()), encoding="utf-8")

    service = ExplainService.from_report_path(report_path)
    result = service.explain(compute_finding_id(0))

    assert result is not None
    assert result["entity_type"] == "EMAIL_ADDRESS"


def test_from_report_path_missing_file_raises_explain_service_error(tmp_path: Path) -> None:
    with pytest.raises(ExplainServiceError):
        ExplainService.from_report_path(tmp_path / "does-not-exist.json")


def test_from_report_path_invalid_json_raises_explain_service_error(tmp_path: Path) -> None:
    report_path = tmp_path / "latest.json"
    report_path.write_text("{ not valid json", encoding="utf-8")

    with pytest.raises(ExplainServiceError):
        ExplainService.from_report_path(report_path)


@pytest.mark.parametrize("payload", ["[]", '"text"'])
def test_from_report_path_non_object_json_raises_explain_service_error(
    tmp_path: Path, payload: str
) -> None:
    report_path = tmp_path / "latest.json"
    report_path.write_text(payload, encoding="utf-8")

    with pytest.raises(ExplainServiceError):
        ExplainService.from_report_path(report_path)


def test_from_report_path_non_list_findings_raises_explain_service_error(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "latest.json"
    report_path.write_text(json.dumps({"findings": "abc"}), encoding="utf-8")

    with pytest.raises(ExplainServiceError):
        ExplainService.from_report_path(report_path)


def test_explain_never_touches_scanner_internals() -> None:
    """ExplainService only reads report data; no scanner/Presidio import needed."""
    import scanner.intelligence.api as api_module

    assert "pii_detector" not in dir(api_module)
    assert "ScanEngine" not in dir(api_module)
