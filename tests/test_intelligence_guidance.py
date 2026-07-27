"""
test_intelligence_guidance.py
===============================

Tests for Task 2, Phase 4's `DeveloperGuidanceReportBuilder`: the
Markdown `developer-guidance.md` document, distinct from Phase 2's
`ai-summary.md`.
"""

from __future__ import annotations

from scanner.intelligence.guidance import DeveloperGuidanceReportBuilder


def _sample_report() -> dict:
    return {
        "repository": {"identifier": "https://gitlab.com/group/project.git"},
        "summary": {
            "total_findings": 2,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 1},
            "risk_score": 15,
            "pipeline_status": "WARNING",
            "risk_thresholds": {"warning": 10, "fail": 50},
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
            },
            {
                "file": "config.py",
                "line_number": 3,
                "entity_type": "CREDIT_CARD",
                "confidence_score": 1.0,
                "severity": "CRITICAL",
                "matched_value": "************1111",
                "redacted": True,
            },
        ],
    }


def test_generate_missing_report_produces_graceful_placeholder() -> None:
    markdown = DeveloperGuidanceReportBuilder().generate(None)

    assert "# Developer Guidance Report" in markdown
    assert "No valid scan report was available" in markdown


def test_generate_includes_all_required_sections() -> None:
    markdown = DeveloperGuidanceReportBuilder().generate(_sample_report())

    for heading in (
        "# Developer Guidance Report",
        "## Executive Summary",
        "## Risk Score & Overall Severity",
        "## Detected Issues, Root Cause & Recommended Fix",
        "## Secure Coding Recommendations (by category)",
    ):
        assert heading in markdown


def test_generate_includes_risk_score_and_status_verbatim_from_report() -> None:
    markdown = DeveloperGuidanceReportBuilder().generate(_sample_report())

    assert "**Risk score:** 15" in markdown
    assert "**Pipeline status:** WARNING" in markdown


def test_generate_includes_root_cause_and_fix_per_finding() -> None:
    markdown = DeveloperGuidanceReportBuilder().generate(_sample_report())

    assert "EMAIL_ADDRESS" in markdown
    assert "CREDIT_CARD" in markdown
    assert "Root cause" in markdown
    assert "Recommended fix" in markdown
    assert "CWE" in markdown
    assert "OWASP" in markdown


def test_generate_uses_organization_specific_guidance() -> None:
    report = _sample_report()
    report["summary"]["total_findings"] = 1
    report["summary"]["severity_counts"] = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 0,
        "CRITICAL": 0,
    }
    report["findings"] = [
        {
            "file": "docs.md",
            "line_number": 5,
            "entity_type": "ORGANIZATION",
            "confidence_score": 0.92,
            "severity": "MEDIUM",
            "matched_value": "ExampleCorp",
            "redacted": True,
        }
    ]

    markdown = DeveloperGuidanceReportBuilder().generate(report)

    assert "ORGANIZATION" in markdown
    assert "Business Information" in markdown
    assert "customer datasets" in markdown
    assert "CWE-200" in markdown


def test_generate_orders_findings_highest_severity_first() -> None:
    markdown = DeveloperGuidanceReportBuilder().generate(_sample_report())

    critical_index = markdown.index("CREDIT_CARD")
    high_index = markdown.index("EMAIL_ADDRESS")
    assert critical_index < high_index


def test_generate_empty_findings_reports_no_findings() -> None:
    report = _sample_report()
    report["summary"]["total_findings"] = 0
    report["findings"] = []

    markdown = DeveloperGuidanceReportBuilder().generate(report)

    assert "No PII findings were detected." in markdown
