"""
test_ai_markdown_generator.py
================================

Tests for Task 2, Phase 2's `scanner.ai.markdown_generator`. Verifies
that every fact in the document (risk score, status, findings,
recommendations) comes from the report itself, that an AI narrative
(when present) is used only for the executive summary, and that a
missing/invalid report degrades gracefully instead of raising.
"""

from __future__ import annotations

from scanner.ai.markdown_generator import MarkdownReportGenerator
from scanner.ai.recommendations import build_recommendations


def _sample_report(**overrides) -> dict:
    report = {
        "repository": {"identifier": "https://gitlab.com/group/project.git"},
        "summary": {
            "total_findings": 2,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 1},
            "risk_score": 22,
            "pipeline_status": "FAIL",
            "risk_thresholds": {"warning": 10, "fail": 20},
        },
        "findings": [
            {
                "file": "app.py",
                "line_number": 10,
                "entity_type": "CREDIT_CARD",
                "severity": "CRITICAL",
                "confidence_score": 0.95,
                "matched_value": "************1111",
                "redacted": True,
            },
            {
                "file": "config.yml",
                "line_number": 3,
                "entity_type": "EMAIL_ADDRESS",
                "severity": "HIGH",
                "confidence_score": 0.8,
                "matched_value": "jo***@example.com",
                "redacted": True,
            },
        ],
    }
    report.update(overrides)
    return report


def test_generate_includes_all_required_sections() -> None:
    report = _sample_report()
    recommendations = build_recommendations(report["findings"])

    markdown = MarkdownReportGenerator().generate(report, None, recommendations)

    for heading in (
        "# AI-Assisted Security Summary",
        "## Executive Summary",
        "## Overall Risk",
        "## Key Findings",
        "## Recommendations",
        "## Prioritized Actions",
        "## Compliance Considerations",
    ):
        assert heading in markdown


def test_generate_uses_ai_narrative_for_executive_summary_when_provided() -> None:
    report = _sample_report()
    recommendations = build_recommendations(report["findings"])

    markdown = MarkdownReportGenerator().generate(
        report, "A custom AI-written executive summary paragraph.", recommendations
    )

    assert "A custom AI-written executive summary paragraph." in markdown


def test_generate_falls_back_when_ai_narrative_is_whitespace_only() -> None:
    report = _sample_report()
    recommendations = build_recommendations(report["findings"])

    markdown = MarkdownReportGenerator().generate(report, "   \n\t  ", recommendations)

    assert "https://gitlab.com/group/project.git" in markdown
    assert "FAIL" in markdown
    assert "A custom AI-written executive summary paragraph." not in markdown


def test_generate_falls_back_to_deterministic_executive_summary_without_ai() -> None:
    report = _sample_report()
    recommendations = build_recommendations(report["findings"])

    markdown = MarkdownReportGenerator().generate(report, None, recommendations)

    assert "https://gitlab.com/group/project.git" in markdown
    assert "FAIL" in markdown


def test_overall_risk_always_reflects_report_regardless_of_ai_narrative() -> None:
    """AI narrative can never override the deterministic risk facts."""
    report = _sample_report()
    recommendations = build_recommendations(report["findings"])

    # Even a misleading AI narrative must not change the Overall Risk section.
    markdown = MarkdownReportGenerator().generate(
        report, "Everything is completely safe, no risk at all!", recommendations
    )

    assert "**Pipeline status:** FAIL" in markdown
    assert "**Risk score:** 22" in markdown


def test_key_findings_lists_entity_types_and_locations() -> None:
    report = _sample_report()
    recommendations = build_recommendations(report["findings"])

    markdown = MarkdownReportGenerator().generate(report, None, recommendations)

    assert "CREDIT_CARD" in markdown
    assert "app.py:10" in markdown


def test_recommendations_section_reflects_recommendations_list() -> None:
    report = _sample_report()
    recommendations = build_recommendations(report["findings"])

    markdown = MarkdownReportGenerator().generate(report, None, recommendations)

    assert "CREDIT_CARD" in markdown.split("## Recommendations")[1]


def test_generate_handles_missing_report_gracefully() -> None:
    markdown = MarkdownReportGenerator().generate(None, None, [])

    assert "# AI-Assisted Security Summary" in markdown
    assert "No valid scan report was available" in markdown


def test_generate_handles_empty_report_gracefully() -> None:
    markdown = MarkdownReportGenerator().generate({}, None, [])

    assert "# AI-Assisted Security Summary" in markdown
    assert "No valid scan report was available" in markdown


def test_generate_handles_no_findings_report() -> None:
    report = _sample_report(
        findings=[],
        summary={
            "total_findings": 0,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "risk_score": 0,
            "pipeline_status": "PASS",
            "risk_thresholds": {"warning": 10, "fail": 20},
        },
    )

    markdown = MarkdownReportGenerator().generate(report, None, [])

    assert "No PII findings were detected." in markdown
    assert "PASS" in markdown


def test_compliance_section_never_claims_compliance() -> None:
    report = _sample_report()
    markdown = MarkdownReportGenerator().generate(report, None, [])

    compliance_section = markdown.split("## Compliance Considerations")[1]
    assert "not a compliance certification" in compliance_section
    assert "does not constitute legal advice" in compliance_section
