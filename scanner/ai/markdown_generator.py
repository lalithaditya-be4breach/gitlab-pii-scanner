"""
markdown_generator.py
=======================

Task 2, Phase 2: turns a Task 2 Phase 1 JSON report into the final
Markdown summary written to disk (e.g. `output/ai-summary.md`).

Only the Executive Summary's narrative prose may come from an AI
provider. Every other fact in the document — overall risk, severity
breakdown, key findings, recommendations, and prioritized actions — is
computed directly from the JSON report by this module, so the summary
is guaranteed to stay consistent with `RiskEngine`'s output even if:
    - AI is disabled or unavailable, or
    - the AI provider's narrative text is missing/unusable.

This keeps the "AI explains, it never decides" rule enforceable at the
document level, not just at the orchestration level.
"""

from __future__ import annotations

from typing import Any

# How many individual findings are listed under "Key Findings" before
# the section switches to "... and N more, see the JSON report".
_MAX_KEY_FINDINGS_LISTED = 15

_DETERMINISTIC_EXECUTIVE_SUMMARY_TEMPLATE = (
    "This report covers a PII scan of {repository_identifier}. The scan "
    "found {total_findings} finding(s) across the repository, producing "
    "a deterministic risk score of {risk_score} and a pipeline status of "
    "**{pipeline_status}** (warning at {warning_threshold}, fail at "
    "{fail_threshold}). {severity_sentence}"
)

_NO_REPORT_EXECUTIVE_SUMMARY = (
    "No valid scan report was available to summarize. This may mean the "
    "scan has not completed yet, or the report data provided to the AI "
    "assistant was missing or malformed. No findings, risk score, or "
    "pipeline status can be reported below."
)

_COMPLIANCE_NOTE = (
    "This summary provides general security and privacy guidance only. "
    "It is not a compliance certification and does not constitute legal "
    "advice. Findings related to regulated data categories (e.g. "
    "payment card data, health information, government identifiers) "
    "should be reviewed against your organization's applicable "
    "regulatory and contractual obligations by qualified personnel."
)

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _severity_sentence(severity_counts: dict[str, int]) -> str:
    parts = [
        f"{count} {severity.title()}"
        for severity in _SEVERITY_ORDER
        for count in [severity_counts.get(severity, 0)]
        if count
    ]
    if not parts:
        return "No findings were detected at any severity level."
    return "Severity breakdown: " + ", ".join(parts) + "."


def _deterministic_executive_summary(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    repository = report.get("repository", {})
    thresholds = summary.get("risk_thresholds", {}) or {}

    return _DETERMINISTIC_EXECUTIVE_SUMMARY_TEMPLATE.format(
        repository_identifier=repository.get("identifier", "the scanned repository"),
        total_findings=summary.get("total_findings", 0),
        risk_score=summary.get("risk_score", 0),
        pipeline_status=summary.get("pipeline_status", "UNKNOWN"),
        warning_threshold=thresholds.get("warning", "n/a"),
        fail_threshold=thresholds.get("fail", "n/a"),
        severity_sentence=_severity_sentence(summary.get("severity_counts", {}) or {}),
    )


def _render_overall_risk(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    thresholds = summary.get("risk_thresholds", {}) or {}
    severity_counts = summary.get("severity_counts", {}) or {}

    lines = [
        f"- **Pipeline status:** {summary.get('pipeline_status', 'UNKNOWN')}",
        f"- **Risk score:** {summary.get('risk_score', 0)} "
        f"(warning >= {thresholds.get('warning', 'n/a')}, "
        f"fail >= {thresholds.get('fail', 'n/a')})",
        f"- **Total findings:** {summary.get('total_findings', 0)}",
    ]
    for severity in _SEVERITY_ORDER:
        count = severity_counts.get(severity, 0)
        if count:
            lines.append(f"  - {severity.title()}: {count}")
    return "\n".join(lines)


def _render_key_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "No PII findings were detected."

    def _sort_key(finding: dict[str, Any]) -> int:
        severity = finding.get("severity", "LOW")
        return _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else len(
            _SEVERITY_ORDER
        )

    ordered = sorted(findings, key=_sort_key)
    lines = []
    for finding in ordered[:_MAX_KEY_FINDINGS_LISTED]:
        location = finding.get("file", "unknown file")
        line_number = finding.get("line_number")
        if line_number is not None:
            location = f"{location}:{line_number}"
        lines.append(
            f"- **[{finding.get('severity', 'UNKNOWN')}]** "
            f"{finding.get('entity_type', 'UNKNOWN')} in {location}"
        )

    remaining = len(ordered) - _MAX_KEY_FINDINGS_LISTED
    if remaining > 0:
        lines.append(f"- ...and {remaining} more finding(s); see the full JSON report.")
    return "\n".join(lines)


def _render_recommendations(recommendations: list[dict[str, str]]) -> str:
    if not recommendations:
        return "No specific recommendations — no PII findings were detected."
    return "\n".join(
        f"- **{item['entity_type']}** ({item['severity']}): {item['recommendation']}"
        for item in recommendations
    )


def _render_prioritized_actions(recommendations: list[dict[str, str]]) -> str:
    if not recommendations:
        return "No prioritized actions — no PII findings were detected."

    lines = []
    for index, item in enumerate(recommendations, start=1):
        lines.append(
            f"{index}. Address **{item['entity_type']}** findings first "
            f"(severity: {item['severity']}) — {item['recommendation']}"
        )
    lines.append(
        "\nHigher-severity findings are listed first because they "
        "represent the greatest exposure (e.g. financial or government "
        "identifiers) and are weighted most heavily by the deterministic "
        "risk engine; addressing them first has the largest impact on "
        "the overall risk score."
    )
    return "\n".join(lines)


class MarkdownReportGenerator:
    """Builds the final Markdown AI summary document."""

    def generate(
        self,
        report: dict[str, Any] | None,
        ai_narrative: str | None,
        recommendations: list[dict[str, str]],
    ) -> str:
        """
        Compose the full Markdown summary.

        Args:
            report: A Task 2 Phase 1 JSON report dict, or `None`/`{}`
                if no valid report was available (e.g. missing or
                invalid JSON was supplied to the AI assistant).
            ai_narrative: The AI provider's executive-summary prose, or
                `None` if AI is disabled/unavailable/failed — in which
                case a deterministic executive summary is used instead.
            recommendations: Output of
                `scanner.ai.recommendations.build_recommendations`.

        Returns:
            The complete Markdown document as a string.
        """
        report = report or {}
        has_report = bool(report.get("summary"))

        if has_report:
            if ai_narrative and ai_narrative.strip():
                executive_summary = ai_narrative.strip()
            else:
                executive_summary = _deterministic_executive_summary(report)
            overall_risk = _render_overall_risk(report)
            key_findings = _render_key_findings(report.get("findings", []))
            recommendations_section = _render_recommendations(recommendations)
            prioritized_actions = _render_prioritized_actions(recommendations)
        else:
            executive_summary = _NO_REPORT_EXECUTIVE_SUMMARY
            overall_risk = "Not available (no scan report)."
            key_findings = "Not available (no scan report)."
            recommendations_section = "Not available (no scan report)."
            prioritized_actions = "Not available (no scan report)."

        sections = [
            "# AI-Assisted Security Summary",
            "",
            "## Executive Summary",
            "",
            executive_summary,
            "",
            "## Overall Risk",
            "",
            overall_risk,
            "",
            "## Key Findings",
            "",
            key_findings,
            "",
            "## Recommendations",
            "",
            recommendations_section,
            "",
            "## Prioritized Actions",
            "",
            prioritized_actions,
            "",
            "## Compliance Considerations",
            "",
            _COMPLIANCE_NOTE,
            "",
        ]
        return "\n".join(sections)
