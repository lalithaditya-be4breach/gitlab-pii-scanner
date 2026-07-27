"""
guidance.py
===========

Task 2, Phase 4: Developer Guidance Report.

Renders `developer-guidance.md` -- a report distinct from Phase 2's
`ai-summary.md` (`scanner.ai.markdown_generator`). Where `ai-summary.md`
is an executive-facing risk summary, `developer-guidance.md` is aimed
at the developer who has to fix the findings: for each detected issue
it surfaces the root cause, the recommended fix, and the relevant
secure-coding best practice / references, on top of the same
Executive Summary / Risk Score / Overall Severity facts.

Every fact in this document is computed directly from the JSON report,
`RootCauseEngine`, and `RemediationEngine` -- nothing here is AI
narrative text (this module never calls an AI provider).
"""

from __future__ import annotations

from typing import Any

from scanner.intelligence.finding_ids import attach_finding_ids
from scanner.intelligence.remediation import RemediationEngine
from scanner.intelligence.root_cause import RootCauseEngine

# How many individual findings get a full root-cause + remediation
# write-up before the report falls back to "...and N more, see
# dashboard.json / the JSON report".
_MAX_DETAILED_FINDINGS = 20

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _severity_sort_key(finding: dict[str, Any]) -> int:
    severity = finding.get("severity", "LOW")
    return _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else len(
        _SEVERITY_ORDER
    )


def _render_executive_summary(report: dict[str, Any]) -> str:
    summary = report.get("summary", {}) or {}
    repository = report.get("repository", {}) or {}
    return (
        f"This developer guidance report accompanies the PII scan of "
        f"{repository.get('identifier', 'the scanned repository')}. It "
        f"explains, for each detected issue, why it was flagged and how "
        f"to fix it -- the risk score and pipeline status themselves are "
        f"decided exclusively by the deterministic risk engine and are "
        f"reproduced here for reference only."
    )


def _render_risk_score_and_severity(report: dict[str, Any]) -> str:
    summary = report.get("summary", {}) or {}
    thresholds = summary.get("risk_thresholds", {}) or {}
    severity_counts = summary.get("severity_counts", {}) or {}

    lines = [
        f"- **Risk score:** {summary.get('risk_score', 0)} "
        f"(warning >= {thresholds.get('warning', 'n/a')}, "
        f"fail >= {thresholds.get('fail', 'n/a')})",
        f"- **Pipeline status:** {summary.get('pipeline_status', 'UNKNOWN')}",
        f"- **Total findings:** {summary.get('total_findings', 0)}",
        "- **Overall severity breakdown:**",
    ]
    any_severity = False
    for severity in _SEVERITY_ORDER:
        count = severity_counts.get(severity, 0)
        if count:
            any_severity = True
            lines.append(f"  - {severity.title()}: {count}")
    if not any_severity:
        lines.append("  - No findings were detected at any severity level.")
    return "\n".join(lines)


def _render_detected_issue(root_cause: dict[str, Any], remediation: dict[str, Any]) -> str:
    location = root_cause.get("file", "unknown file")
    line_number = root_cause.get("line_number")
    if line_number is not None:
        location = f"{location}:{line_number}"

    references = ", ".join(remediation.get("references", [])) or "n/a"

    return "\n".join(
        [
            f"### {root_cause.get('finding_id', 'F-??????')} - "
            f"{root_cause.get('entity_type', 'UNKNOWN')} "
            f"[{root_cause.get('severity', 'UNKNOWN')}]",
            "",
            f"- **Location:** {location}",
            f"- **Category:** {root_cause.get('category', 'Other')}",
            f"- **Detection confidence:** {root_cause.get('confidence', 'n/a')}",
            f"- **Root cause:** {root_cause.get('root_cause', '')}",
            f"- **Likely developer mistake:** "
            f"{root_cause.get('likely_developer_mistake', '')}",
            f"- **Security impact:** {root_cause.get('security_impact', '')}",
            f"- **Recommended fix:** {remediation.get('recommendation', '')}",
            f"- **Security best practice:** {remediation.get('best_practice', '')}",
            f"- **OWASP:** {remediation.get('owasp', '')}",
            f"- **CWE:** {remediation.get('cwe', '')}",
            f"- **References:** {references}",
        ]
    )


class DeveloperGuidanceReportBuilder:
    """Builds the Markdown `developer-guidance.md` document."""

    def __init__(
        self,
        root_cause_engine: RootCauseEngine | None = None,
        remediation_engine: RemediationEngine | None = None,
    ) -> None:
        """
        Args:
            root_cause_engine: Optional explicit `RootCauseEngine`
                (defaults to a new instance). Injectable for tests.
            remediation_engine: Optional explicit `RemediationEngine`
                (defaults to a new instance). Injectable for tests.
        """
        self._root_cause_engine = root_cause_engine or RootCauseEngine()
        self._remediation_engine = remediation_engine or RemediationEngine()

    def generate(self, report: dict[str, Any] | None) -> str:
        """
        Compose the full `developer-guidance.md` Markdown document.

        Args:
            report: A Task 2 Phase 1 JSON report dict, or `None`/`{}`
                if no valid report is available.

        Returns:
            The complete Markdown document as a string. Never raises.
        """
        report = report or {}
        has_report = bool(report.get("summary"))

        if not has_report:
            body = (
                "No valid scan report was available. No detected issues, "
                "root causes, or recommendations can be reported below."
            )
            sections = [
                "# Developer Guidance Report",
                "",
                "## Executive Summary",
                "",
                body,
                "",
            ]
            return "\n".join(sections)

        findings = attach_finding_ids(report.get("findings", []) or [])
        ordered_findings = sorted(findings, key=_severity_sort_key)

        detailed = ordered_findings[:_MAX_DETAILED_FINDINGS]
        remaining_count = len(ordered_findings) - len(detailed)

        detected_issue_sections = []
        for finding in detailed:
            root_cause = self._root_cause_engine.analyze_finding(finding)
            remediation = self._remediation_engine.remediation_for_finding(finding)
            detected_issue_sections.append(_render_detected_issue(root_cause, remediation))

        if not detected_issue_sections:
            detected_issues_body = "No PII findings were detected."
        else:
            detected_issues_body = "\n\n".join(detected_issue_sections)
            if remaining_count > 0:
                detected_issues_body += (
                    f"\n\n...and {remaining_count} more finding(s). See "
                    "`dashboard.json` for category-level aggregates or the "
                    "full JSON report for every finding."
                )

        secure_coding = self._remediation_engine.build_secure_coding_recommendations(
            report.get("findings", []) or []
        )
        if secure_coding:
            secure_coding_body = "\n".join(
                f"- **{item['entity_type']}** ({item['severity']}): "
                f"{item['owasp']} / {item['cwe']} -- {item['best_practice']}"
                for item in secure_coding
            )
        else:
            secure_coding_body = "No secure coding recommendations -- no findings were detected."

        sections = [
            "# Developer Guidance Report",
            "",
            "## Executive Summary",
            "",
            _render_executive_summary(report),
            "",
            "## Risk Score & Overall Severity",
            "",
            _render_risk_score_and_severity(report),
            "",
            "## Detected Issues, Root Cause & Recommended Fix",
            "",
            detected_issues_body,
            "",
            "## Secure Coding Recommendations (by category)",
            "",
            secure_coding_body,
            "",
        ]
        return "\n".join(sections)
