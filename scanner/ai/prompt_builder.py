"""
prompt_builder.py
===================

Task 2, Phase 2: the single location where prompts sent to an AI
provider are constructed.

Per the project's AI architecture rules, the prompt built here asks
the model only to *explain* a report that has already been fully
computed by `PIIDetector` (detection) and `RiskEngine` (scoring) — it
is explicitly instructed not to invent findings, change severities, or
recompute the risk score/pipeline status. The AI's response is used
only for narrative prose (see `markdown_generator.py`); every fact in
the final Markdown summary is still taken directly from the JSON
report, never from the model's output.

Keeping prompt construction in exactly one module (rather than
scattering prompt text throughout the project) makes it possible to
review, and change, the model's instructions in one place.
"""

from __future__ import annotations

import json
from typing import Any

# Cap on how many individual findings are included verbatim in the
# prompt. Large repositories can produce thousands of findings; the
# report's own `summary` block already carries the aggregate counts,
# so only a representative sample is needed for narrative context.
_MAX_FINDINGS_IN_PROMPT = 25

_SYSTEM_INSTRUCTIONS = """\
You are a security assistant that explains an already-completed PII \
(personally identifiable information) scan report to both developers \
and engineering managers.

Strict rules you must follow:
- The findings, severities, risk score, and pipeline status below are \
final and were computed deterministically before you were called. Do \
not invent new findings, change any severity, or change the risk \
score or pipeline status.
- Only discuss entity types and counts that appear in the data below.
- Do not claim compliance with any regulation (e.g. GDPR, HIPAA, PCI \
DSS) and do not provide legal advice — general security/privacy \
guidance only.
- Write in clear, concise prose suitable for a short executive summary \
paragraph (roughly 3-6 sentences). Do not repeat the raw JSON back, \
do not add Markdown headings, and do not list recommendations or \
prioritized actions yourself — another part of the system handles \
those sections.
"""


def _summarize_findings_sample(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a small, JSON-safe sample of findings for prompt context."""
    sample = findings[:_MAX_FINDINGS_IN_PROMPT]
    return [
        {
            "entity_type": finding.get("entity_type"),
            "severity": finding.get("severity"),
            "file": finding.get("file"),
        }
        for finding in sample
    ]


class PromptBuilder:
    """Builds the prompt text sent to an `AIProvider` for a given report."""

    @staticmethod
    def build(report: dict[str, Any]) -> str:
        """
        Construct the full prompt for `report`.

        Args:
            report: A Task 2 Phase 1 JSON report dict (see
                `scanner.report_generator.ReportGenerator.build_report`).

        Returns:
            The prompt string to pass to `AIProvider.generate()`.
        """
        summary = report.get("summary", {})
        repository = report.get("repository", {})
        findings = report.get("findings", [])

        context = {
            "repository_identifier": repository.get("identifier"),
            "total_findings": summary.get("total_findings"),
            "severity_counts": summary.get("severity_counts"),
            "risk_score": summary.get("risk_score"),
            "pipeline_status": summary.get("pipeline_status"),
            "risk_thresholds": summary.get("risk_thresholds"),
            "findings_sample": _summarize_findings_sample(findings),
            "findings_sample_is_truncated": len(findings) > _MAX_FINDINGS_IN_PROMPT,
        }

        context_json = json.dumps(context, indent=2, sort_keys=False)

        return (
            f"{_SYSTEM_INSTRUCTIONS}\n"
            f"Scan report data:\n{context_json}\n\n"
            "Write the executive summary paragraph now."
        )
