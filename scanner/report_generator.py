"""
report_generator.py
=====================

Task 2, Phase 1: converts a completed `ScanSummary` + `RiskAssessment`
into a structured, versioned JSON report.

This module performs no scanning and no risk calculation of its own —
it is a pure serialization layer that sits after `ScanEngine`
(detection) and `RiskEngine` (deterministic scoring):

    RepositoryManager -> ScanEngine -> RiskEngine -> ReportGenerator

The JSON produced here is the stable contract future phases (the AI
assistant in Task 2 Phase 2, the Azure DevOps pipeline in Task 2
Phase 3) depend on — they read this report rather than reaching into
scanner internals directly.

Redaction
---------
By default (`report_redaction_enabled=True`), every finding's matched
value is masked before being written to disk, since this report is
meant to be stored and potentially published as a pipeline artifact
that other people (or CI systems) can access. Redaction never affects
detection, severity, or risk scoring — it only changes what ends up
in the `matched_value` field of the persisted report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.config import ScannerSettings
from scanner.logger import get_logger
from scanner.models import RiskAssessment, ScanSummary
from scanner.utils import ensure_directory, format_timestamp_for_filename, utc_now

logger = get_logger(__name__)

# Bumped whenever the report's *structure* changes in a way that could
# break a downstream consumer (the AI assistant, the Azure DevOps
# pipeline). Additive, backward-compatible changes don't require a bump.
SCHEMA_VERSION = "1.0"

# Reported as `scanner_version` inside the report. Bumped alongside
# meaningful changes to detection or reporting behaviour.
SCANNER_VERSION = "0.4.0"

# Number of trailing characters preserved when redacting a matched
# value (e.g. a credit card number keeps only its last 4 digits).
_REDACTION_VISIBLE_SUFFIX_LENGTH = 4


def redact_value(entity_type: str, value: str) -> str:
    """
    Mask a matched PII value for safe storage/publication.

    Args:
        entity_type: The Presidio entity type (e.g. "EMAIL_ADDRESS").
        value: The raw matched text.

    Returns:
        A masked version of `value`:
            - Email addresses keep the first two characters of the
              local part, e.g. "john.doe@example.com" -> "jo***@example.com".
            - Every other entity type keeps only the last few
              characters, replacing everything else with "*", e.g.
              "4111111111111111" -> "************1111".
        An empty string is returned unchanged.
    """
    if not value:
        return value

    if entity_type == "EMAIL_ADDRESS" and "@" in value:
        local_part, _, domain = value.partition("@")
        visible = local_part[:2]
        return f"{visible}***@{domain}"

    keep = _REDACTION_VISIBLE_SUFFIX_LENGTH
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]


class ReportGenerator:
    """
    Builds and writes the structured JSON report for a completed scan.
    """

    def __init__(self, settings: ScannerSettings) -> None:
        """
        Args:
            settings: Application settings, providing
                `report_redaction_enabled` and `report_output_directory`.
        """
        self._settings = settings

    def build_report(
        self, summary: ScanSummary, risk_assessment: RiskAssessment
    ) -> dict[str, Any]:
        """
        Assemble the structured report dict for a completed scan.

        Args:
            summary: The completed `ScanSummary` from `ScanEngine.scan()`.
            risk_assessment: The deterministic `RiskAssessment` from
                `RiskEngine.assess()`.

        Returns:
            A JSON-serializable dict following the versioned report
            schema (see module docstring / README for the field list).
        """
        redact = self._settings.report_redaction_enabled

        findings: list[dict[str, Any]] = []
        for finding in summary.findings:
            matched_value = finding.matched_text
            if redact:
                matched_value = redact_value(finding.entity_type, matched_value)
            findings.append(
                {
                    "file": str(finding.file.relative_path),
                    "line_number": finding.line_number,
                    "entity_type": finding.entity_type,
                    "confidence_score": round(finding.confidence_score, 4),
                    "severity": finding.severity.value,
                    "matched_value": matched_value,
                    "redacted": redact,
                }
            )

        severity_counts = {
            severity.value: count
            for severity, count in risk_assessment.severity_counts.items()
        }

        return {
            "schema_version": SCHEMA_VERSION,
            "scanner_version": SCANNER_VERSION,
            "repository": {
                "identifier": summary.source.identifier,
                "source_type": summary.source.source_type.value,
                "local_path": str(summary.source.local_path),
            },
            "scan": {
                "started_at": summary.started_at.isoformat(),
                "finished_at": (
                    summary.finished_at.isoformat() if summary.finished_at else None
                ),
                "duration_seconds": summary.duration_seconds,
                "files_scanned": summary.files_scanned,
                "files_skipped": summary.files_skipped,
            },
            "summary": {
                "total_findings": summary.total_findings,
                "severity_counts": severity_counts,
                "risk_score": risk_assessment.risk_score,
                "pipeline_status": risk_assessment.status.value,
                "risk_thresholds": {
                    "warning": risk_assessment.warning_threshold,
                    "fail": risk_assessment.fail_threshold,
                },
            },
            "findings": findings,
        }

    def write_json_report(self, report: dict[str, Any]) -> Path:
        """
        Write `report` to a timestamped JSON file, plus a `latest.json` copy.

        Args:
            report: A report dict, as produced by `build_report()`.

        Returns:
            Path to the timestamped report file that was written.
        """
        reports_dir = ensure_directory(self._settings.report_output_directory)

        timestamp = format_timestamp_for_filename(utc_now())
        report_path = reports_dir / f"report_{timestamp}.json"
        latest_path = reports_dir / "latest.json"

        payload = json.dumps(report, indent=2, sort_keys=False)
        report_path.write_text(payload, encoding="utf-8")
        latest_path.write_text(payload, encoding="utf-8")

        logger.info("Report written to %s (and latest.json)", report_path)
        return report_path

    def generate(
        self, summary: ScanSummary, risk_assessment: RiskAssessment
    ) -> tuple[dict[str, Any], Path]:
        """
        Build and write the report in one step.

        Args:
            summary: The completed `ScanSummary` from `ScanEngine.scan()`.
            risk_assessment: The deterministic `RiskAssessment` from
                `RiskEngine.assess()`.

        Returns:
            A `(report, report_path)` tuple.
        """
        report = self.build_report(summary, risk_assessment)
        report_path = self.write_json_report(report)
        return report, report_path
