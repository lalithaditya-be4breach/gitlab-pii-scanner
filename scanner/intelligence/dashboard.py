"""
dashboard.py
============

Task 2, Phase 4: Executive Dashboard JSON.

Renders `dashboard.json`, a backend-only data file intended for a
future frontend dashboard. This module builds no UI -- it only
aggregates data that already exists in the Task 2 Phase 1 JSON report
(plus the Phase 4 category taxonomy and trend comparison) into a
single, stable JSON shape.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from scanner.config import ScannerSettings
from scanner.intelligence.categories import build_category_counts
from scanner.intelligence.finding_ids import attach_finding_ids
from scanner.logger import get_logger
from scanner.utils import ensure_directory, utc_now

logger = get_logger(__name__)

_DASHBOARD_FILENAME = "dashboard.json"

#: Number of files / findings surfaced in the "top" lists. Kept small
#: and fixed so the dashboard payload stays a reasonable size even for
#: a repository with thousands of findings.
_TOP_FILES_LIMIT = 10
_TOP_FINDINGS_LIMIT = 25

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _severity_sort_key(finding: dict[str, Any]) -> int:
    severity = finding.get("severity", "LOW")
    return _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else len(
        _SEVERITY_ORDER
    )


def _build_top_files(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(finding.get("file", "unknown") for finding in findings)
    top = counts.most_common(_TOP_FILES_LIMIT)
    return [{"file": file, "finding_count": count} for file, count in top]


def _build_top_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(findings, key=_severity_sort_key)
    top = ordered[:_TOP_FINDINGS_LIMIT]
    return [
        {
            "finding_id": finding.get("finding_id"),
            "file": finding.get("file"),
            "line_number": finding.get("line_number"),
            "entity_type": finding.get("entity_type"),
            "severity": finding.get("severity"),
        }
        for finding in top
    ]


class DashboardBuilder:
    """Builds and writes `dashboard.json`."""

    def __init__(self, settings: ScannerSettings) -> None:
        """
        Args:
            settings: Application settings. Only
                `settings.output_directory` is used, to locate the
                `intelligence/` subdirectory `dashboard.json` is
                written to.
        """
        self._settings = settings

    @property
    def _intelligence_directory(self) -> Path:
        return self._settings.working_directory / "reports" / "latest"

    @property
    def dashboard_path(self) -> Path:
        """Path `dashboard.json` is (or will be) written to."""
        return self._intelligence_directory / _DASHBOARD_FILENAME

    def build(
        self, report: dict[str, Any] | None, trend: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Assemble the dashboard JSON dict.

        Args:
            report: A Task 2 Phase 1 JSON report dict, or `None`/`{}`
                if no valid report is available.
            trend: Output of `scanner.intelligence.trend.TrendAnalyzer.analyze`.

        Returns:
            A JSON-serializable dict with `generated_at`, `summary`,
            `category_counts`, `trend`, `top_files`, `top_findings`,
            and `severity_distribution`.
        """
        report = report or {}
        summary = report.get("summary", {}) or {}
        findings = report.get("findings", []) or []

        # Findings are enriched with a positional finding_id here (not
        # persisted back to the report) purely so `top_findings`
        # entries can be looked up later via `/api/explain`.
        enriched_findings = attach_finding_ids(findings)

        return {
            "generated_at": utc_now().isoformat(),
            "summary": {
                "total_findings": summary.get("total_findings", 0),
                "risk_score": summary.get("risk_score", 0),
                "pipeline_status": summary.get("pipeline_status", "UNKNOWN"),
            },
            "category_counts": build_category_counts(findings),
            "trend": trend,
            "top_files": _build_top_files(findings),
            "top_findings": _build_top_findings(enriched_findings),
            "severity_distribution": summary.get("severity_counts", {}) or {},
        }

    def write(self, dashboard: dict[str, Any]) -> Path:
        """
        Write `dashboard` to `dashboard.json`.

        Args:
            dashboard: A dashboard dict, as produced by `build()`.

        Returns:
            The path `dashboard.json` was written to.
        """
        ensure_directory(self._intelligence_directory)
        path = self.dashboard_path
        path.write_text(json.dumps(dashboard, indent=2), encoding="utf-8")
        logger.info("Dashboard JSON written to %s", path)
        return path

    def generate(
        self, report: dict[str, Any] | None, trend: dict[str, Any]
    ) -> tuple[dict[str, Any], Path]:
        """
        Build and write `dashboard.json` in one step.

        Args:
            report: A Task 2 Phase 1 JSON report dict.
            trend: Output of `TrendAnalyzer.analyze`.

        Returns:
            A `(dashboard, dashboard_path)` tuple.
        """
        dashboard = self.build(report, trend)
        path = self.write(dashboard)
        return dashboard, path
