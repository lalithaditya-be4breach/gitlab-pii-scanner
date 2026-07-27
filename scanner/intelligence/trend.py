"""
trend.py
========

Task 2, Phase 4: AI Risk Trend Summary.

Compares the current scan's JSON report against the previous scan's
JSON report (automatically stored by this module after each analysis)
and reports whether findings/risk increased or decreased, plus which
risk category improved the most and which got worse.

If no previous report exists (e.g. this is the first scan, or the
history file was deleted), trend analysis degrades gracefully: it
never raises and never fabricates a comparison.

This module performs no detection or scoring of its own -- both the
"current" and "previous" values it compares are read directly from
Task 2 Phase 1 JSON reports (`summary.total_findings`,
`summary.risk_score`) or derived from `categories.build_category_counts`,
which itself only relabels each finding's existing `entity_type`.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from scanner.config import ScannerSettings
from scanner.intelligence.categories import build_category_counts
from scanner.logger import get_logger
from scanner.utils import ensure_directory

logger = get_logger(__name__)

#: Trend comparisons are read from the canonical report history instead
#: of a duplicate previous-report snapshot.
_HISTORY_DIRECTORY_NAME = "history"
_SCAN_REPORT_FILENAME = "scan_report.json"
_REPORT_FOLDER_PATTERN = re.compile(r"^Report_(\d{3})_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")

_NO_PREVIOUS_REPORT_MESSAGE = (
    "Trend analysis unavailable: no previous scan report was found. "
    "This is expected on the first scan; future scans will be compared "
    "against this one."
)


def _direction(delta: int) -> str:
    """Classify a numeric delta as 'increased', 'decreased', or 'unchanged'."""
    if delta > 0:
        return "increased"
    if delta < 0:
        return "decreased"
    return "unchanged"


class TrendAnalyzer:
    """
    Compares the current report to the previously stored report and
    persists the current report for the next comparison.
    """

    def __init__(self, settings: ScannerSettings) -> None:
        """
        Args:
            settings: Application settings. Only
                `settings.output_directory` is used, to locate the
                `intelligence/` subdirectory where the previous
                report's snapshot is stored.
        """
        self._settings = settings

    @property
    def _history_directory(self) -> Path:
        return self._settings.working_directory / "reports" / _HISTORY_DIRECTORY_NAME

    def _load_previous_report(self) -> dict[str, Any] | None:
        if not self._history_directory.is_dir():
            return None
        candidates = sorted(
            child / _SCAN_REPORT_FILENAME
            for child in self._history_directory.iterdir()
            if child.is_dir() and (child / _SCAN_REPORT_FILENAME).is_file()
        )
        if not candidates:
            return None
        path = candidates[-1]
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "Could not read previous report %s for trend analysis: %s",
                path,
                exc,
            )
            return None

    def analyze(self, current_report: dict[str, Any]) -> dict[str, Any]:
        """
        Compare `current_report` against the previously stored report.

        Args:
            current_report: A Task 2 Phase 1 JSON report dict for the
                scan that just completed.

        Returns:
            If no previous report is available: a dict with
            `trend_available: False` and a human-readable `message`.

            Otherwise, a dict with `trend_available: True` plus:
                - `previous_total_findings`, `current_total_findings`,
                  `findings_delta`, `findings_trend`
                - `previous_risk_score`, `current_risk_score`,
                  `risk_score_delta`, `risk_score_trend`
                - `category_deltas` (category -> current minus previous count)
                - `most_improved_category` (largest decrease, or `None`
                  if no category decreased)
                - `worst_category` (largest increase, or `None` if no
                  category increased)
        """
        previous_report = self._load_previous_report()
        if previous_report is None:
            return {"trend_available": False, "message": _NO_PREVIOUS_REPORT_MESSAGE}

        return self._compare(previous_report, current_report)

    def _compare(
        self, previous_report: dict[str, Any], current_report: dict[str, Any]
    ) -> dict[str, Any]:
        previous_summary = previous_report.get("summary", {}) or {}
        current_summary = current_report.get("summary", {}) or {}

        previous_total = int(previous_summary.get("total_findings", 0))
        current_total = int(current_summary.get("total_findings", 0))
        previous_risk_score = int(previous_summary.get("risk_score", 0))
        current_risk_score = int(current_summary.get("risk_score", 0))

        previous_categories = build_category_counts(previous_report.get("findings", []) or [])
        current_categories = build_category_counts(current_report.get("findings", []) or [])

        categories = set(previous_categories) | set(current_categories)
        category_deltas = {
            category: current_categories.get(category, 0) - previous_categories.get(category, 0)
            for category in categories
        }

        most_improved_category = None
        worst_category = None
        if category_deltas:
            best_candidate = min(category_deltas, key=lambda c: category_deltas[c])
            if category_deltas[best_candidate] < 0:
                most_improved_category = best_candidate

            worst_candidate = max(category_deltas, key=lambda c: category_deltas[c])
            if category_deltas[worst_candidate] > 0:
                worst_category = worst_candidate

        findings_delta = current_total - previous_total
        risk_score_delta = current_risk_score - previous_risk_score

        return {
            "trend_available": True,
            "previous_total_findings": previous_total,
            "current_total_findings": current_total,
            "difference": findings_delta,
            "findings_delta": findings_delta,
            "findings_trend": _direction(findings_delta),
            "previous_risk_score": previous_risk_score,
            "current_risk_score": current_risk_score,
            "risk_score_delta": risk_score_delta,
            "risk_score_trend": _direction(risk_score_delta),
            "category_deltas": category_deltas,
            "most_improved_category": most_improved_category,
            "worst_category": worst_category,
        }

    def store_current_report(self, current_report: dict[str, Any]) -> Path:
        """
        Persist `current_report` as the snapshot future scans compare against.

        Args:
            current_report: A Task 2 Phase 1 JSON report dict.

        Returns:
            The path the snapshot was written to.
        """
        history = ensure_directory(self._history_directory)
        highest = 0
        for child in history.iterdir():
            if child.is_dir():
                match = _REPORT_FOLDER_PATTERN.match(child.name)
                if match:
                    highest = max(highest, int(match.group(1)))
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        candidate = history / f"Report_{highest + 1:03d}_{timestamp}"
        while candidate.exists():
            highest += 1
            candidate = history / f"Report_{highest + 1:03d}_{timestamp}"
        ensure_directory(candidate)
        path = candidate / _SCAN_REPORT_FILENAME
        path.write_text(json.dumps(current_report, indent=2), encoding="utf-8")
        logger.info("Stored current report for future trend analysis at %s", path)
        return path
