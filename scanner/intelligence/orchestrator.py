"""
orchestrator.py
===============

Task 2, Phase 4: `IntelligenceEngine`, the single integration point
`main.py` calls.

Ties together every Phase 4 module (root cause, remediation, trend,
developer guidance, dashboard) and writes their output artifacts under
`reports/latest/`, without touching scanner detection or risk logic.

Failure handling
----------------
Per the project's requirements ("AI never makes security decisions",
and by analogy with `scanner.ai.AIAssistant`'s failure handling), a
Phase 4 failure must never terminate a scan or change
`summary.pipeline_status`. `generate_all()` therefore never raises:
any failure (missing/invalid report, disk I/O error, ...) is logged
and results in an empty result dict rather than an exception reaching
`main.py`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.config import ScannerSettings
from scanner.intelligence.dashboard import DashboardBuilder
from scanner.intelligence.guidance import DeveloperGuidanceReportBuilder
from scanner.intelligence.trend import TrendAnalyzer
from scanner.logger import get_logger
from scanner.utils import ensure_directory

logger = get_logger(__name__)

_GUIDANCE_FILENAME = "Developer_Guidance.md"


def _is_valid_report(report: Any) -> bool:
    """Return True if `report` looks like a Task 2 Phase 1 report dict."""
    return (
        isinstance(report, dict)
        and isinstance(report.get("summary"), dict)
        and bool(report.get("summary"))
        and isinstance(report.get("findings"), list)
    )


class IntelligenceEngine:
    """
    Orchestrates the Phase 4 Intelligence Layer.

    Consumes only the JSON report dict produced by
    `scanner.report_generator.ReportGenerator` -- it never imports or
    calls Presidio, `RiskEngine`, or scanner internals directly, and it
    never changes a finding, a severity, a risk score, or a pipeline
    status.
    """

    def __init__(self, settings: ScannerSettings) -> None:
        """
        Args:
            settings: Application settings (only
                `settings.output_directory` is used).
        """
        self._settings = settings
        self._trend_analyzer = TrendAnalyzer(settings)
        self._dashboard_builder = DashboardBuilder(settings)
        self._guidance_builder = DeveloperGuidanceReportBuilder()

    @property
    def _intelligence_directory(self) -> Path:
        return self._settings.working_directory / "reports" / "latest"

    @property
    def guidance_path(self) -> Path:
        """Path `developer-guidance.md` is (or will be) written to."""
        return self._intelligence_directory / _GUIDANCE_FILENAME

    def generate_all(self, report: dict[str, Any] | None) -> dict[str, Path]:
        """
        Generate every Phase 4 artifact for a completed scan.

        Args:
            report: A Task 2 Phase 1 JSON report dict, as produced by
                `ReportGenerator.build_report()`. May be `None` or
                malformed -- handled gracefully rather than raising.

        Returns:
            A dict mapping artifact name to the `Path` it was written
            to (e.g. `{"developer_guidance": ..., "dashboard": ...}`).
            Returns an empty dict if generation failed entirely; never
            raises.
        """
        if not _is_valid_report(report):
            if report is not None:
                logger.warning(
                    "Intelligence layer received a missing or malformed "
                    "report; skipping developer guidance/dashboard/trend "
                    "generation for this run."
                )
            return {}

        written: dict[str, Path] = {}

        try:
            trend = self._trend_analyzer.analyze(report)
        except Exception as exc:  # noqa: BLE001 - Phase 4 must never abort the scan
            logger.warning("Trend analysis failed unexpectedly: %s", exc)
            trend = {"trend_available": False, "message": "Trend analysis failed unexpectedly."}

        try:
            ensure_directory(self._intelligence_directory)
            guidance_markdown = self._guidance_builder.generate(report)
            self.guidance_path.write_text(guidance_markdown, encoding="utf-8")
            written["developer_guidance"] = self.guidance_path
            logger.info("Developer guidance report written to %s", self.guidance_path)
        except Exception as exc:  # noqa: BLE001 - Phase 4 must never abort the scan
            logger.warning("Developer guidance report generation failed: %s", exc)

        try:
            _dashboard, dashboard_path = self._dashboard_builder.generate(report, trend)
            written["dashboard"] = dashboard_path
        except Exception as exc:  # noqa: BLE001 - Phase 4 must never abort the scan
            logger.warning("Dashboard JSON generation failed: %s", exc)

        try:
            self._trend_analyzer.store_current_report(report)
        except Exception as exc:  # noqa: BLE001 - Phase 4 must never abort the scan
            logger.warning(
                "Could not store the current report as the previous-scan "
                "snapshot for future trend analysis: %s",
                exc,
            )

        return written
