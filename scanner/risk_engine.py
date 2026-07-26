"""
risk_engine.py
================

Task 2, Phase 1: deterministic repository-level risk scoring.

Turns a completed `ScanSummary`'s severity counts into a single
`risk_score` and a `PipelineStatus` (PASS / WARNING / FAIL), using
fixed, documented severity weights and configurable warning/fail
thresholds.

This module never uses AI, machine learning, or any other
non-deterministic signal: the same `ScanSummary` and the same
thresholds always produce the same `RiskAssessment`. A future Azure
DevOps pipeline gate (Task 2, Phase 3) and the AI assistant (Task 2,
Phase 2) can therefore both treat `RiskAssessment.status` as the
single source of truth for whether a build should pass, warn, or
fail, without depending on an external AI service being available.
"""

from __future__ import annotations

from scanner.config import ScannerSettings
from scanner.logger import get_logger
from scanner.models import PipelineStatus, RiskAssessment, ScanSummary, Severity

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Fixed severity weights.
#
# Unlike the pass/warning/fail thresholds (which are meant to be tuned
# per-project via configuration), these weights define the *shape* of
# the risk score itself. Changing them changes what every past score
# means, so they are intentionally not environment-configurable and
# live in exactly one place.
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 7,
    Severity.CRITICAL: 15,
}


class RiskEngine:
    """
    Computes a deterministic `RiskAssessment` for a completed scan.

    Instances are cheap and stateless aside from configuration,
    mirroring the rest of the project's Phase classes (`ScanEngine`,
    `RepositoryManager`).
    """

    def __init__(self, settings: ScannerSettings) -> None:
        """
        Args:
            settings: Application settings, providing
                `risk_warning_threshold` and `risk_fail_threshold`.
        """
        self._settings = settings

    def assess(self, summary: ScanSummary) -> RiskAssessment:
        """
        Compute a `RiskAssessment` from a completed scan's findings.

        Args:
            summary: The completed `ScanSummary` from `ScanEngine.scan()`.

        Returns:
            A `RiskAssessment` with a deterministic `risk_score` and
            `status`. Any CRITICAL finding forces `status` to FAIL
            regardless of the numeric score, since a single critical
            exposure (e.g. a credit card number) should never be
            averaged away by an otherwise-clean repository.
        """
        severity_counts = summary.findings_by_severity
        risk_score = sum(
            severity_counts[severity] * weight
            for severity, weight in SEVERITY_WEIGHTS.items()
        )

        warning_threshold = self._settings.risk_warning_threshold
        fail_threshold = self._settings.risk_fail_threshold

        if severity_counts[Severity.CRITICAL] > 0 or risk_score >= fail_threshold:
            status = PipelineStatus.FAIL
        elif risk_score >= warning_threshold:
            status = PipelineStatus.WARNING
        else:
            status = PipelineStatus.PASS

        assessment = RiskAssessment(
            risk_score=risk_score,
            status=status,
            severity_counts=severity_counts,
            warning_threshold=warning_threshold,
            fail_threshold=fail_threshold,
        )

        logger.info(
            "Risk assessment: score=%d status=%s (warning>=%d, fail>=%d)",
            risk_score,
            status.value,
            warning_threshold,
            fail_threshold,
        )
        return assessment
