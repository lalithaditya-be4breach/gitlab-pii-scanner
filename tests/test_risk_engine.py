"""
test_risk_engine.py
=====================

Tests for Task 2, Phase 1's `RiskEngine`: deterministic severity
weighting, threshold-based status, and the "any CRITICAL finding
forces FAIL" override.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scanner.config import ScannerSettings
from scanner.models import (
    PIIFinding,
    PipelineStatus,
    RepositorySource,
    RepositorySourceType,
    ScannedFile,
    ScanSummary,
    Severity,
)
from scanner.risk_engine import RiskEngine


def _build_test_settings(
    tmp_path: Path,
    *,
    risk_warning_threshold: int = 20,
    risk_fail_threshold: int = 50,
) -> ScannerSettings:
    output_directory = tmp_path / "output"
    return ScannerSettings(
        app_name="gitlab-pii-scanner-test",
        environment="test",
        log_level="DEBUG",
        working_directory=tmp_path,
        output_directory=output_directory,
        supported_extensions=(".py",),
        excluded_directories=(".git",),
        max_file_size_bytes=5 * 1024 * 1024,
        presidio_language="en",
        presidio_min_confidence=0.5,
        presidio_spacy_model="en_core_web_lg",
        clone_base_directory=output_directory / "cloned_repositories",
        clone_shallow_depth=1,
        risk_warning_threshold=risk_warning_threshold,
        risk_fail_threshold=risk_fail_threshold,
        report_output_directory=output_directory / "reports",
        report_redaction_enabled=True,
    )


def _summary_with_severities(tmp_path: Path, severities: list[Severity]) -> ScanSummary:
    source = RepositorySource(
        source_type=RepositorySourceType.LOCAL_PATH,
        identifier=str(tmp_path),
        local_path=tmp_path,
    )
    scanned_file = ScannedFile(
        absolute_path=tmp_path / "app.py",
        relative_path=Path("app.py"),
        size_bytes=10,
        extension=".py",
    )
    summary = ScanSummary(
        source=source,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        files_scanned=1,
        files_skipped=0,
    )
    for severity in severities:
        summary.findings.append(
            PIIFinding(
                file=scanned_file,
                entity_type="EMAIL_ADDRESS",
                matched_text="someone@example.com",
                line_number=1,
                confidence_score=0.9,
                severity=severity,
            )
        )
    return summary


def test_assess_with_no_findings_is_pass(tmp_path: Path) -> None:
    """A clean scan (no findings) always yields PASS with a zero score."""
    settings = _build_test_settings(tmp_path)
    summary = _summary_with_severities(tmp_path, [])

    assessment = RiskEngine(settings=settings).assess(summary)

    assert assessment.risk_score == 0
    assert assessment.status == PipelineStatus.PASS


def test_assess_low_severity_findings_stay_under_warning(tmp_path: Path) -> None:
    """A handful of LOW findings should stay under the warning threshold."""
    settings = _build_test_settings(tmp_path, risk_warning_threshold=20)
    summary = _summary_with_severities(tmp_path, [Severity.LOW] * 5)  # score = 5

    assessment = RiskEngine(settings=settings).assess(summary)

    assert assessment.risk_score == 5
    assert assessment.status == PipelineStatus.PASS


def test_assess_crosses_warning_threshold(tmp_path: Path) -> None:
    """Enough MEDIUM findings to cross (but not exceed) the fail threshold warns."""
    settings = _build_test_settings(
        tmp_path, risk_warning_threshold=20, risk_fail_threshold=50
    )
    # 8 MEDIUM findings * weight 3 = 24 -> above warning(20), below fail(50)
    summary = _summary_with_severities(tmp_path, [Severity.MEDIUM] * 8)

    assessment = RiskEngine(settings=settings).assess(summary)

    assert assessment.risk_score == 24
    assert assessment.status == PipelineStatus.WARNING


def test_assess_crosses_fail_threshold_by_score(tmp_path: Path) -> None:
    """A high enough score fails even without any CRITICAL findings."""
    settings = _build_test_settings(
        tmp_path, risk_warning_threshold=20, risk_fail_threshold=50
    )
    # 8 HIGH findings * weight 7 = 56 -> above fail(50)
    summary = _summary_with_severities(tmp_path, [Severity.HIGH] * 8)

    assessment = RiskEngine(settings=settings).assess(summary)

    assert assessment.risk_score == 56
    assert assessment.status == PipelineStatus.FAIL


def test_single_critical_finding_forces_fail_regardless_of_score(tmp_path: Path) -> None:
    """Even one CRITICAL finding forces FAIL, even if the numeric score is low."""
    settings = _build_test_settings(
        tmp_path, risk_warning_threshold=20, risk_fail_threshold=50
    )
    summary = _summary_with_severities(tmp_path, [Severity.CRITICAL])  # score = 15

    assessment = RiskEngine(settings=settings).assess(summary)

    assert assessment.risk_score == 15
    assert assessment.risk_score < settings.risk_warning_threshold
    assert assessment.status == PipelineStatus.FAIL


def test_assessment_reports_thresholds_used(tmp_path: Path) -> None:
    """The RiskAssessment records which thresholds produced the status."""
    settings = _build_test_settings(
        tmp_path, risk_warning_threshold=10, risk_fail_threshold=30
    )
    summary = _summary_with_severities(tmp_path, [])

    assessment = RiskEngine(settings=settings).assess(summary)

    assert assessment.warning_threshold == 10
    assert assessment.fail_threshold == 30


def test_assessment_severity_counts_include_all_levels(tmp_path: Path) -> None:
    """severity_counts always has an entry for every Severity, even if zero."""
    settings = _build_test_settings(tmp_path)
    summary = _summary_with_severities(tmp_path, [Severity.HIGH])

    assessment = RiskEngine(settings=settings).assess(summary)

    assert set(assessment.severity_counts.keys()) == set(Severity)
    assert assessment.severity_counts[Severity.HIGH] == 1
    assert assessment.severity_counts[Severity.LOW] == 0


def test_same_summary_produces_identical_assessment(tmp_path: Path) -> None:
    """Determinism: assessing the same summary twice yields the same result."""
    settings = _build_test_settings(tmp_path)
    summary = _summary_with_severities(tmp_path, [Severity.MEDIUM, Severity.HIGH])

    engine = RiskEngine(settings=settings)
    first = engine.assess(summary)
    second = engine.assess(summary)

    assert first == second
