"""
test_report_generator.py
==========================

Tests for Task 2, Phase 1's `ReportGenerator`: report structure, JSON
export, and — critically — that raw PII values are redacted by
default before anything is written to disk.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scanner.config import ScannerSettings
from scanner.models import (
    PIIFinding,
    PipelineStatus,
    RepositorySource,
    RepositorySourceType,
    RiskAssessment,
    ScannedFile,
    ScanSummary,
    Severity,
)
from scanner.report_generator import ReportGenerator, redact_value


def _build_test_settings(
    tmp_path: Path, *, report_redaction_enabled: bool = True
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
        risk_warning_threshold=20,
        risk_fail_threshold=50,
        report_output_directory=output_directory / "reports",
        report_redaction_enabled=report_redaction_enabled,
    )


def _summary_with_finding(
    tmp_path: Path, entity_type: str, matched_text: str, severity: Severity
) -> ScanSummary:
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
    summary.findings.append(
        PIIFinding(
            file=scanned_file,
            entity_type=entity_type,
            matched_text=matched_text,
            line_number=7,
            confidence_score=0.987654,
            severity=severity,
        )
    )
    return summary


def _assessment_for(summary: ScanSummary) -> RiskAssessment:
    return RiskAssessment(
        risk_score=7,
        status=PipelineStatus.WARNING,
        severity_counts=summary.findings_by_severity,
        warning_threshold=5,
        fail_threshold=50,
    )


# -- redact_value() unit tests -----------------------------------------------


def test_redact_value_email_keeps_first_two_chars_and_domain() -> None:
    assert redact_value("EMAIL_ADDRESS", "john.doe@example.com") == "jo***@example.com"


def test_redact_value_credit_card_keeps_last_four_digits() -> None:
    assert redact_value("CREDIT_CARD", "4111111111111111") == "************1111"


def test_redact_value_short_value_fully_masked() -> None:
    assert redact_value("US_SSN", "123") == "***"


def test_redact_value_empty_string_unchanged() -> None:
    assert redact_value("PERSON", "") == ""


# -- ReportGenerator.build_report() -------------------------------------------


def test_build_report_redacts_matched_value_by_default(tmp_path: Path) -> None:
    """The raw matched value never appears in the report when redaction is on."""
    settings = _build_test_settings(tmp_path, report_redaction_enabled=True)
    summary = _summary_with_finding(
        tmp_path, "EMAIL_ADDRESS", "john.doe@example.com", Severity.HIGH
    )
    assessment = _assessment_for(summary)

    report = ReportGenerator(settings=settings).build_report(summary, assessment)

    matched_value = report["findings"][0]["matched_value"]
    assert matched_value == "jo***@example.com"
    assert "john.doe@example.com" not in json.dumps(report)
    assert report["findings"][0]["redacted"] is True


def test_build_report_can_disable_redaction(tmp_path: Path) -> None:
    """With redaction disabled, the raw matched value is preserved."""
    settings = _build_test_settings(tmp_path, report_redaction_enabled=False)
    summary = _summary_with_finding(
        tmp_path, "EMAIL_ADDRESS", "john.doe@example.com", Severity.HIGH
    )
    assessment = _assessment_for(summary)

    report = ReportGenerator(settings=settings).build_report(summary, assessment)

    assert report["findings"][0]["matched_value"] == "john.doe@example.com"
    assert report["findings"][0]["redacted"] is False


def test_build_report_includes_schema_and_scanner_version(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    summary = _summary_with_finding(tmp_path, "PERSON", "Jane Doe", Severity.MEDIUM)
    assessment = _assessment_for(summary)

    report = ReportGenerator(settings=settings).build_report(summary, assessment)

    assert "schema_version" in report
    assert "scanner_version" in report
    assert isinstance(report["schema_version"], str)


def test_build_report_summary_reflects_risk_assessment(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    summary = _summary_with_finding(tmp_path, "PERSON", "Jane Doe", Severity.MEDIUM)
    assessment = RiskAssessment(
        risk_score=42,
        status=PipelineStatus.FAIL,
        severity_counts=summary.findings_by_severity,
        warning_threshold=20,
        fail_threshold=40,
    )

    report = ReportGenerator(settings=settings).build_report(summary, assessment)

    assert report["summary"]["risk_score"] == 42
    assert report["summary"]["pipeline_status"] == "FAIL"
    assert report["summary"]["risk_thresholds"] == {"warning": 20, "fail": 40}
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["severity_counts"]["MEDIUM"] == 1


def test_build_report_finding_includes_file_and_line(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    summary = _summary_with_finding(tmp_path, "PERSON", "Jane Doe", Severity.LOW)
    assessment = _assessment_for(summary)

    report = ReportGenerator(settings=settings).build_report(summary, assessment)
    finding = report["findings"][0]

    assert finding["file"] == "app.py"
    assert finding["line_number"] == 7
    assert finding["entity_type"] == "PERSON"
    assert finding["severity"] == "LOW"
    assert finding["confidence_score"] == pytest.approx(0.9877, abs=1e-4)


def test_build_report_is_json_serializable(tmp_path: Path) -> None:
    """The report must round-trip through json.dumps/loads without error."""
    settings = _build_test_settings(tmp_path)
    summary = _summary_with_finding(
        tmp_path, "CREDIT_CARD", "4111111111111111", Severity.CRITICAL
    )
    assessment = _assessment_for(summary)

    report = ReportGenerator(settings=settings).build_report(summary, assessment)

    round_tripped = json.loads(json.dumps(report))
    assert round_tripped == report


# -- ReportGenerator.write_json_report() / generate() -------------------------


def test_write_json_report_creates_timestamped_and_latest_files(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    summary = _summary_with_finding(tmp_path, "PERSON", "Jane Doe", Severity.LOW)
    assessment = _assessment_for(summary)
    generator = ReportGenerator(settings=settings)
    report = generator.build_report(summary, assessment)

    report_path = generator.write_json_report(report)

    assert report_path.exists()
    assert report_path.name == "scan_report.json"
    assert report_path.parent.name == "latest"
    assert report_path.parent.parent.name == "reports"
    assert report_path.is_file()

    # Verify the report contents
    assert json.loads(report_path.read_text(encoding="utf-8")) == report
    


def test_generate_builds_and_writes_in_one_step(tmp_path: Path) -> None:
    settings = _build_test_settings(tmp_path)
    summary = _summary_with_finding(tmp_path, "PERSON", "Jane Doe", Severity.LOW)
    assessment = _assessment_for(summary)
    generator = ReportGenerator(settings=settings)

    report, report_path = generator.generate(summary, assessment)

    assert report_path.exists()
    assert json.loads(report_path.read_text()) == report


def test_write_json_report_creates_output_directory_if_missing(tmp_path: Path) -> None:
    """report_output_directory need not exist beforehand."""
    settings = _build_test_settings(tmp_path)
    assert not settings.report_output_directory.exists()

    summary = _summary_with_finding(tmp_path, "PERSON", "Jane Doe", Severity.LOW)
    assessment = _assessment_for(summary)
    generator = ReportGenerator(settings=settings)

    generator.generate(summary, assessment)

    reports_dir = settings.working_directory / "reports"
    latest_dir = reports_dir / "latest"

    assert reports_dir.exists()
    assert latest_dir.exists()
