"""
test_main.py
=============

Integration-style tests for `main.run()`: configuration load, mocked
scan pipeline (repository -> scan -> risk -> JSON report -> AI summary),
and process exit codes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import main
from main import ExitCode
from scanner.config import ConfigError, ScannerSettings
from scanner.models import (
    PipelineStatus,
    RepositorySource,
    RepositorySourceType,
    RiskAssessment,
    ScanSummary,
    Severity,
)


def _build_test_settings(tmp_path: Path) -> ScannerSettings:
    output_directory = tmp_path / "output"
    return ScannerSettings(
        app_name="gitlab-pii-scanner-test",
        environment="test",
        log_level="CRITICAL",
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
        report_redaction_enabled=True,
        ai_enabled=True,
        ai_provider="null",
        ai_summary_filename="ai-summary.md",
    )


def _sample_repository(tmp_path: Path) -> RepositorySource:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    return RepositorySource(
        source_type=RepositorySourceType.LOCAL_PATH,
        identifier=str(repo_path),
        local_path=repo_path,
    )


def _sample_scan_summary(repository: RepositorySource) -> ScanSummary:
    now = datetime.now(timezone.utc)
    return ScanSummary(
        source=repository,
        started_at=now,
        finished_at=now,
        files_scanned=1,
        files_skipped=0,
    )


def _sample_risk_assessment() -> RiskAssessment:
    return RiskAssessment(
        risk_score=0,
        status=PipelineStatus.PASS,
        severity_counts={severity: 0 for severity in Severity},
        warning_threshold=20,
        fail_threshold=50,
    )


def _pipeline_mocks(
    tmp_path: Path,
) -> tuple[ScannerSettings, ScanSummary, RiskAssessment, dict, Path]:
    settings = _build_test_settings(tmp_path)
    repository = _sample_repository(tmp_path)
    summary = _sample_scan_summary(repository)
    assessment = _sample_risk_assessment()
    report = {"summary": {"total_findings": 0, "pipeline_status": "PASS"}, "findings": []}
    report_path = settings.report_output_directory / "latest.json"
    return settings, summary, assessment, report, report_path


def test_run_returns_configuration_error_when_settings_invalid() -> None:
    with patch("main.get_settings", side_effect=ConfigError("bad config")):
        assert main.run(["local", "--path", "."]) == ExitCode.CONFIGURATION_ERROR


def test_run_successful_local_pipeline_exit_code_zero(tmp_path: Path) -> None:
    settings, summary, assessment, report, report_path = _pipeline_mocks(tmp_path)
    repository = summary.source

    mock_rm = MagicMock()
    mock_rm.obtain_local.return_value = repository

    mock_scan_engine = MagicMock()
    mock_scan_engine.scan.return_value = summary

    mock_risk_engine = MagicMock()
    mock_risk_engine.assess.return_value = assessment

    mock_report_gen = MagicMock()
    mock_report_gen.generate.return_value = (report, report_path)

    mock_ai = MagicMock()
    mock_ai.generate.return_value = ("# summary", settings.output_directory / "ai-summary.md")

    with patch("main.get_settings", return_value=settings):
        with patch("main.RepositoryManager", return_value=mock_rm):
            with patch("main.ScanEngine", return_value=mock_scan_engine):
                with patch("main.RiskEngine", return_value=mock_risk_engine):
                    with patch("main.ReportGenerator", return_value=mock_report_gen):
                        with patch("main.AIAssistant", return_value=mock_ai):
                            exit_code = main.run(
                                ["local", "--path", str(repository.local_path), "--no-file-log"]
                            )

    assert exit_code == ExitCode.SUCCESS
    mock_rm.obtain_local.assert_called_once()
    mock_scan_engine.scan.assert_called_once_with(repository)
    mock_risk_engine.assess.assert_called_once_with(summary)
    mock_report_gen.generate.assert_called_once_with(summary, assessment)
    mock_ai.generate.assert_called_once_with(report)


def test_run_pipeline_order_scan_before_report_before_ai(tmp_path: Path) -> None:
    settings, summary, assessment, report, report_path = _pipeline_mocks(tmp_path)
    repository = summary.source
    call_order: list[str] = []

    mock_rm = MagicMock()
    mock_rm.obtain_local.return_value = repository

    mock_scan_engine = MagicMock()

    def _scan(_repo: RepositorySource) -> ScanSummary:
        call_order.append("scan")
        return summary

    mock_scan_engine.scan.side_effect = _scan

    mock_risk_engine = MagicMock()

    def _assess(_summary: ScanSummary) -> RiskAssessment:
        call_order.append("risk")
        return assessment

    mock_risk_engine.assess.side_effect = _assess

    mock_report_gen = MagicMock()

    def _generate(_summary: ScanSummary, _assessment: RiskAssessment) -> tuple:
        call_order.append("report")
        return report, report_path

    mock_report_gen.generate.side_effect = _generate

    mock_ai = MagicMock()

    def _ai_generate(_report: dict) -> tuple:
        call_order.append("ai")
        return ("# summary", settings.output_directory / "ai-summary.md")

    mock_ai.generate.side_effect = _ai_generate

    with patch("main.get_settings", return_value=settings):
        with patch("main.RepositoryManager", return_value=mock_rm):
            with patch("main.ScanEngine", return_value=mock_scan_engine):
                with patch("main.RiskEngine", return_value=mock_risk_engine):
                    with patch("main.ReportGenerator", return_value=mock_report_gen):
                        with patch("main.AIAssistant", return_value=mock_ai):
                            main.run(
                                ["local", "--path", str(repository.local_path), "--no-file-log"]
                            )

    assert call_order == ["scan", "risk", "report", "ai"]


def test_run_returns_report_write_error_on_json_os_error(tmp_path: Path) -> None:
    settings, summary, assessment, _report, _report_path = _pipeline_mocks(tmp_path)
    repository = summary.source

    mock_rm = MagicMock()
    mock_rm.obtain_local.return_value = repository

    mock_scan_engine = MagicMock()
    mock_scan_engine.scan.return_value = summary

    mock_risk_engine = MagicMock()
    mock_risk_engine.assess.return_value = assessment

    mock_report_gen = MagicMock()
    mock_report_gen.generate.side_effect = OSError("No space left on device")

    mock_ai = MagicMock()

    with patch("main.get_settings", return_value=settings):
        with patch("main.RepositoryManager", return_value=mock_rm):
            with patch("main.ScanEngine", return_value=mock_scan_engine):
                with patch("main.RiskEngine", return_value=mock_risk_engine):
                    with patch("main.ReportGenerator", return_value=mock_report_gen):
                        with patch("main.AIAssistant", return_value=mock_ai):
                            exit_code = main.run(
                                ["local", "--path", str(repository.local_path), "--no-file-log"]
                            )

    assert exit_code == ExitCode.REPORT_WRITE_ERROR
    mock_ai.generate.assert_not_called()


def test_run_ai_failure_still_exits_success_after_report_written(tmp_path: Path) -> None:
    settings, summary, assessment, report, report_path = _pipeline_mocks(tmp_path)
    repository = summary.source

    mock_rm = MagicMock()
    mock_rm.obtain_local.return_value = repository

    mock_scan_engine = MagicMock()
    mock_scan_engine.scan.return_value = summary

    mock_risk_engine = MagicMock()
    mock_risk_engine.assess.return_value = assessment

    mock_report_gen = MagicMock()
    mock_report_gen.generate.return_value = (report, report_path)

    mock_ai = MagicMock()
    mock_ai.generate.side_effect = OSError("permission denied writing markdown")

    with patch("main.get_settings", return_value=settings):
        with patch("main.RepositoryManager", return_value=mock_rm):
            with patch("main.ScanEngine", return_value=mock_scan_engine):
                with patch("main.RiskEngine", return_value=mock_risk_engine):
                    with patch("main.ReportGenerator", return_value=mock_report_gen):
                        with patch("main.AIAssistant", return_value=mock_ai):
                            exit_code = main.run(
                                ["local", "--path", str(repository.local_path), "--no-file-log"]
                            )

    assert exit_code == ExitCode.SUCCESS
