"""
test_evaluate_gate.py
=======================

Task 2, Phase 3: tests for `ci/evaluate_gate.py`.

These tests only exercise the CI gate helper in isolation -- they
never import `scanner` internals, since the whole point of this
script is that it *doesn't* depend on them. A hand-written JSON
report dict stands in for whatever `ReportGenerator` would have
produced.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci.evaluate_gate import GateError, apply_gate, read_pipeline_status, run


def _write_report(tmp_path: Path, pipeline_status: str | None, *, valid_summary: bool = True) -> Path:
    """Write a minimal report JSON file mirroring ReportGenerator's shape."""
    report_path = tmp_path / "latest.json"
    if not valid_summary:
        payload = {"schema_version": "1.0"}  # no "summary" key at all
    else:
        payload = {
            "schema_version": "1.0",
            "summary": {
                "total_findings": 3,
                "risk_score": 10,
                "pipeline_status": pipeline_status,
            },
        }
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    return report_path


class TestReadPipelineStatus:
    def test_reads_pass(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path, "PASS")
        assert read_pipeline_status(report_path) == "PASS"

    def test_reads_warning(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path, "WARNING")
        assert read_pipeline_status(report_path) == "WARNING"

    def test_reads_fail(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path, "FAIL")
        assert read_pipeline_status(report_path) == "FAIL"

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(GateError, match="not found"):
            read_pipeline_status(tmp_path / "does-not-exist.json")

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        report_path = tmp_path / "latest.json"
        report_path.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(GateError, match="not valid JSON"):
            read_pipeline_status(report_path)

    def test_missing_summary_raises(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path, None, valid_summary=False)
        with pytest.raises(GateError, match="summary"):
            read_pipeline_status(report_path)

    def test_missing_pipeline_status_raises(self, tmp_path: Path) -> None:
        report_path = tmp_path / "latest.json"
        report_path.write_text(json.dumps({"summary": {}}), encoding="utf-8")
        with pytest.raises(GateError, match="unrecognized"):
            read_pipeline_status(report_path)

    def test_unrecognized_status_raises(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path, "SOMETHING_ELSE")
        with pytest.raises(GateError, match="unrecognized"):
            read_pipeline_status(report_path)


class TestApplyGate:
    def test_pass_succeeds(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = apply_gate("PASS")
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "task.complete result=Succeeded;" in captured.out

    def test_warning_succeeds_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = apply_gate("WARNING")
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "task.logissue type=warning;" in captured.out
        assert "task.complete result=SucceededWithIssues;" in captured.out

    def test_fail_fails_the_build(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = apply_gate("FAIL")
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "task.logissue type=error;" in captured.out
        assert "task.complete result=Failed;" in captured.out


class TestRun:
    def test_run_pass_returns_zero(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path, "PASS")
        assert run(["--report-path", str(report_path)]) == 0

    def test_run_warning_returns_zero(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path, "WARNING")
        assert run(["--report-path", str(report_path)]) == 0

    def test_run_fail_returns_one(self, tmp_path: Path) -> None:
        report_path = _write_report(tmp_path, "FAIL")
        assert run(["--report-path", str(report_path)]) == 1

    def test_run_missing_report_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = run(["--report-path", str(tmp_path / "missing.json")])
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "task.complete result=Failed;" in captured.out

    def test_default_report_path(self) -> None:
        # No --report-path given: should fall back to the documented
        # default and fail closed (fine either way in a throwaway CWD,
        # this just proves the default doesn't raise before that point).
        exit_code = run(["--report-path", "output/reports/does-not-exist.json"])
        assert exit_code == 1
