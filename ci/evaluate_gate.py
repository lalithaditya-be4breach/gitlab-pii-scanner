"""
evaluate_gate.py
================

Task 2, Phase 3: Azure DevOps pipeline gate.

This script is the *only* piece of Phase 3 that runs inside the Azure
DevOps agent after the scanner has already produced its JSON report.
It performs a single, narrow job:

    read `summary.pipeline_status` from the JSON report
                        |
                        v
    translate PASS / WARNING / FAIL into an Azure DevOps
    pipeline result (succeed / succeed with warning / fail)

It deliberately does nothing else. In particular, this script:

    - never re-scans anything (no Presidio, no file traversal)
    - never recomputes a risk score
    - never inspects individual findings
    - never duplicates any `RiskEngine` logic

`RiskEngine` (in `scanner/risk_engine.py`) is the single source of
truth for risk decisions. This script only *reads* the decision that
was already made and reported by `ReportGenerator`:

    Presidio -> RiskEngine -> ReportGenerator (JSON report) -> [this script] -> Azure DevOps

By design this module has zero third-party dependencies -- only the
Python standard library -- so it can run on any Azure DevOps
`UsePythonVersion` agent with nothing beyond `python3` on PATH, before
(or even without) `pip install -r requirements.txt`.

Usage
-----
    python ci/evaluate_gate.py --report-path reports/latest/scan_report.json

Exit codes
----------
    0   pipeline_status was PASS or WARNING (build continues)
    1   pipeline_status was FAIL, or the report could not be read/
        parsed, or `summary.pipeline_status` was missing/unrecognized
        (fail closed: an unreadable gate is treated as a failed gate)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

#: The only three values `RiskEngine` / `ReportGenerator` ever produce
#: for `summary.pipeline_status` (see `scanner/models.py::PipelineStatus`).
#: Duplicated here only as a set of *recognized strings* for validation --
#: not as a re-implementation of any risk decision.
_KNOWN_STATUSES = {"PASS", "WARNING", "FAIL"}

_DEFAULT_REPORT_PATH = Path("reports") / "latest" / "scan_report.json"


class GateError(Exception):
    """Raised when the pipeline gate cannot be evaluated at all."""


def read_pipeline_status(report_path: Path) -> str:
    """
    Read `summary.pipeline_status` from a scanner JSON report.

    Args:
        report_path: Path to the JSON report written by
            `ReportGenerator` (typically `reports/latest/scan_report.json`).

    Returns:
        The raw `pipeline_status` string ("PASS", "WARNING", or "FAIL").

    Raises:
        GateError: if the file is missing, is not valid JSON, or does
            not contain a recognized `summary.pipeline_status` value.
            This function never guesses a status -- an unreadable
            report is always an error, not a silent PASS.
    """
    if not report_path.is_file():
        raise GateError(f"Report file not found: {report_path}")

    try:
        raw = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError(f"Could not read report file {report_path}: {exc}") from exc

    try:
        report = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GateError(f"Report file {report_path} is not valid JSON: {exc}") from exc

    summary = report.get("summary") if isinstance(report, dict) else None
    if not isinstance(summary, dict):
        raise GateError(
            f"Report file {report_path} has no 'summary' object; "
            "cannot determine pipeline_status."
        )

    status = summary.get("pipeline_status")
    if status not in _KNOWN_STATUSES:
        raise GateError(
            f"Report file {report_path} has an unrecognized "
            f"summary.pipeline_status: {status!r} (expected one of "
            f"{sorted(_KNOWN_STATUSES)})."
        )

    return status


def apply_gate(status: str) -> int:
    """
    Emit Azure DevOps logging commands for `status` and return an exit code.

    Azure DevOps logging commands used here (all standard,
    stdlib-only `print()` calls -- see Microsoft's "Logging commands"
    docs):

        ##vso[task.logissue type=warning;]<message>
        ##vso[task.logissue type=error;]<message>
        ##vso[task.complete result=Succeeded;]
        ##vso[task.complete result=SucceededWithIssues;]
        ##vso[task.complete result=Failed;]

    Args:
        status: One of "PASS", "WARNING", or "FAIL", as read from the
            JSON report by `read_pipeline_status()`.

    Returns:
        Process exit code: 0 for PASS/WARNING, 1 for FAIL.
    """
    if status == "PASS":
        print(f"PII scan gate: PASS (pipeline_status={status})")
        print("##vso[task.complete result=Succeeded;]")
        return 0

    if status == "WARNING":
        print(f"PII scan gate: WARNING (pipeline_status={status})")
        print(
            "##vso[task.logissue type=warning;]"
            "PII scan reported WARNING-level findings. Review the "
            "published AI summary and JSON report."
        )
        print("##vso[task.complete result=SucceededWithIssues;]")
        return 0

    # status == "FAIL"
    print(f"PII scan gate: FAIL (pipeline_status={status})", file=sys.stderr)
    print(
        "##vso[task.logissue type=error;]"
        "PII scan reported FAIL-level findings. Build gated -- see the "
        "published JSON report and AI summary for details."
    )
    print("##vso[task.complete result=Failed;]")
    return 1


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for this helper script."""
    parser = argparse.ArgumentParser(
        prog="evaluate_gate",
        description=(
            "Read summary.pipeline_status from the scanner's JSON report "
            "and gate the Azure DevOps pipeline accordingly. Never "
            "recomputes risk; only reads the existing decision."
        ),
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=_DEFAULT_REPORT_PATH,
        help=(
            "Path to the JSON report written by ReportGenerator "
            f"(default: {_DEFAULT_REPORT_PATH})."
        ),
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    """
    Entry point logic, separated from `main()` for testability.

    Args:
        argv: Optional argument list (defaults to `sys.argv[1:]`).

    Returns:
        A process exit code (0 = pass the gate, 1 = fail the gate).
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        status = read_pipeline_status(args.report_path)
    except GateError as exc:
        # Fail closed: if the gate can't be evaluated, treat it as a
        # failed gate rather than silently letting the build pass.
        print(f"PII scan gate: ERROR ({exc})", file=sys.stderr)
        print(f"##vso[task.logissue type=error;]{exc}")
        print("##vso[task.complete result=Failed;]")
        return 1

    return apply_gate(status)


def main() -> None:
    """Console-script style entry point that exits the process with the right code."""
    sys.exit(run())


if __name__ == "__main__":
    main()
