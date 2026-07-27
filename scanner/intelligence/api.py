"""
api.py
======

Task 2, Phase 4: AI Explanation API (`/api/explain`).

`ExplainService` answers questions about a single, already-detected
finding using only the existing JSON report plus `RootCauseEngine` /
`RemediationEngine` -- it **never** re-runs the scanner, Presidio, or
the risk engine. This mirrors the rule enforced throughout
`scanner.ai` and the rest of `scanner.intelligence`: this layer
explains, it never (re-)decides.

The optional HTTP endpoint below is intentionally implemented with only
the Python standard library (`http.server`), per the project's "no
additional cloud dependencies" / "offline compatible" requirements --
no web framework is added to `requirements.txt` for this. It is not
started automatically by `main.py` or any pipeline stage; it is a
standalone tool an engineer can run locally or in CI to query an
already-written report interactively.

Usage
-----
    python -m scanner.intelligence.api --report-path reports/latest/scan_report.json --port 8090

    curl "http://127.0.0.1:8090/api/explain?finding_id=F-000000"
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from scanner.intelligence.finding_ids import get_finding_by_id
from scanner.intelligence.remediation import RemediationEngine
from scanner.intelligence.root_cause import RootCauseEngine
from scanner.logger import get_logger

logger = get_logger(__name__)

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8090
_DEFAULT_REPORT_PATH = Path("reports") / "latest" / "scan_report.json"


class ExplainServiceError(Exception):
    """Raised when a report cannot be loaded for explanation."""


class ExplainService:
    """
    Answers `/api/explain` questions from an already-written JSON report.

    Holds one report in memory; never re-scans, never re-runs
    Presidio, and never recomputes a risk score.
    """

    def __init__(self, report: dict[str, Any]) -> None:
        """
        Args:
            report: A Task 2 Phase 1 JSON report dict, as produced by
                `scanner.report_generator.ReportGenerator`.
        """
        self._report = report
        self._findings = report.get("findings", []) or []
        self._root_cause_engine = RootCauseEngine()
        self._remediation_engine = RemediationEngine()

    @classmethod
    def from_report_path(cls, report_path: Path) -> "ExplainService":
        """
        Load a report from disk and build an `ExplainService` for it.

        Args:
            report_path: Path to a JSON report written by
                `ReportGenerator` (e.g. `reports/latest/scan_report.json`).

        Returns:
            A new `ExplainService`.

        Raises:
            ExplainServiceError: if the file is missing or is not
                valid JSON.
        """
        if not report_path.is_file():
            raise ExplainServiceError(f"Report file not found: {report_path}")
        try:
            raw = report_path.read_text(encoding="utf-8")
            report = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise ExplainServiceError(
                f"Could not read/parse report file {report_path}: {exc}"
            ) from exc
        if not isinstance(report, dict):
            raise ExplainServiceError(
                f"Report file {report_path} must contain a JSON object."
            )
        if "findings" in report and not isinstance(report["findings"], list):
            raise ExplainServiceError(
                f"Report file {report_path} has an invalid 'findings' value; "
                "expected a list."
            )
        return cls(report)

    def explain(self, finding_id: str) -> dict[str, Any] | None:
        """
        Explain a single finding by its deterministic, positional ID.

        Args:
            finding_id: A finding ID as produced by
                `scanner.intelligence.finding_ids.compute_finding_id`
                (e.g. "F-000000").

        Returns:
            A dict with `finding_id`, `root_cause`, `explanation`
            (alias of `why_detected`, for readability at the API
            boundary), `recommendation`, `best_practice`, and
            `confidence`; or `None` if `finding_id` does not match any
            finding in the loaded report.
        """
        finding = get_finding_by_id(self._findings, finding_id)
        if finding is None:
            return None

        root_cause = self._root_cause_engine.analyze_finding(finding)
        remediation = self._remediation_engine.remediation_for_finding(finding)

        return {
            "finding_id": finding_id,
            "entity_type": root_cause["entity_type"],
            "severity": root_cause["severity"],
            "file": root_cause["file"],
            "line_number": root_cause["line_number"],
            "root_cause": root_cause["root_cause"],
            "explanation": root_cause["why_detected"],
            "recommendation": remediation["recommendation"],
            "best_practice": remediation["best_practice"],
            "owasp": remediation["owasp"],
            "cwe": remediation["cwe"],
            "confidence": root_cause["confidence"],
        }


def _make_handler(service: ExplainService) -> type[BaseHTTPRequestHandler]:
    """Build a `BaseHTTPRequestHandler` subclass bound to `service`."""

    class ExplainRequestHandler(BaseHTTPRequestHandler):
        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - required BaseHTTPRequestHandler name
            parsed = urlparse(self.path)
            if parsed.path != "/api/explain":
                self._send_json(404, {"error": "Not found. Use /api/explain?finding_id=..."})
                return

            query = parse_qs(parsed.query)
            finding_ids = query.get("finding_id")
            if not finding_ids:
                self._send_json(400, {"error": "Missing required query parameter 'finding_id'."})
                return

            explanation = service.explain(finding_ids[0])
            if explanation is None:
                self._send_json(
                    404, {"error": f"No finding found for finding_id={finding_ids[0]!r}."}
                )
                return

            self._send_json(200, explanation)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            # Route access logs through the project's logger instead of
            # stderr, for consistency with the rest of the application.
            logger.info("%s - %s", self.address_string(), format % args)

    return ExplainRequestHandler


def run_server(
    report_path: Path,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
) -> None:
    """
    Start the (blocking) `/api/explain` HTTP server for one report.

    Args:
        report_path: Path to a JSON report written by `ReportGenerator`.
        host: Interface to bind to (defaults to loopback-only).
        port: TCP port to listen on.

    Raises:
        ExplainServiceError: if `report_path` cannot be loaded.
    """
    service = ExplainService.from_report_path(report_path)
    handler = _make_handler(service)
    server = HTTPServer((host, port), handler)
    logger.info(
        "AI Explanation API serving %s at http://%s:%d/api/explain "
        "(never re-runs the scanner; reads only from the loaded report)",
        report_path,
        host,
        port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive use only
        logger.info("AI Explanation API shutting down.")
    finally:
        server.server_close()


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for this optional standalone tool."""
    parser = argparse.ArgumentParser(
        prog="scanner.intelligence.api",
        description=(
            "Optional, dependency-free HTTP endpoint for /api/explain. "
            "Reads an existing JSON report; never re-runs the scanner."
        ),
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=_DEFAULT_REPORT_PATH,
        help=f"Path to the JSON report to serve (default: {_DEFAULT_REPORT_PATH}).",
    )
    parser.add_argument("--host", type=str, default=_DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT)
    return parser


def main() -> None:
    """Console-script style entry point."""
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        run_server(args.report_path, host=args.host, port=args.port)
    except ExplainServiceError as exc:
        print(f"AI Explanation API error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
