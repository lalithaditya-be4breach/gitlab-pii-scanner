"""
executive_report.py
===================

Human-readable executive reporting layer.

This module does not scan, score, classify, or change any machine-readable
report schema. It consumes the existing JSON/Markdown artifacts produced by
earlier pipeline layers and packages them into ``reports/latest`` plus an
immutable history folder under ``reports/history``.
"""

from __future__ import annotations

import html
import json
import re
import shutil
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from scanner.config import ScannerSettings
from scanner.intelligence.finding_ids import attach_finding_ids
from scanner.utils import ensure_directory

_REPORTS_DIRECTORY_NAME = "reports"
_LATEST_DIRECTORY_NAME = "latest"
_HISTORY_DIRECTORY_NAME = "history"
_REPORT_FOLDER_PATTERN = re.compile(r"^Report_(\d{3})_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _escape(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _read_text(path: Path | None) -> str:
    if path is None or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _copy_if_exists(source: Path | None, destination: Path) -> None:
    if source is not None and source.is_file():
        shutil.copy2(source, destination)


def _status_class(status: str) -> str:
    return status.lower() if status in {"PASS", "WARNING", "FAIL"} else "unknown"


def _markdown_to_html(markdown: str) -> str:
    lines: list[str] = []
    in_list = False
    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if not line:
            if in_list:
                lines.append("</ul>")
                in_list = False
            continue
        if line.startswith("# "):
            if in_list:
                lines.append("</ul>")
                in_list = False
            lines.append(f"<h2>{_escape(line[2:])}</h2>")
        elif line.startswith("## "):
            if in_list:
                lines.append("</ul>")
                in_list = False
            lines.append(f"<h3>{_escape(line[3:])}</h3>")
        elif line.startswith("- "):
            if not in_list:
                lines.append("<ul>")
                in_list = True
            lines.append(f"<li>{_escape(line[2:])}</li>")
        else:
            if in_list:
                lines.append("</ul>")
                in_list = False
            lines.append(f"<p>{_escape(line)}</p>")
    if in_list:
        lines.append("</ul>")
    return "\n".join(lines)


def _reports_root(root: Path) -> Path:
    return ensure_directory(root / _REPORTS_DIRECTORY_NAME)


def _latest_directory(root: Path) -> Path:
    latest = _reports_root(root) / _LATEST_DIRECTORY_NAME
    if latest.exists():
        shutil.rmtree(latest)
    return ensure_directory(latest)


def _next_report_directory(root: Path, now: datetime) -> Path:
    reports_root = ensure_directory(_reports_root(root) / _HISTORY_DIRECTORY_NAME)
    legacy_root = _reports_root(root)
    highest = 0
    for parent in (reports_root, legacy_root):
        for child in parent.iterdir():
            if child.is_dir():
                match = _REPORT_FOLDER_PATTERN.match(child.name)
                if match:
                    highest = max(highest, int(match.group(1)))
    number = highest + 1
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    candidate = reports_root / f"Report_{number:03d}_{timestamp}"
    while candidate.exists():
        number += 1
        candidate = reports_root / f"Report_{number:03d}_{timestamp}"
    return candidate


def _existing_history_directory_for_scan(root: Path, scan_report: dict[str, Any]) -> Path | None:
    history_root = _reports_root(root) / _HISTORY_DIRECTORY_NAME
    if not history_root.is_dir():
        return None
    expected = json.dumps(scan_report, sort_keys=True)
    for child in sorted(history_root.iterdir(), reverse=True):
        scan_path = child / "scan_report.json"
        if child.is_dir() and scan_path.is_file():
            existing = _load_scan_report(scan_path)
            if json.dumps(existing, sort_keys=True) == expected:
                return child
    return None


def _top_files(findings: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    return Counter(finding.get("file", "unknown") for finding in findings).most_common(limit)


def _top_critical_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    critical = [finding for finding in attach_finding_ids(findings) if finding.get("severity") == "CRITICAL"]
    return critical[:10]


def _recommendation_for(entity_type: str, recommendations: list[dict[str, str]]) -> str:
    for item in recommendations:
        if item.get("entity_type") == entity_type:
            return item.get("recommendation", "")
    return ""


def _format_number(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return _escape(value)


def _format_duration(seconds: Any) -> str:
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return "n/a"
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s" if secs else f"{minutes}m"
    return f"{secs}s"


def _format_date(value: Any) -> str:
    if not value:
        return "n/a"
    raw = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return str(value)
    return parsed.strftime("%d %B %Y<br>%I:%M %p UTC")


def _release_recommendation(summary: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    status = summary.get("pipeline_status", "UNKNOWN")
    severity_counts = summary.get("severity_counts", {}) or {}
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)

    if status == "PASS":
        return {
            "status": "SAFE TO RELEASE",
            "tone": "pass",
            "reason": "The scan completed with a PASS pipeline status.",
            "actions": ["Keep monitoring future scans.", "Preserve the generated evidence package."],
        }

    reasons = []
    if critical:
        reasons.append(f"{critical} Critical finding(s) detected.")
    if high:
        reasons.append(f"{high} High finding(s) detected.")
    reasons.append("Risk score exceeds the configured release policy." if status == "FAIL" else "Review required before release.")
    categories = sorted({finding.get("entity_type", "UNKNOWN") for finding in findings[:20]})
    if categories:
        reasons.append("Detected sensitive data types include: " + ", ".join(categories[:8]) + ".")
    return {
        "status": "DO NOT RELEASE" if status == "FAIL" else "REVIEW BEFORE RELEASE",
        "tone": "fail" if status == "FAIL" else "warning",
        "reason": " ".join(reasons),
        "actions": ["Remove blocking findings.", "Re-run the scanner.", "Verify remediation in the next report."],
    }


class ExecutiveReportPackage:
    """Builds the timestamped human-readable report folder."""

    def __init__(self, settings: ScannerSettings) -> None:
        self._settings = settings

    def generate(
        self,
        *,
        scan_report: dict[str, Any],
        scan_report_path: Path,
        ai_summary_path: Path | None,
        developer_guidance_path: Path | None,
        dashboard_json_path: Path | None,
        now: datetime | None = None,
    ) -> Path:
        root = self._settings.working_directory
        latest_dir = _latest_directory(root)
        report_dir = _existing_history_directory_for_scan(root, scan_report)
        if report_dir is None:
            report_dir = _next_report_directory(root, now or datetime.now())

        _copy_if_exists(scan_report_path, latest_dir / "scan_report.json")
        _copy_if_exists(ai_summary_path, latest_dir / "AI_Summary.md")
        _copy_if_exists(developer_guidance_path, latest_dir / "Developer_Guidance.md")
        _copy_if_exists(dashboard_json_path, latest_dir / "dashboard.json")

        ai_summary = _read_text(ai_summary_path)
        developer_guidance = _read_text(developer_guidance_path)
        dashboard = {}
        if dashboard_json_path is not None and dashboard_json_path.is_file():
            dashboard = json.loads(dashboard_json_path.read_text(encoding="utf-8"))

        (latest_dir / "Executive_Report.html").write_text(
            self._render_executive_html(scan_report, dashboard, ai_summary),
            encoding="utf-8",
        )
        (latest_dir / "Dashboard.html").write_text(
            self._render_dashboard_html(scan_report, dashboard, developer_guidance),
            encoding="utf-8",
        )
        if report_dir.exists():
            for source in latest_dir.iterdir():
                destination = report_dir / source.name
                if source.is_file():
                    shutil.copy2(source, destination)
        else:
            shutil.copytree(latest_dir, report_dir, dirs_exist_ok=False)
        (_reports_root(root) / "index.html").write_text(
            self._render_index_html(scan_report, report_dir),
            encoding="utf-8",
        )
        return report_dir

    def _render_executive_html(
        self, scan_report: dict[str, Any], dashboard: dict[str, Any], ai_summary: str
    ) -> str:
        summary = scan_report.get("summary", {}) or {}
        repository = scan_report.get("repository", {}) or {}
        scan = scan_report.get("scan", {}) or {}
        findings = scan_report.get("findings", []) or []
        severity_counts = summary.get("severity_counts", {}) or {}
        recommendations = _extract_recommendations(ai_summary)
        release = _release_recommendation(summary, findings)

        top_files_rows = "\n".join(
            f"<tr><td>{_escape(file)}</td><td>{count}</td></tr>" for file, count in _top_files(findings)
        ) or "<tr><td colspan=\"2\">No affected files.</td></tr>"
        critical_rows = "\n".join(
            "<tr>"
            f"<td>{_escape(finding.get('finding_id'))}</td>"
            f"<td>{_escape(finding.get('entity_type'))}</td>"
            f"<td>{_escape(finding.get('file'))}:{_escape(finding.get('line_number'))}</td>"
            f"<td>{_escape(finding.get('severity'))}</td>"
            f"<td>{_escape(_recommendation_for(finding.get('entity_type', ''), recommendations))}</td>"
            "</tr>"
            for finding in _top_critical_findings(findings)
        ) or "<tr><td colspan=\"5\">No Critical findings detected.</td></tr>"

        chart_data = _chart_data(summary, dashboard, findings)
        cards = [
            ("Total Findings", summary.get("total_findings", 0)),
            ("Critical", severity_counts.get("CRITICAL", 0)),
            ("High", severity_counts.get("HIGH", 0)),
            ("Medium", severity_counts.get("MEDIUM", 0)),
            ("Low", severity_counts.get("LOW", 0)),
            ("Risk Score", summary.get("risk_score", 0)),
            ("Files Scanned", scan.get("files_scanned", 0)),
        ]
        card_html = "\n".join(
            f"<div class=\"metric\"><span>{_escape(label)}</span><strong>{_format_number(value)}</strong></div>"
            for label, value in cards
        )
        actions = "".join(f"<li>{_escape(action)}</li>" for action in release["actions"])

        return _html_page(
            title="PII Security Assessment Report",
            body=f"""
<section class="hero">
  <div>
    <p class="eyebrow">Executive Security Report</p>
    <h1>PII Security Assessment Report</h1>
    <p>{_escape(repository.get('identifier', 'Unknown repository'))}</p>
  </div>
  <div class="scorecard">
    <span class="badge {_status_class(summary.get('pipeline_status', 'UNKNOWN'))}">{_escape(summary.get('pipeline_status', 'UNKNOWN'))}</span>
    <strong>{_escape(summary.get('risk_score', 0))}</strong>
    <span>Risk Score</span>
  </div>
</section>
<nav class="links"><a href="Dashboard.html">Dashboard</a><a href="Developer_Guidance.md">Developer Guidance</a><a href="AI_Summary.md">AI Summary</a><a href="scan_report.json">Raw JSON</a><a href="dashboard.json">Dashboard JSON</a><a href="../index.html">Back to Index</a></nav>
<section class="assessment"><h2>AI Executive Assessment</h2><h3>AI Security Summary</h3>{_markdown_to_html(ai_summary) or "<p>No AI assessment available.</p>"}</section>
<section class="meta">
  <div><span>Generation Date</span><strong>{_format_date(scan.get('finished_at') or scan.get('started_at') or '')}</strong></div>
  <div><span>Scanner Version</span><strong>{_escape(scan_report.get('scanner_version', 'n/a'))}</strong></div>
  <div><span>Duration</span><strong>{_format_duration(scan.get('duration_seconds'))}</strong></div>
  <div><span>Files Scanned</span><strong>{_format_number(scan.get('files_scanned', 0))}</strong></div>
</section>
<section class="metrics">{card_html}</section>
<section class="grid">
  <div class="panel"><h2>Severity Distribution</h2><canvas id="severityChart"></canvas></div>
  <div class="panel"><h2>Category Distribution</h2><canvas id="categoryChart"></canvas></div>
</section>
<section class="grid">
  <div class="panel"><h2>Top Categories</h2><canvas id="topCategoryChart"></canvas></div>
  <div class="panel"><h2>Top Files</h2><canvas id="topFilesChart"></canvas></div>
</section>
<section class="panel"><h2>Top Affected Files</h2><table><thead><tr><th>File</th><th>Finding Count</th></tr></thead><tbody>{top_files_rows}</tbody></table></section>
<section class="panel"><h2>Top Critical Findings</h2><table><thead><tr><th>Finding ID</th><th>Entity Type</th><th>Location</th><th>Severity</th><th>Recommendation</th></tr></thead><tbody>{critical_rows}</tbody></table></section>
<section class="panel"><h2>Prioritized Actions</h2>{_markdown_to_html(_extract_prioritized_actions(ai_summary))}</section>
<section class="release {release['tone']}"><h2>AI Release Recommendation</h2><h3>{_escape(release['status'])}</h3><p>{_escape(release['reason'])}</p><ul>{actions}</ul></section>
<section class="panel"><h2>Compliance Mapping</h2>{_markdown_to_html(_extract_compliance(ai_summary))}</section>
<script>const reportData = {json.dumps(chart_data)}; renderCharts(reportData);</script>
""",
        )

    def _render_dashboard_html(
        self, scan_report: dict[str, Any], dashboard: dict[str, Any], developer_guidance: str
    ) -> str:
        summary = scan_report.get("summary", {}) or {}
        scan = scan_report.get("scan", {}) or {}
        chart_data = _chart_data(summary, dashboard, scan_report.get("findings", []) or [])
        trend = dashboard.get("trend", {}) if isinstance(dashboard, dict) else {}
        trend_cards = _trend_cards(trend)
        recent_reports = _recent_report_links(self._settings.working_directory)
        return _html_page(
            title="PII Security Dashboard",
            body=f"""
<section class="hero compact">
  <div><p class="eyebrow">Operational Dashboard</p><h1>PII Security Dashboard</h1><p>Status: {_escape(summary.get('pipeline_status', 'UNKNOWN'))}</p></div>
  <div class="scorecard"><span class="badge {_status_class(summary.get('pipeline_status', 'UNKNOWN'))}">{_escape(summary.get('pipeline_status', 'UNKNOWN'))}</span><strong>{_escape(summary.get('risk_score', 0))}</strong><span>Risk Score</span></div>
</section>
<nav class="links"><a href="Executive_Report.html">Open Executive Report</a><a href="../index.html">Back to Index</a></nav>
<section class="metrics">
  <div class="metric"><span>Total Findings</span><strong>{_format_number(summary.get('total_findings', 0))}</strong></div>
  <div class="metric"><span>Risk Score</span><strong>{_format_number(summary.get('risk_score', 0))}</strong></div>
  <div class="metric"><span>Pipeline Status</span><strong>{_escape(summary.get('pipeline_status', 'UNKNOWN'))}</strong></div>
  <div class="metric"><span>Files Scanned</span><strong>{_format_number(scan.get('files_scanned', 0))}</strong></div>
  <div class="metric"><span>Duration</span><strong>{_format_duration(scan.get('duration_seconds'))}</strong></div>
  <div class="metric"><span>Generated</span><strong>{_format_date(scan.get('finished_at') or scan.get('started_at'))}</strong></div>
</section>
<section class="metrics trend">{trend_cards}</section>
<section class="grid">
  <div class="panel"><h2>Severity</h2><canvas id="severityChart"></canvas></div>
  <div class="panel"><h2>Categories</h2><canvas id="categoryChart"></canvas></div>
</section>
<section class="grid">
  <div class="panel"><h2>Top Files</h2><canvas id="topFilesChart"></canvas></div>
  <div class="panel"><h2>Recent Reports</h2>{recent_reports}</div>
</section>
<section class="panel"><h2>Developer Guidance</h2>{_markdown_to_html(developer_guidance)}</section>
<script>const reportData = {json.dumps(chart_data)}; renderCharts(reportData);</script>
""",
        )

    def _render_index_html(self, latest_report: dict[str, Any], latest_dir: Path) -> str:
        reports_root = _reports_root(self._settings.working_directory)
        history_root = reports_root / _HISTORY_DIRECTORY_NAME
        rows = []
        if history_root.is_dir():
            for child in sorted(history_root.iterdir()):
                if child.is_dir():
                    report = _load_scan_report(child / "scan_report.json")
                    summary = report.get("summary", {}) if report else {}
                    scan = report.get("scan", {}) if report else {}
                    rows.append(
                        "<tr>"
                        f"<td>{_escape(child.name.split('_')[1])}</td>"
                        f"<td>{_format_date(scan.get('finished_at') or scan.get('started_at'))}</td>"
                        f"<td><span class=\"badge {_status_class(summary.get('pipeline_status', 'UNKNOWN'))}\">{_escape(summary.get('pipeline_status', 'UNKNOWN'))}</span></td>"
                        f"<td><a href=\"history/{_escape(child.name)}/Executive_Report.html\">Open</a></td>"
                        "</tr>"
                    )
        history_rows = "\n".join(rows) or "<tr><td colspan=\"4\">No historical reports yet.</td></tr>"
        latest_summary = latest_report.get("summary", {}) or {}
        return _html_page(
            title="Report History",
            body=f"""
<section class="hero compact">
  <div><p class="eyebrow">Report History</p><h1>PII Security Reports</h1><p>Latest status: {_escape(latest_summary.get('pipeline_status', 'UNKNOWN'))}</p></div>
  <div class="scorecard"><span class="badge {_status_class(latest_summary.get('pipeline_status', 'UNKNOWN'))}">{_escape(latest_summary.get('pipeline_status', 'UNKNOWN'))}</span><strong>{_format_number(latest_summary.get('risk_score', 0))}</strong><span>Risk Score</span></div>
</section>
<section class="panel"><h2>Latest Report</h2><p><a href="latest/Executive_Report.html">Open Executive Report</a> <a href="latest/Dashboard.html">Open Dashboard</a></p></section>
<section class="panel"><h2>Previous Reports</h2><table><thead><tr><th>Report</th><th>Date</th><th>Status</th><th>Action</th></tr></thead><tbody>{history_rows}</tbody></table></section>
""",
        )


def _extract_recommendations(ai_summary: str) -> list[dict[str, str]]:
    recommendations: list[dict[str, str]] = []
    in_section = False
    for line in ai_summary.splitlines():
        if line.startswith("## Recommendations"):
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if in_section and line.startswith("- **"):
            entity, _, rest = line[4:].partition("**")
            recommendation = rest.split(":", 1)[-1].strip() if ":" in rest else rest.strip()
            recommendations.append({"entity_type": entity, "recommendation": recommendation})
    return recommendations


def _extract_prioritized_actions(ai_summary: str) -> str:
    marker = "## Prioritized Actions"
    if marker not in ai_summary:
        return "No prioritized actions available."
    section = ai_summary.split(marker, 1)[1]
    if "## Compliance Considerations" in section:
        section = section.split("## Compliance Considerations", 1)[0]
    return section.strip()


def _extract_compliance(ai_summary: str) -> str:
    marker = "## Compliance Considerations"
    if marker not in ai_summary:
        return "- OWASP: Sensitive data exposure controls should be reviewed.\n- CWE: Weak data handling patterns should be remediated.\n- Categories: Review detected PII categories against internal policy."
    return ai_summary.split(marker, 1)[1].strip()


def _load_scan_report(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _trend_cards(trend: dict[str, Any]) -> str:
    if not trend.get("trend_available"):
        message = trend.get("message", "No previous report is available for comparison.")
        return f"<div class=\"metric wide\"><span>Trend</span><strong>No Change</strong><small>{_escape(message)}</small></div>"
    labels = [
        ("Previous Findings", trend.get("previous_total_findings", 0)),
        ("Current Findings", trend.get("current_total_findings", 0)),
        ("Difference", trend.get("findings_delta", 0)),
        ("Trend", str(trend.get("findings_trend", "unchanged")).title()),
        ("Previous Risk", trend.get("previous_risk_score", 0)),
        ("Current Risk", trend.get("current_risk_score", 0)),
    ]
    return "\n".join(
        f"<div class=\"metric\"><span>{_escape(label)}</span><strong>{_format_number(value) if isinstance(value, int) else _escape(value)}</strong></div>"
        for label, value in labels
    )


def _recent_report_links(root: Path) -> str:
    history = root / _REPORTS_DIRECTORY_NAME / _HISTORY_DIRECTORY_NAME
    if not history.is_dir():
        return "<p>No previous reports yet.</p>"
    items = []
    for child in sorted(history.iterdir(), reverse=True)[:6]:
        if child.is_dir():
            report = _load_scan_report(child / "scan_report.json")
            status = ((report.get("summary") or {}).get("pipeline_status") or "UNKNOWN")
            items.append(
                f"<li><a href=\"../history/{_escape(child.name)}/Executive_Report.html\">{_escape(child.name)}</a> "
                f"<span class=\"badge {_status_class(status)}\">{_escape(status)}</span></li>"
            )
    return "<ul class=\"report-list\">" + "".join(items) + "</ul>" if items else "<p>No previous reports yet.</p>"


def _chart_data(
    summary: dict[str, Any], dashboard: dict[str, Any], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    severity_counts = summary.get("severity_counts", {}) or {}
    category_counts = dashboard.get("category_counts", {}) if isinstance(dashboard, dict) else {}
    top_files = _top_files(findings)
    top_categories = sorted(
        ((category, count) for category, count in category_counts.items() if count),
        key=lambda item: item[1],
        reverse=True,
    )[:8]
    return {
        "severity": {severity: severity_counts.get(severity, 0) for severity in _SEVERITY_ORDER},
        "categories": category_counts,
        "topCategories": dict(top_categories),
        "topFiles": dict(top_files),
    }


def _html_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_escape(title)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <main>{body}</main>
  <script>{_JS}</script>
</body>
</html>
"""


_CSS = """
:root{--bg:#f4f7fb;--surface:#fff;--ink:#172033;--muted:#637083;--line:#d9e1ec;--accent:#2563eb;--pass:#15803d;--warn:#b45309;--fail:#b91c1c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Arial,sans-serif}main{max-width:1180px;margin:0 auto;padding:28px}
.hero{display:flex;justify-content:space-between;gap:24px;align-items:center;background:linear-gradient(135deg,#152238,#244a77);color:#fff;border-radius:8px;padding:34px;margin-bottom:18px}.hero.compact{padding:26px}.eyebrow{text-transform:uppercase;letter-spacing:.08em;font-size:12px;color:#b9d4ff;margin:0 0 10px}h1{font-size:34px;margin:0 0 10px}h2{margin:0 0 16px;font-size:20px}h3{margin:8px 0 10px}.scorecard{text-align:center;min-width:170px}.scorecard strong{display:block;font-size:54px;line-height:1}.badge{display:inline-block;border-radius:999px;padding:8px 14px;font-weight:700;background:#64748b;color:#fff}.badge.pass,.release.pass h3{background:var(--pass)}.badge.warning,.release.warning h3{background:var(--warn)}.badge.fail,.release.fail h3{background:var(--fail)}
.links{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 18px}.links a,.panel a{color:#1d4ed8;font-weight:700;text-decoration:none}.links a{background:#fff;border:1px solid var(--line);border-radius:8px;padding:10px 12px}.assessment{background:#ecfdf5;border:1px solid #bbf7d0;border-radius:8px;padding:22px;margin-bottom:18px}.assessment p{font-size:17px;line-height:1.55}.meta,.metrics,.grid{display:grid;gap:14px;margin-bottom:18px}.meta{grid-template-columns:repeat(4,1fr)}.metrics{grid-template-columns:repeat(7,1fr)}.metrics.trend{grid-template-columns:repeat(6,1fr)}.grid{grid-template-columns:repeat(2,1fr)}.meta div,.metric,.panel,.release{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:18px;box-shadow:0 1px 2px rgba(15,23,42,.04)}.meta span,.metric span{display:block;color:var(--muted);font-size:13px}.metric strong{font-size:28px}.metric small{display:block;margin-top:8px;color:var(--muted);line-height:1.4}.wide{grid-column:span 2}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}th{font-size:12px;text-transform:uppercase;color:var(--muted)}canvas{width:100%;height:260px}pre{white-space:pre-wrap;background:#f8fafc;border:1px solid var(--line);padding:12px;border-radius:6px}.release h3{display:inline-block;color:#fff;border-radius:6px;padding:8px 12px}.release p{font-size:16px}.report-list{display:grid;gap:10px;padding-left:18px}.report-list .badge{margin-left:8px;padding:4px 8px;font-size:12px}
@media(max-width:850px){main{padding:16px}.hero{display:block}.meta,.metrics,.grid{grid-template-columns:1fr}.scorecard{text-align:left;margin-top:20px}}
"""

_JS = """
function palette(i){return ['#dc2626','#ea580c','#ca8a04','#2563eb','#0891b2','#7c3aed','#16a34a','#64748b'][i%8];}
function drawBar(canvas, data){const ctx=canvas.getContext('2d'), labels=Object.keys(data), vals=Object.values(data);const w=canvas.width=canvas.clientWidth*2,h=canvas.height=canvas.clientHeight*2,max=Math.max(...vals,1);ctx.scale(2,2);ctx.clearRect(0,0,w,h);labels.forEach((label,i)=>{const y=28+i*32,bw=(canvas.clientWidth-170)*(vals[i]/max);ctx.fillStyle=palette(i);ctx.fillRect(140,y,bw,18);ctx.fillStyle='#172033';ctx.font='12px Segoe UI';ctx.fillText(label,8,y+14);ctx.fillText(vals[i],145+bw,y+14);});}
function drawDonut(canvas, data){const ctx=canvas.getContext('2d'), entries=Object.entries(data).filter(([,v])=>v>0);const w=canvas.width=canvas.clientWidth*2,h=canvas.height=canvas.clientHeight*2,cx=w/4,cy=h/4,r=Math.min(cx,cy)-20,total=entries.reduce((s,e)=>s+e[1],0)||1;ctx.scale(2,2);let a=-Math.PI/2;entries.forEach(([label,v],i)=>{const next=a+Math.PI*2*(v/total);ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,a,next);ctx.closePath();ctx.fillStyle=palette(i);ctx.fill();a=next;ctx.fillStyle='#172033';ctx.font='12px Segoe UI';ctx.fillText(label+' '+v,cx+r+24,34+i*20);});ctx.beginPath();ctx.arc(cx,cy,r*.55,0,Math.PI*2);ctx.fillStyle='#fff';ctx.fill();}
function renderCharts(d){const sev=document.getElementById('severityChart'), cat=document.getElementById('categoryChart'), topCat=document.getElementById('topCategoryChart'), topFiles=document.getElementById('topFilesChart');if(sev)drawDonut(sev,d.severity||{});if(cat)drawDonut(cat,d.categories||{});if(topCat)drawBar(topCat,d.topCategories||{});if(topFiles)drawBar(topFiles,d.topFiles||{});}
document.querySelectorAll('a[href="../index.html"]').forEach(a=>{if(location.pathname.includes('/history/'))a.href='../../index.html';});
"""
