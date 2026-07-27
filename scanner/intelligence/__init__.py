"""
scanner.intelligence
====================

Task 2, Phase 4: the AI-Assisted DevSecOps Intelligence Layer.

This package sits strictly *after* the existing, unchanged pipeline:

    RepositoryManager -> ScanEngine -> RiskEngine -> ReportGenerator -> AIAssistant -> [scanner.intelligence]

Everything in this package is read-only with respect to the scan: it
consumes the structured JSON report already produced by
`scanner.report_generator.ReportGenerator` (the same report
`scanner.ai.AIAssistant` and `ci/evaluate_gate.py` consume) and never
re-runs Presidio, recomputes a risk score, or changes a finding,
severity, or `pipeline_status`.

Where Phase 2's `scanner.ai` package answers "what was found and how
severe is it", Phase 4 answers the next four questions a developer or
security reviewer actually asks:

    WHY   was this flagged?           -> root_cause.py
    WHERE does it live, concretely?   -> root_cause.py (file/line, from the report)
    HOW   do I fix it?                -> remediation.py
    HOW   do I prevent it recurring?  -> remediation.py (secure coding references)

Modules
-------
    finding_ids.py    : Deterministic, positional IDs for findings
                         within a single report (the report schema
                         itself is never changed to add an ID field).
    categories.py      : Groups Presidio entity types into
                         business-facing risk categories (Secrets,
                         Personal Information, Financial Data, ...).
    root_cause.py      : `RootCauseEngine` -- why a finding was
                         detected, the likely developer mistake, and
                         the security impact, per finding.
    remediation.py     : `RemediationEngine` -- deterministic fix
                         recommendations plus OWASP/CWE mappings, per
                         entity type. Reuses
                         `scanner.ai.recommendations` rather than
                         duplicating its entity -> advice table.
    trend.py           : `TrendAnalyzer` -- compares the current
                         report against the previous run's report
                         (stored automatically under
                         `<output_dir>/intelligence/`) and degrades
                         gracefully when no previous report exists.
    guidance.py        : `DeveloperGuidanceReportBuilder` -- renders
                         `developer-guidance.md`, a report distinct
                         from Phase 2's `ai-summary.md`.
    dashboard.py       : `DashboardBuilder` -- renders `dashboard.json`,
                         a backend-only data file for a future
                         frontend dashboard.
    api.py             : `ExplainService` + an optional, dependency-free
                         `/api/explain` HTTP endpoint that answers
                         questions about a single already-detected
                         finding. Never re-runs the scanner.
    orchestrator.py    : `IntelligenceEngine`, the single integration
                         point `main.py` calls. Ties the modules above
                         together and never raises -- any failure here
                         is logged and degrades gracefully, exactly
                         like `scanner.ai.AIAssistant`.

Nothing in this package can cause the scanner to exit non-zero, change
`ci/evaluate_gate.py`'s decision, or alter the JSON report schema.
"""

from __future__ import annotations

from scanner.intelligence.orchestrator import IntelligenceEngine

__all__ = ["IntelligenceEngine"]
