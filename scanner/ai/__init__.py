"""
scanner.ai
==========

Task 2, Phase 2: the AI Assistant layer.

This package sits strictly *after* the Task 2 Phase 1 pipeline:

    RepositoryManager -> ScanEngine -> RiskEngine -> ReportGenerator -> AIAssistant

It consumes only the structured JSON report produced by
`scanner.report_generator.ReportGenerator` — it never touches Presidio,
the risk engine, or scanner internals directly.

Architectural rule (see README "Design principles"): **AI never makes
security decisions.**
    - Presidio detects.
    - RiskEngine decides (pass/warning/fail, risk score).
    - AIAssistant explains — it produces human-readable Markdown
      (executive summary, recommendations, prioritized actions) but
      never changes a finding, a severity, a risk score, or the
      pipeline status.

Modules:
    - providers.py         : Replaceable `AIProvider` abstraction
                              (Null/Azure OpenAI/OpenAI), each raising
                              `AIProviderError` on any failure so the
                              caller can fall back deterministically.
    - recommendations.py    : Deterministic entity-type -> remediation
                              advice mapping, sorted by severity.
    - prompt_builder.py     : Single location that turns a JSON report
                              into the prompt sent to an AI provider.
    - markdown_generator.py : Turns a JSON report (+ optional AI
                              narrative text) into the final Markdown
                              summary. Every fact (risk score, status,
                              findings, recommendations) is derived
                              directly from the report — only the
                              narrative prose can come from AI.
    - ai_assistant.py       : `AIAssistant`, the orchestrator used by
                              `main.py`. Never raises: any failure
                              anywhere in this package results in a
                              deterministic fallback summary instead of
                              aborting the scan.

Nothing in this package can cause the scanner to exit non-zero; AI
failures are logged and degrade gracefully (see `ai_assistant.py`).
"""

from __future__ import annotations

from scanner.ai.ai_assistant import AIAssistant

__all__ = ["AIAssistant"]
