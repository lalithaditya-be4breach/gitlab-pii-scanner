"""
ai_assistant.py
================

Task 2, Phase 2: `AIAssistant`, the final layer of the pipeline.

    RepositoryManager -> ScanEngine -> RiskEngine -> ReportGenerator -> AIAssistant

`AIAssistant` consumes only the JSON report dict produced by
`scanner.report_generator.ReportGenerator` (see Task 2, Phase 1). It
never imports or calls Presidio, the risk engine, or scanner
internals directly, and it never changes a finding, a severity, a
risk score, or a pipeline status.

Failure handling
-----------------
Per the project's requirements, an AI failure must never terminate a
scan. `generate_summary()` therefore never raises: a missing report, a
malformed report, a missing API key, a provider timeout, an invalid
response, or an unknown provider all result in a deterministic
fallback Markdown summary rather than an exception reaching `main.py`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.ai.markdown_generator import MarkdownReportGenerator
from scanner.ai.prompt_builder import PromptBuilder
from scanner.ai.providers import (
    AIProvider,
    AIProviderError,
    NullAIProvider,
    get_provider,
    is_null_provider_name,
)
from scanner.ai.recommendations import build_recommendations
from scanner.config import ScannerSettings
from scanner.logger import get_logger
from scanner.utils import ensure_directory

logger = get_logger(__name__)


def _is_valid_report(report: Any) -> bool:
    """Return True if `report` looks like a Task 2 Phase 1 report dict."""
    return (
        isinstance(report, dict)
        and isinstance(report.get("summary"), dict)
        and bool(report.get("summary"))
        and isinstance(report.get("findings"), list)
    )


class AIAssistant:
    """
    Orchestrates the AI Assistant layer: builds a prompt from a JSON
    report, calls a replaceable `AIProvider`, and always produces a
    Markdown summary — falling back deterministically whenever AI is
    disabled, misconfigured, or unavailable.
    """

    def __init__(
        self,
        settings: ScannerSettings,
        provider: AIProvider | None = None,
    ) -> None:
        """
        Args:
            settings: Application settings (see `ai_enabled`,
                `ai_provider`, and related fields in `scanner.config`).
            provider: Optional explicit `AIProvider` (defaults to the
                provider selected by `settings.ai_provider`). Injectable
                for tests so a fake provider can stand in for a real
                LLM call.
        """
        self._settings = settings
        self._provider_injected = provider is not None
        if provider is not None:
            self._provider = provider
        elif not settings.ai_enabled:
            self._provider = NullAIProvider()
        else:
            try:
                self._provider = get_provider(settings)
            except AIProviderError as exc:
                logger.warning(
                    "Could not initialize AI provider %r, falling back to the "
                    "deterministic summary: %s",
                    settings.ai_provider,
                    exc,
                )
                self._provider = NullAIProvider()

    def generate_summary(self, report: dict[str, Any] | None) -> str:
        """
        Build the Markdown AI summary for `report`.

        Args:
            report: A Task 2 Phase 1 JSON report dict, as produced by
                `ReportGenerator.build_report()`. May be `None` or
                malformed (e.g. missing required keys) — this is
                handled gracefully rather than raising.

        Returns:
            The complete Markdown document. This method never raises:
            any failure (missing/invalid report, AI provider failure)
            results in a deterministic fallback summary instead.
        """
        if not _is_valid_report(report):
            if report is not None:
                logger.warning(
                    "AI assistant received a missing or malformed report; "
                    "generating a fallback summary instead."
                )
            report = {}

        recommendations = build_recommendations(report.get("findings", []))

        narrative: str | None = None
        should_call_provider = (
            self._settings.ai_enabled
            and report
            and (
                self._provider_injected
                or not is_null_provider_name(self._settings.ai_provider)
            )
        )
        if should_call_provider:
            try:
                prompt = PromptBuilder.build(report)
                narrative = self._provider.generate(prompt)
            except AIProviderError as exc:
                logger.warning(
                    "AI summary generation failed, using the deterministic "
                    "fallback executive summary: %s",
                    exc,
                )
                narrative = None
            except Exception as exc:  # noqa: BLE001 - AI must never abort the scan
                logger.warning(
                    "Unexpected AI provider failure, using the deterministic "
                    "fallback executive summary: %s",
                    exc,
                )
                narrative = None

        return MarkdownReportGenerator().generate(report, narrative, recommendations)

    @staticmethod
    def _validate_summary_filename(filename: str) -> str:
        """
        Return a safe basename for the Markdown summary file.

        Raises:
            ValueError: if `filename` would escape the output directory
                or is otherwise unsafe.
        """
        if not filename or not filename.strip():
            raise ValueError("AI summary filename must not be empty.")

        name = filename.strip()
        if ".." in name:
            raise ValueError(f"AI summary filename must not contain '..': {filename!r}")
        if name != Path(name).name:
            raise ValueError(
                f"AI summary filename must be a single file name, not a path: {filename!r}"
            )
        if Path(name).is_absolute():
            raise ValueError(f"AI summary filename must not be an absolute path: {filename!r}")

        return name

    def write_markdown_report(self, markdown: str) -> Path:
        """
        Write `markdown` to the canonical latest report directory.

        Args:
            markdown: The Markdown document, as returned by
                `generate_summary()`.

        Returns:
            The path the summary was written to (does not overwrite
            the JSON report produced by `ReportGenerator`).
        """
        output_directory = ensure_directory(
            self._settings.working_directory / "reports" / "latest"
        )
        self._validate_summary_filename(self._settings.ai_summary_filename)
        safe_name = "AI_Summary.md"
        summary_path = (output_directory / safe_name).resolve()
        if not summary_path.is_relative_to(output_directory.resolve()):
            raise ValueError(
                f"AI summary path must stay under the output directory: {summary_path}"
            )
        summary_path.write_text(markdown, encoding="utf-8")
        logger.info("AI summary written to %s", summary_path)
        return summary_path

    def generate(self, report: dict[str, Any] | None) -> tuple[str, Path]:
        """
        Build and write the Markdown AI summary in one step.

        Args:
            report: A Task 2 Phase 1 JSON report dict (see
                `generate_summary()` for handling of missing/invalid
                input).

        Returns:
            A `(markdown, summary_path)` tuple.
        """
        markdown = self.generate_summary(report)
        summary_path = self.write_markdown_report(markdown)
        return markdown, summary_path
