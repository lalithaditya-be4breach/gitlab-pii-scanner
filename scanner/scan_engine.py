"""
scan_engine.py
===============

Phase 3: ties file traversal (`FileScanner`) and PII detection
(`PIIDetector`) together into a single scan run.

This mirrors the shape of `RepositoryManager` from Phase 2: a small,
stateless-aside-from-configuration class with one main entry point
(`scan()`) that downstream code (currently `main.py`, later the
Phase 4 report generator) depends on instead of reaching into file
traversal or Presidio directly.
"""

from __future__ import annotations

from scanner.config import ScannerSettings
from scanner.file_scanner import FileScanner
from scanner.logger import get_logger
from scanner.models import RepositorySource, ScanSummary
from scanner.pii_detector import PIIDetector
from scanner.utils import utc_now

logger = get_logger(__name__)


class ScanEngine:
    """
    Runs a full scan of a `RepositorySource`: traversal + PII detection.
    """

    def __init__(
        self,
        settings: ScannerSettings,
        file_scanner: FileScanner | None = None,
        pii_detector: PIIDetector | None = None,
    ) -> None:
        """
        Args:
            settings: Application settings.
            file_scanner: Optional explicit `FileScanner` (defaults to a
                new instance bound to `settings`). Injectable for tests.
            pii_detector: Optional explicit `PIIDetector` (defaults to a
                new instance bound to `settings`, which loads a real
                Presidio/spaCy engine). Injectable for tests so a fake
                detector can stand in for the real NLP model.
        """
        self._settings = settings
        self._file_scanner = file_scanner or FileScanner(settings)
        self._pii_detector = pii_detector or PIIDetector(settings)

    def scan(self, source: RepositorySource) -> ScanSummary:
        """
        Scan every in-scope file under `source.local_path` for PII.

        Args:
            source: The repository to scan, as obtained from
                `RepositoryManager` (Phase 2).

        Returns:
            A `ScanSummary` with `files_scanned`, `files_skipped`, and
            every `PIIFinding` collected across the run.
        """
        logger.info("Starting scan of %s", source.local_path)
        summary = ScanSummary(source=source, started_at=utc_now())

        for scanned_file, text in self._file_scanner.iter_files_with_content(
            source.local_path
        ):
            summary.files_scanned += 1
            summary.findings.extend(self._pii_detector.analyze_file(scanned_file, text))

        summary.files_skipped = self._file_scanner.skipped_count
        summary.finished_at = utc_now()

        logger.info(
            "Scan complete: %d file(s) scanned, %d skipped, %d finding(s) "
            "in %.2fs",
            summary.files_scanned,
            summary.files_skipped,
            summary.total_findings,
            summary.duration_seconds or 0.0,
        )
        return summary
