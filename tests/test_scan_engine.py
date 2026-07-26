"""
test_scan_engine.py
====================

Tests for Phase 3's `ScanEngine`, which orchestrates `FileScanner` and
`PIIDetector`. Both collaborators are faked here so this suite tests
only the orchestration logic (counts, findings aggregation, summary
timing) without touching the filesystem or a real Presidio engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, List, Tuple

import pytest

from scanner.config import ScannerSettings
from scanner.models import (
    PIIFinding,
    RepositorySource,
    RepositorySourceType,
    ScannedFile,
    Severity,
)
from scanner.scan_engine import ScanEngine


def _build_test_settings(tmp_path: Path) -> ScannerSettings:
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
        report_redaction_enabled=True,
    )


def _scanned_file(tmp_path: Path, name: str) -> ScannedFile:
    return ScannedFile(
        absolute_path=tmp_path / name,
        relative_path=Path(name),
        size_bytes=10,
        extension=".py",
    )


class _FakeFileScanner:
    """Stand-in for FileScanner yielding pre-scripted (file, text) pairs."""

    def __init__(self, pairs: List[Tuple[ScannedFile, str]], skipped_count: int = 0) -> None:
        self._pairs = pairs
        self.skipped_count = skipped_count
        self.received_roots: List[Path] = []

    def iter_files_with_content(self, root: Path) -> Iterator[Tuple[ScannedFile, str]]:
        self.received_roots.append(root)
        yield from self._pairs


class _FakePIIDetector:
    """Stand-in for PIIDetector returning pre-scripted findings per file."""

    def __init__(self, findings_by_file_name: dict[str, List[PIIFinding]]) -> None:
        self._findings_by_file_name = findings_by_file_name
        self.analyzed_files: List[str] = []

    def analyze_file(self, scanned_file: ScannedFile, text: str) -> List[PIIFinding]:
        self.analyzed_files.append(scanned_file.absolute_path.name)
        return self._findings_by_file_name.get(scanned_file.absolute_path.name, [])


def _repository_source(tmp_path: Path) -> RepositorySource:
    return RepositorySource(
        source_type=RepositorySourceType.LOCAL_PATH,
        identifier=str(tmp_path),
        local_path=tmp_path,
    )


def _finding(scanned_file: ScannedFile, entity_type: str = "EMAIL_ADDRESS") -> PIIFinding:
    return PIIFinding(
        file=scanned_file,
        entity_type=entity_type,
        matched_text="someone@example.com",
        line_number=1,
        confidence_score=0.9,
        severity=Severity.HIGH,
    )


def test_scan_aggregates_findings_across_files(tmp_path: Path) -> None:
    """Findings from every scanned file are collected into one ScanSummary."""
    file_a = _scanned_file(tmp_path, "a.py")
    file_b = _scanned_file(tmp_path, "b.py")

    fake_scanner = _FakeFileScanner(pairs=[(file_a, "text a"), (file_b, "text b")])
    fake_detector = _FakePIIDetector(
        findings_by_file_name={
            "a.py": [_finding(file_a)],
            "b.py": [_finding(file_b), _finding(file_b, entity_type="PHONE_NUMBER")],
        }
    )

    settings = _build_test_settings(tmp_path)
    engine = ScanEngine(settings=settings, file_scanner=fake_scanner, pii_detector=fake_detector)

    summary = engine.scan(_repository_source(tmp_path))

    assert summary.files_scanned == 2
    assert summary.total_findings == 3
    assert fake_detector.analyzed_files == ["a.py", "b.py"]


def test_scan_reports_skipped_file_count_from_file_scanner(tmp_path: Path) -> None:
    """files_skipped comes from the FileScanner's skipped_count after traversal."""
    fake_scanner = _FakeFileScanner(pairs=[], skipped_count=4)
    fake_detector = _FakePIIDetector(findings_by_file_name={})

    settings = _build_test_settings(tmp_path)
    engine = ScanEngine(settings=settings, file_scanner=fake_scanner, pii_detector=fake_detector)

    summary = engine.scan(_repository_source(tmp_path))

    assert summary.files_scanned == 0
    assert summary.files_skipped == 4
    assert summary.total_findings == 0


def test_scan_sets_started_and_finished_timestamps(tmp_path: Path) -> None:
    """The resulting ScanSummary has both timestamps set, with finished >= started."""
    fake_scanner = _FakeFileScanner(pairs=[])
    fake_detector = _FakePIIDetector(findings_by_file_name={})

    settings = _build_test_settings(tmp_path)
    engine = ScanEngine(settings=settings, file_scanner=fake_scanner, pii_detector=fake_detector)

    summary = engine.scan(_repository_source(tmp_path))

    assert summary.started_at is not None
    assert summary.finished_at is not None
    assert summary.finished_at >= summary.started_at
    assert summary.duration_seconds is not None
    assert summary.duration_seconds >= 0.0


def test_scan_passes_repository_local_path_to_file_scanner(tmp_path: Path) -> None:
    """ScanEngine traverses the repository at source.local_path, not somewhere else."""
    fake_scanner = _FakeFileScanner(pairs=[])
    fake_detector = _FakePIIDetector(findings_by_file_name={})

    settings = _build_test_settings(tmp_path)
    engine = ScanEngine(settings=settings, file_scanner=fake_scanner, pii_detector=fake_detector)
    source = _repository_source(tmp_path)

    engine.scan(source)

    assert fake_scanner.received_roots == [source.local_path]
