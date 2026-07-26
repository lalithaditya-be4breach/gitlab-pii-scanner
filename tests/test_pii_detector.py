"""
test_pii_detector.py
=====================

Tests for Phase 3's `PIIDetector`.

These tests inject a fake `AnalyzerEngine` stand-in rather than
loading a real Presidio/spaCy pipeline, so the suite stays fast and
runs fully offline without requiring `en_core_web_lg` to be
downloaded. The real Presidio integration (constructing the default
engine) is exercised separately, and skipped automatically if
presidio-analyzer/spaCy or the configured model aren't installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

import pytest

from scanner.config import ScannerSettings
from scanner.models import ScannedFile, Severity
from scanner.pii_detector import PIIDetector, PIIDetectorError


def _build_test_settings(
    tmp_path: Path,
    *,
    presidio_min_confidence: float = 0.5,
) -> ScannerSettings:
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
        presidio_min_confidence=presidio_min_confidence,
        presidio_spacy_model="en_core_web_lg",
        clone_base_directory=output_directory / "cloned_repositories",
        clone_shallow_depth=1,
        risk_warning_threshold=20,
        risk_fail_threshold=50,
        report_output_directory=output_directory / "reports",
        report_redaction_enabled=True,
    )


@dataclass
class _FakeResult:
    """Stand-in for `presidio_analyzer.RecognizerResult`."""

    entity_type: str
    start: int
    end: int
    score: float


class _FakeAnalyzerEngine:
    """Stand-in for `presidio_analyzer.AnalyzerEngine` with scripted results."""

    def __init__(self, results: List[_FakeResult]) -> None:
        self._results = results
        self.last_call_kwargs: dict | None = None

    def analyze(self, **kwargs) -> List[_FakeResult]:
        self.last_call_kwargs = kwargs
        return self._results


class _ExplodingAnalyzerEngine:
    """Stand-in that always raises, to test failure isolation."""

    def analyze(self, **kwargs) -> List[_FakeResult]:
        raise RuntimeError("boom")


def _scanned_file(tmp_path: Path, name: str = "app.py") -> ScannedFile:
    path = tmp_path / name
    return ScannedFile(
        absolute_path=path,
        relative_path=Path(name),
        size_bytes=0,
        extension=".py",
    )


def test_analyze_file_returns_findings_above_threshold(tmp_path: Path) -> None:
    """Results at or above the confidence threshold become PIIFindings."""
    text = "contact me at someone@example.com please"
    start = text.index("someone@example.com")
    end = start + len("someone@example.com")

    fake_engine = _FakeAnalyzerEngine(
        [_FakeResult(entity_type="EMAIL_ADDRESS", start=start, end=end, score=0.85)]
    )
    settings = _build_test_settings(tmp_path)
    detector = PIIDetector(settings=settings, analyzer_engine=fake_engine)

    findings = detector.analyze_file(_scanned_file(tmp_path), text)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.entity_type == "EMAIL_ADDRESS"
    assert finding.matched_text == "someone@example.com"
    assert finding.confidence_score == 0.85
    assert finding.severity == Severity.HIGH


def test_analyze_file_filters_results_below_threshold(tmp_path: Path) -> None:
    """Results below presidio_min_confidence are dropped, even if the engine returns them."""
    text = "maybe an email x@y.z"
    fake_engine = _FakeAnalyzerEngine(
        [_FakeResult(entity_type="EMAIL_ADDRESS", start=13, end=18, score=0.2)]
    )
    settings = _build_test_settings(tmp_path, presidio_min_confidence=0.5)
    detector = PIIDetector(settings=settings, analyzer_engine=fake_engine)

    findings = detector.analyze_file(_scanned_file(tmp_path), text)

    assert findings == []


def test_analyze_file_computes_line_numbers(tmp_path: Path) -> None:
    """A finding on a later line gets the correct 1-based line number."""
    text = "line one\nline two\nssn is 123-45-6789\n"
    start = text.index("123-45-6789")
    end = start + len("123-45-6789")

    fake_engine = _FakeAnalyzerEngine(
        [_FakeResult(entity_type="US_SSN", start=start, end=end, score=0.9)]
    )
    settings = _build_test_settings(tmp_path)
    detector = PIIDetector(settings=settings, analyzer_engine=fake_engine)

    findings = detector.analyze_file(_scanned_file(tmp_path), text)

    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].severity == Severity.CRITICAL


def test_analyze_file_returns_empty_list_for_empty_text(tmp_path: Path) -> None:
    """Empty file content short-circuits without calling the engine."""
    fake_engine = _FakeAnalyzerEngine([_FakeResult("PERSON", 0, 1, 0.9)])
    settings = _build_test_settings(tmp_path)
    detector = PIIDetector(settings=settings, analyzer_engine=fake_engine)

    findings = detector.analyze_file(_scanned_file(tmp_path), "")

    assert findings == []
    assert fake_engine.last_call_kwargs is None


def test_analyze_file_returns_empty_list_when_engine_raises(tmp_path: Path) -> None:
    """A single file's analysis failure is swallowed, not propagated."""
    settings = _build_test_settings(tmp_path)
    detector = PIIDetector(settings=settings, analyzer_engine=_ExplodingAnalyzerEngine())

    findings = detector.analyze_file(_scanned_file(tmp_path), "some text")

    assert findings == []


def test_unknown_entity_type_defaults_to_medium_severity(tmp_path: Path) -> None:
    """Entity types not in any severity set default to MEDIUM."""
    text = "some organization ACME_CORP appears here"
    fake_engine = _FakeAnalyzerEngine(
        [_FakeResult(entity_type="ORGANIZATION", start=0, end=4, score=0.9)]
    )
    settings = _build_test_settings(tmp_path)
    detector = PIIDetector(settings=settings, analyzer_engine=fake_engine)

    findings = detector.analyze_file(_scanned_file(tmp_path), text)

    assert findings[0].severity == Severity.MEDIUM


def test_missing_presidio_analyzer_raises_pii_detector_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If presidio-analyzer isn't importable, engine construction fails clearly."""
    import builtins

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "presidio_analyzer" or name.startswith("presidio_analyzer."):
            raise ImportError("simulated: presidio_analyzer not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    with pytest.raises(PIIDetectorError):
        PIIDetector(settings=_build_test_settings(tmp_path))
