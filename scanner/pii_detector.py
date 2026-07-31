"""
pii_detector.py
================

Phase 3: Microsoft Presidio integration.

Wraps a `presidio_analyzer.AnalyzerEngine` and turns the raw text of a
`ScannedFile` into a list of `PIIFinding` objects. This is the only
module in the project that imports `presidio_analyzer` directly, so
later phases (and tests) can depend on `PIIDetector`'s small interface
instead of Presidio's API directly.

Nothing here touches the filesystem or does traversal — that is
`file_scanner.py`'s job. Nothing here reaches into the vendored
`presidio/` reference repository either; Presidio is consumed purely
as the installed `presidio-analyzer` package, per the project's
design principles.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List

from scanner.config import ScannerSettings
from scanner.logger import get_logger
from scanner.detection_validator import DetectionContext, DetectionValidator
from scanner.models import PIIFinding, ScannedFile, Severity

if TYPE_CHECKING:  # pragma: no cover - import only used for type hints
    from presidio_analyzer import AnalyzerEngine

logger = get_logger(__name__)


class PIIDetectorError(Exception):
    """Raised when the Presidio analyzer engine cannot be created or used."""


# ---------------------------------------------------------------------------
# Entity -> Severity mapping.
#
# Presidio's default recognizers return dozens of entity types. Rather
# than hardcode severity deep inside the analysis loop, findings are
# classified here so the mapping is easy to see and adjust in one
# place. Anything not explicitly listed defaults to Severity.MEDIUM.
# ---------------------------------------------------------------------------
_CRITICAL_SEVERITY_ENTITIES = frozenset(
    {
        "CREDIT_CARD",
        "CRYPTO",
        "US_SSN",
        "US_ITIN",
        "US_PASSPORT",
        "US_BANK_NUMBER",
        "UK_NHS",
        "IBAN_CODE",
        "MEDICAL_LICENSE",
        "IN_AADHAAR",
        "IN_PASSPORT",
    }
)
_HIGH_SEVERITY_ENTITIES = frozenset(
    {
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "IP_ADDRESS",
        "PERSON",
        "LOCATION",
        "US_DRIVER_LICENSE",
    }
)
_LOW_SEVERITY_ENTITIES = frozenset(
    {
        "URL",
        "DATE_TIME",
        "NRP",
    }
)


def _severity_for_entity(entity_type: str) -> Severity:
    """Classify a Presidio entity type into a project `Severity`."""
    if entity_type in _CRITICAL_SEVERITY_ENTITIES:
        return Severity.CRITICAL
    if entity_type in _HIGH_SEVERITY_ENTITIES:
        return Severity.HIGH
    if entity_type in _LOW_SEVERITY_ENTITIES:
        return Severity.LOW
    return Severity.MEDIUM


def _line_number_for_offset(text: str, offset: int) -> int | None:
    """Translate a character offset in `text` into a 1-based line number."""
    if offset < 0 or offset > len(text):
        return None
    return text.count("\n", 0, offset) + 1


class PIIDetector:
    """
    Project-specific wrapper around Presidio's `AnalyzerEngine`.

    The underlying engine is expensive to construct (it loads an NLP
    model), so a `PIIDetector` is meant to be created once per scan run
    and reused across every file, not per-file.
    """

    def __init__(
        self,
        settings: ScannerSettings,
        analyzer_engine: "AnalyzerEngine | None" = None,
        detection_validator: DetectionValidator | None = None,
    ) -> None:
        """
        Args:
            settings: Application settings (language, confidence threshold,
                spaCy model to load).
            analyzer_engine: Optional pre-built `AnalyzerEngine`. Tests
                inject a fake/stub here to avoid loading a real NLP
                model; production code lets this build the default engine.
            detection_validator: Optional validation pipeline for raw
                recognizer output. Tests may inject one; production uses
                the deterministic repository-aware validator.
        """
        self._settings = settings
        self._engine = analyzer_engine or self._build_default_engine(settings)
        self._validator = detection_validator or DetectionValidator()

    @staticmethod
    def _build_default_engine(settings: ScannerSettings) -> "AnalyzerEngine":
        """Construct the default spaCy-backed `AnalyzerEngine` for `settings`."""
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
        except ImportError as exc:
            raise PIIDetectorError(
                "presidio-analyzer is not installed. Install Phase 3's "
                "dependencies with `pip install -r requirements.txt`."
            ) from exc

        nlp_configuration = {
            "nlp_engine_name": "spacy",
            "models": [
                {
                    "lang_code": settings.presidio_language,
                    "model_name": settings.presidio_spacy_model,
                }
            ],
        }

        try:
            nlp_engine = NlpEngineProvider(nlp_configuration=nlp_configuration).create_engine()
            return AnalyzerEngine(
                nlp_engine=nlp_engine,
                supported_languages=[settings.presidio_language],
                default_score_threshold=settings.presidio_min_confidence,
            )
        except OSError as exc:
            # Raised by spaCy when the model isn't downloaded yet.
            raise PIIDetectorError(
                f"Could not load spaCy model {settings.presidio_spacy_model!r}. "
                f"Download it with: python -m spacy download "
                f"{settings.presidio_spacy_model}"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - surface any other init failure clearly
            raise PIIDetectorError(
                f"Failed to initialize Presidio's AnalyzerEngine: {exc}"
            ) from exc

    def analyze_file(self, scanned_file: ScannedFile, text: str) -> List[PIIFinding]:
        """
        Run Presidio analysis over a single file's text content.

        Args:
            scanned_file: Metadata for the file `text` was read from.
            text: The file's decoded text content.

        Returns:
            A list of `PIIFinding` objects, one per detected entity that
            meets `presidio_min_confidence`. Analysis failures for a
            single file are logged and treated as "no findings" rather
            than aborting the whole scan.
        """
        if not text:
            return []

        try:
            results = self._engine.analyze(
                text=text,
                language=self._settings.presidio_language,
                score_threshold=self._settings.presidio_min_confidence,
            )
        except Exception as exc:  # noqa: BLE001 - one bad file must not abort the scan
            logger.warning(
                "Presidio analysis failed for %s: %s", scanned_file.absolute_path, exc
            )
            return []

        findings: List[PIIFinding] = []
        for result in results:
            if result.score < self._settings.presidio_min_confidence:
                continue
            context = DetectionContext(
                relative_path=scanned_file.relative_path,
                extension=scanned_file.extension,
                text=text,
                start=result.start,
                end=result.end,
                entity_type=result.entity_type,
                score=result.score,
            )
            if not self._validator.should_keep(context):
                continue
            findings.append(
                PIIFinding(
                    file=scanned_file,
                    entity_type=result.entity_type,
                    matched_text=text[result.start : result.end],
                    line_number=_line_number_for_offset(text, result.start),
                    confidence_score=result.score,
                    severity=_severity_for_entity(result.entity_type),
                )
            )

        if findings:
            logger.info(
                "%d PII finding(s) in %s", len(findings), scanned_file.relative_path
            )

        return findings
