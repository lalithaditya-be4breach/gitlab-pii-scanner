"""
models.py
=========

Typed data structures shared across the GitLab PII Scanner project.

Phase 1 only defines the *shape* of the data the project will work
with. No scanning, cloning, or Presidio logic exists yet — those will
populate these models in later phases. Defining them now means the
project's structure will not need to change as functionality is added.

All models are immutable dataclasses (`frozen=True`) unless they are
explicitly meant to be accumulated into (e.g. `ScanSummary`), which
keeps data flow predictable and easy to reason about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """Severity classification for a detected finding."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PipelineStatus(str, Enum):
    """
    Deterministic repository-level outcome produced by the Risk Engine
    (Task 2, Phase 1). This is the single value a future Azure DevOps
    pipeline gate reads to decide whether a build passes.
    """

    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"


class RepositorySourceType(str, Enum):
    """Where the scanned code originated from."""

    LOCAL_PATH = "LOCAL_PATH"
    GITLAB_REMOTE = "GITLAB_REMOTE"


@dataclass(frozen=True, slots=True)
class RepositorySource:
    """
    Describes where the code being scanned came from.

    This will be populated by the future `git.py` module when cloning
    a GitLab repository. For local testing (Phase 1), a scan can also
    point directly at a `LOCAL_PATH`.
    """

    source_type: RepositorySourceType
    identifier: str  # e.g. a GitLab URL, or an absolute local path
    local_path: Path
    resolved_at: datetime = field(default_factory=datetime.utcnow)


@dataclass(frozen=True, slots=True)
class ScannedFile:
    """A single source file that was (or will be) inspected."""

    absolute_path: Path
    relative_path: Path
    size_bytes: int
    extension: str


@dataclass(frozen=True, slots=True)
class PIIFinding:
    """
    A single piece of PII detected inside a file.

    Populated by the future Presidio integration. Fields intentionally
    mirror the shape of a Presidio `RecognizerResult`, plus the extra
    source-location context (file, line) needed to make the finding
    actionable for a developer.
    """

    file: ScannedFile
    entity_type: str  # e.g. "EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER"
    matched_text: str  # the raw or masked matched value
    line_number: int | None
    confidence_score: float
    severity: Severity


@dataclass(slots=True)
class ScanSummary:
    """
    Aggregated results for a completed scan run.

    Unlike the other models, this one is mutable (`frozen=False`) by
    design: it is built up incrementally as files are processed in a
    later phase, then handed to the report generator.
    """

    source: RepositorySource
    started_at: datetime
    finished_at: datetime | None = None
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[PIIFinding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        """Total number of PII findings across all scanned files."""
        return len(self.findings)

    @property
    def findings_by_severity(self) -> dict[Severity, int]:
        """Count of findings grouped by severity level."""
        counts: dict[Severity, int] = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def duration_seconds(self) -> float | None:
        """How long the scan took, in seconds, or None if still running."""
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """
    Deterministic, repeatable risk output for a completed `ScanSummary`.

    Produced by `scanner.risk_engine.RiskEngine`. Contains no AI or
    machine-learning output by design (see Task 2, Phase 1): the same
    severity counts and thresholds always produce the same result.
    """

    risk_score: int
    status: PipelineStatus
    severity_counts: dict[Severity, int]
    warning_threshold: int
    fail_threshold: int
