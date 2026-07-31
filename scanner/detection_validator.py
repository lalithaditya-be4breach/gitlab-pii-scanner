"""
detection_validator.py
======================

Deterministic validation for raw Presidio recognizer output.

Presidio is intentionally broad: it reports NLP entities that may be
interesting in prose, but are not always actionable PII in source
repositories. This module keeps that broad recognizer recall while
adding repository-aware precision gates before findings enter the
existing report and risk pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


_HIGH_SIGNAL_ENTITIES = frozenset(
    {
        "CREDIT_CARD",
        "CRYPTO",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "US_SSN",
        "US_ITIN",
        "US_PASSPORT",
        "US_BANK_NUMBER",
        "US_DRIVER_LICENSE",
        "UK_NHS",
        "IBAN_CODE",
        "MEDICAL_LICENSE",
        "IN_AADHAAR",
        "IN_PASSPORT",
        "IN_PAN",
        "JWT",
        "API_KEY",
        "PASSWORD",
        "SECRET",
        "PRIVATE_KEY",
    }
)

_NLP_CONTEXT_ENTITIES = frozenset({"PERSON", "ORGANIZATION", "LOCATION", "NRP"})
_LOW_CONTEXT_ENTITIES = frozenset({"DATE_TIME", "URL"})

_DOCUMENTATION_EXTENSIONS = frozenset({".md", ".rst", ".txt", ".adoc"})
_CODE_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".cs",
        ".go",
        ".rb",
        ".php",
        ".rs",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".sh",
        ".ps1",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
    }
)

_DOCUMENTATION_FILE_NAMES = frozenset(
    {
        "authors",
        "changelog",
        "changes",
        "code_of_conduct",
        "contributing",
        "contributors",
        "history",
        "license",
        "news",
        "readme",
        "release_notes",
        "releasenotes",
    }
)

_TEST_PATH_PARTS = frozenset(
    {
        "test",
        "tests",
        "fixture",
        "fixtures",
        "mock",
        "mocks",
        "sample",
        "samples",
        "demo",
        "demos",
        "sandbox",
        "playground",
        "example",
        "examples",
    }
)

_PUBLIC_URL_HOSTS = (
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "docs.github.com",
    "owasp.org",
    "mitre.org",
    "cve.org",
    "python.org",
    "docs.python.org",
    "pypi.org",
    "readthedocs.io",
    "stackoverflow.com",
    "stackexchange.com",
    "microsoft.com",
    "learn.microsoft.com",
    "w3.org",
    "ietf.org",
    "rfc-editor.org",
)

_TECHNOLOGY_TERMS = frozenset(
    {
        "amazon",
        "api",
        "click",
        "docker",
        "flask",
        "framework",
        "git",
        "github",
        "gitlab",
        "html",
        "http",
        "https",
        "json",
        "kubernetes",
        "linux",
        "markdown",
        "parser",
        "python",
        "pypi",
        "pytest",
        "requests",
        "scanner",
        "setuptools",
        "shell",
        "sql",
        "toml",
        "windows",
        "yaml",
    }
)

_PERSON_SUPPORTING_CONTEXT = re.compile(
    r"\b(customer|employee|patient|person|user|account|applicant|beneficiary|"
    r"date of birth|dob|passport|driver'?s license|ssn|tax id|medical record|"
    r"full name|first name|last name)\b",
    re.IGNORECASE,
)
_ORG_SUPPORTING_CONTEXT = re.compile(
    r"\b(customer|client|vendor|supplier|partner|tenant|employer|company|"
    r"organization|account|contract|invoice|billing|internal)\b",
    re.IGNORECASE,
)
_LOCATION_SUPPORTING_CONTEXT = re.compile(
    r"\b(address|street|city|state|zip|postal|resident|residence|shipping|"
    r"billing|customer|patient|employee)\b",
    re.IGNORECASE,
)
_DATE_SUPPORTING_CONTEXT = re.compile(
    r"\b(date of birth|dob|birth date|birthday|born|patient|passport|"
    r"driver'?s license|employee|customer)\b",
    re.IGNORECASE,
)
_PUBLIC_REPO_CONTEXT = re.compile(
    r"\b(thanks|thank you|reported by|contributed by|contributor|contributors|"
    r"author|authors|maintainer|maintainers|pull request|issue|changelog|"
    r"release|released|version|copyright)\b",
    re.IGNORECASE,
)
_CODE_ASSIGNMENT_CONTEXT = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*\s*[:=]|def\s+|class\s+|import\s+|from\s+|"
    r"function\s+|const\s+|let\s+|var\s+",
    re.IGNORECASE,
)
_URL_WITH_SECRET = re.compile(
    r"([?&](token|key|secret|sig|signature|password|pass|access_token)=)|"
    r"//[^/\s:@]+:[^/\s@]+@",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """Context supplied to validation for one raw detection."""

    relative_path: Path
    extension: str
    text: str
    start: int
    end: int
    entity_type: str
    score: float

    @property
    def matched_text(self) -> str:
        return self.text[self.start : self.end]

    @property
    def window(self) -> str:
        return self.text[max(0, self.start - 120) : min(len(self.text), self.end + 120)]

    @property
    def line(self) -> str:
        line_start = self.text.rfind("\n", 0, self.start) + 1
        line_end = self.text.find("\n", self.end)
        if line_end == -1:
            line_end = len(self.text)
        return self.text[line_start:line_end]


class DetectionValidator:
    """Applies deterministic, repository-aware precision rules."""

    def should_keep(self, context: DetectionContext) -> bool:
        entity_type = context.entity_type
        if entity_type in _HIGH_SIGNAL_ENTITIES:
            return True
        if entity_type == "URL":
            return self._is_actionable_url(context)
        if entity_type == "DATE_TIME":
            return self._has_context(_DATE_SUPPORTING_CONTEXT, context)
        if entity_type in _NLP_CONTEXT_ENTITIES:
            return self._is_actionable_nlp_entity(context)
        if entity_type in _LOW_CONTEXT_ENTITIES:
            return False
        return True

    def _is_actionable_nlp_entity(self, context: DetectionContext) -> bool:
        value = context.matched_text.strip()
        if not value or self._looks_like_code_identifier(value):
            return False
        if value.lower() in _TECHNOLOGY_TERMS:
            return False
        if self._is_documentation_context(context) and not self._has_sensitive_context(context):
            return False
        if self._is_public_repository_context(context):
            return False
        if self._is_code_context(context) and not self._has_sensitive_context(context):
            return False
        if self._is_test_context(context) and not self._has_sensitive_context(context):
            return False

        if context.entity_type == "PERSON":
            return self._has_context(_PERSON_SUPPORTING_CONTEXT, context)
        if context.entity_type == "ORGANIZATION":
            return self._has_context(_ORG_SUPPORTING_CONTEXT, context)
        if context.entity_type == "LOCATION":
            return self._has_context(_LOCATION_SUPPORTING_CONTEXT, context)
        return self._has_sensitive_context(context)

    def _is_actionable_url(self, context: DetectionContext) -> bool:
        value = context.matched_text.strip()
        if _URL_WITH_SECRET.search(value):
            return True

        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        if host in {"localhost", "127.0.0.1", "0.0.0.0"}:
            return False
        if host.endswith(".local") or host.endswith(".internal") or host.endswith(".corp"):
            return True
        if any(host == public or host.endswith(f".{public}") for public in _PUBLIC_URL_HOSTS):
            return False
        if self._is_documentation_context(context):
            return False
        return self._has_sensitive_context(context)

    def _is_documentation_context(self, context: DetectionContext) -> bool:
        stem = context.relative_path.stem.lower()
        parts = {part.lower() for part in context.relative_path.parts}
        return (
            context.extension.lower() in _DOCUMENTATION_EXTENSIONS
            or stem in _DOCUMENTATION_FILE_NAMES
            or bool(parts & {"docs", "doc", "documentation"})
        )

    def _is_test_context(self, context: DetectionContext) -> bool:
        parts = {part.lower() for part in context.relative_path.parts}
        return bool(parts & _TEST_PATH_PARTS)

    def _is_code_context(self, context: DetectionContext) -> bool:
        return context.extension.lower() in _CODE_EXTENSIONS and (
            _CODE_ASSIGNMENT_CONTEXT.search(context.line) is not None
            or "`" in context.line
            or context.matched_text in context.relative_path.as_posix()
        )

    def _is_public_repository_context(self, context: DetectionContext) -> bool:
        return (
            _PUBLIC_REPO_CONTEXT.search(context.window) is not None
            or re.search(r"(^|\s)@[-A-Za-z0-9_]+", context.line) is not None
        )

    def _has_sensitive_context(self, context: DetectionContext) -> bool:
        return any(
            pattern.search(context.window)
            for pattern in (
                _PERSON_SUPPORTING_CONTEXT,
                _ORG_SUPPORTING_CONTEXT,
                _LOCATION_SUPPORTING_CONTEXT,
                _DATE_SUPPORTING_CONTEXT,
            )
        )

    def _has_context(self, pattern: re.Pattern[str], context: DetectionContext) -> bool:
        return pattern.search(context.window) is not None

    def _looks_like_code_identifier(self, value: str) -> bool:
        compact = value.strip()
        if re.search(r"[_./\\{}()[\]<>:=]", compact):
            return True
        if compact.isupper() and len(compact) > 1:
            return True
        if re.fullmatch(r"[a-z]+[A-Z][A-Za-z0-9]*", compact):
            return True
        if re.fullmatch(r"[A-Z][A-Za-z0-9]+(?:[A-Z][a-z0-9]+)+", compact):
            return True
        return False
