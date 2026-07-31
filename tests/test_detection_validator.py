from __future__ import annotations

from pathlib import Path

from scanner.detection_validator import DetectionContext, DetectionValidator


def _context(
    text: str,
    match: str,
    *,
    entity_type: str,
    path: str = "app.py",
    score: float = 0.9,
) -> DetectionContext:
    start = text.index(match)
    return DetectionContext(
        relative_path=Path(path),
        extension=Path(path).suffix.lower(),
        text=text,
        start=start,
        end=start + len(match),
        entity_type=entity_type,
        score=score,
    )


def test_ignores_public_contributor_names_in_changelog() -> None:
    validator = DetectionValidator()
    context = _context(
        "Thanks John Doe for reporting this regression in the release notes.",
        "John Doe",
        entity_type="PERSON",
        path="CHANGES.md",
    )

    assert not validator.should_keep(context)


def test_ignores_github_handles_in_markdown() -> None:
    validator = DetectionValidator()
    context = _context(
        "Reported by @alice and fixed by @bob in issue #42.",
        "alice",
        entity_type="PERSON",
        path="README.md",
    )

    assert not validator.should_keep(context)


def test_ignores_technology_terms_as_organizations() -> None:
    validator = DetectionValidator()
    context = _context(
        "Click integrates with Python and GitHub Actions.",
        "Python",
        entity_type="ORGANIZATION",
        path="docs/index.rst",
    )

    assert not validator.should_keep(context)


def test_keeps_person_with_sensitive_record_context() -> None:
    validator = DetectionValidator()
    context = _context(
        "customer full name: Jane Smith, date of birth: 1980-01-01",
        "Jane Smith",
        entity_type="PERSON",
        path="exports/customers.csv",
    )

    assert validator.should_keep(context)


def test_keeps_high_signal_entities_without_context() -> None:
    validator = DetectionValidator()
    context = _context(
        "tokenless note, support@example.com",
        "support@example.com",
        entity_type="EMAIL_ADDRESS",
        path="README.md",
    )

    assert validator.should_keep(context)


def test_public_documentation_urls_are_not_actionable() -> None:
    validator = DetectionValidator()
    context = _context(
        "See https://docs.python.org/3/library/pathlib.html for pathlib docs.",
        "https://docs.python.org/3/library/pathlib.html",
        entity_type="URL",
        path="README.md",
    )

    assert not validator.should_keep(context)


def test_urls_with_credentials_are_actionable() -> None:
    validator = DetectionValidator()
    context = _context(
        "callback=https://api.example.com/upload?token=secret-value",
        "https://api.example.com/upload?token=secret-value",
        entity_type="URL",
        path="config.yml",
    )

    assert validator.should_keep(context)


def test_release_dates_are_not_actionable_without_personal_context() -> None:
    validator = DetectionValidator()
    context = _context(
        "Released on 2024-01-15 as version 1.2.3.",
        "2024-01-15",
        entity_type="DATE_TIME",
        path="CHANGELOG.md",
    )

    assert not validator.should_keep(context)


def test_birth_dates_are_actionable() -> None:
    validator = DetectionValidator()
    context = _context(
        "patient date of birth: 1975-05-12",
        "1975-05-12",
        entity_type="DATE_TIME",
        path="exports/patient.json",
    )

    assert validator.should_keep(context)
