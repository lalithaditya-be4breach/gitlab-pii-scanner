"""
test_ai_recommendations.py
============================

Tests for Task 2, Phase 2's `scanner.ai.recommendations`: deterministic,
severity-ordered remediation advice derived only from entity types
actually present in a report's findings.
"""

from __future__ import annotations

from scanner.ai.recommendations import build_recommendations, recommendation_for_entity


def _finding(entity_type: str, severity: str) -> dict:
    return {"entity_type": entity_type, "severity": severity, "file": "app.py"}


def test_build_recommendations_empty_findings_returns_empty_list() -> None:
    assert build_recommendations([]) == []


def test_build_recommendations_never_fabricates_entity_types() -> None:
    """Only entity types present in findings appear in recommendations."""
    findings = [_finding("EMAIL_ADDRESS", "HIGH")]

    recommendations = build_recommendations(findings)

    entity_types = {item["entity_type"] for item in recommendations}
    assert entity_types == {"EMAIL_ADDRESS"}


def test_build_recommendations_deduplicates_repeated_entity_types() -> None:
    findings = [
        _finding("EMAIL_ADDRESS", "HIGH"),
        _finding("EMAIL_ADDRESS", "HIGH"),
        _finding("EMAIL_ADDRESS", "MEDIUM"),
    ]

    recommendations = build_recommendations(findings)

    assert len(recommendations) == 1
    assert recommendations[0]["entity_type"] == "EMAIL_ADDRESS"


def test_build_recommendations_keeps_highest_severity_seen_per_entity() -> None:
    findings = [
        _finding("PERSON", "LOW"),
        _finding("PERSON", "CRITICAL"),
        _finding("PERSON", "MEDIUM"),
    ]

    recommendations = build_recommendations(findings)

    assert recommendations[0]["entity_type"] == "PERSON"
    assert recommendations[0]["severity"] == "CRITICAL"


def test_build_recommendations_sorted_highest_severity_first() -> None:
    findings = [
        _finding("URL", "LOW"),
        _finding("CREDIT_CARD", "CRITICAL"),
        _finding("EMAIL_ADDRESS", "HIGH"),
        _finding("PHONE_NUMBER", "MEDIUM"),
    ]

    recommendations = build_recommendations(findings)

    severities = [item["severity"] for item in recommendations]
    assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_build_recommendations_known_entity_gives_specific_advice() -> None:
    findings = [_finding("CREDIT_CARD", "CRITICAL")]

    recommendations = build_recommendations(findings)

    assert "payment" in recommendations[0]["recommendation"].lower()


def test_build_recommendations_unknown_entity_gets_generic_fallback_advice() -> None:
    findings = [_finding("SOME_FUTURE_ENTITY", "MEDIUM")]

    recommendations = build_recommendations(findings)

    assert "SOME_FUTURE_ENTITY" in recommendations[0]["recommendation"]


def test_build_recommendations_skips_malformed_finding_entries() -> None:
    """Findings missing entity_type/severity are ignored, not fabricated."""
    findings = [{"file": "app.py"}, _finding("PERSON", "HIGH")]

    recommendations = build_recommendations(findings)

    assert len(recommendations) == 1
    assert recommendations[0]["entity_type"] == "PERSON"


def test_recommendation_for_entity_matches_build_recommendations_output() -> None:
    findings = [_finding("EMAIL_ADDRESS", "HIGH")]
    recommendations = build_recommendations(findings)

    assert recommendations[0]["recommendation"] == recommendation_for_entity(
        "EMAIL_ADDRESS"
    )
