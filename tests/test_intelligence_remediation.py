"""
test_intelligence_remediation.py
==================================

Tests for Task 2, Phase 4's `RemediationEngine`: deterministic
remediation recommendations plus OWASP/CWE secure-coding references,
built on top of (not duplicating) Phase 2's
`scanner.ai.recommendations`.
"""

from __future__ import annotations

from scanner.ai.recommendations import recommendation_for_entity
from scanner.intelligence.remediation import (
    RemediationEngine,
    secure_coding_reference_for_entity,
)


def test_secure_coding_reference_known_entity_has_specific_cwe() -> None:
    reference = secure_coding_reference_for_entity("CRYPTO")
    assert "CWE-798" in reference["cwe"]
    assert reference["owasp"]
    assert reference["best_practice"]
    assert reference["references"]


def test_organization_has_specific_secure_coding_reference() -> None:
    reference = secure_coding_reference_for_entity("ORGANIZATION")

    assert "CWE-200" in reference["cwe"]
    assert "OWASP A01:2021" in reference["owasp"]
    assert "organization" in reference["best_practice"].lower()


def test_secure_coding_reference_unknown_entity_falls_back_to_default() -> None:
    reference = secure_coding_reference_for_entity("SOMETHING_NEW")
    assert reference["owasp"]
    assert reference["cwe"]
    assert reference["best_practice"]
    assert reference["references"]


def test_remediation_for_finding_reuses_phase_2_recommendation_text() -> None:
    """The recommendation text must be identical to Phase 2's, not re-derived."""
    engine = RemediationEngine()
    finding = {"entity_type": "EMAIL_ADDRESS", "severity": "HIGH", "finding_id": "F-000000"}

    remediation = engine.remediation_for_finding(finding)

    assert remediation["recommendation"] == recommendation_for_entity("EMAIL_ADDRESS")
    assert remediation["finding_id"] == "F-000000"
    assert remediation["owasp"]
    assert remediation["cwe"]


def test_remediation_for_organization_is_specific() -> None:
    engine = RemediationEngine()
    finding = {"entity_type": "ORGANIZATION", "severity": "MEDIUM"}

    remediation = engine.remediation_for_finding(finding)

    assert remediation["recommendation"] == recommendation_for_entity("ORGANIZATION")
    assert "organization" in remediation["recommendation"].lower()
    assert "CWE-200" in remediation["cwe"]


def test_build_secure_coding_recommendations_never_fabricates_entity_types() -> None:
    engine = RemediationEngine()
    findings = [{"entity_type": "PERSON", "severity": "HIGH", "file": "app.py"}]

    recommendations = engine.build_secure_coding_recommendations(findings)

    entity_types = {item["entity_type"] for item in recommendations}
    assert entity_types == {"PERSON"}


def test_build_secure_coding_recommendations_severity_ordered_highest_first() -> None:
    engine = RemediationEngine()
    findings = [
        {"entity_type": "URL", "severity": "LOW", "file": "app.py"},
        {"entity_type": "CREDIT_CARD", "severity": "CRITICAL", "file": "app.py"},
    ]

    recommendations = engine.build_secure_coding_recommendations(findings)

    assert recommendations[0]["entity_type"] == "CREDIT_CARD"
    assert recommendations[0]["severity"] == "CRITICAL"


def test_build_secure_coding_recommendations_empty_findings_returns_empty_list() -> None:
    assert RemediationEngine().build_secure_coding_recommendations([]) == []
