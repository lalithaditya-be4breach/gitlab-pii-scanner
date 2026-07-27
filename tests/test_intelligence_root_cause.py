"""
test_intelligence_root_cause.py
=================================

Tests for Task 2, Phase 4's `RootCauseEngine`: deterministic
why/where/how root-cause analysis derived only from fields already
present in a Task 2 Phase 1 JSON report finding.
"""

from __future__ import annotations

from scanner.intelligence.categories import RiskCategory
from scanner.intelligence.finding_ids import compute_finding_id
from scanner.intelligence.root_cause import RootCauseEngine, narrative_for_entity


def _finding(**overrides) -> dict:
    base = {
        "file": "app.py",
        "line_number": 42,
        "entity_type": "EMAIL_ADDRESS",
        "confidence_score": 1.0,
        "severity": "HIGH",
        "matched_value": "jo***@example.com",
        "redacted": True,
    }
    base.update(overrides)
    return base


def test_analyze_finding_includes_location_and_confidence_from_report() -> None:
    engine = RootCauseEngine()
    finding = _finding(finding_id=compute_finding_id(0))

    analysis = engine.analyze_finding(finding)

    assert analysis["finding_id"] == compute_finding_id(0)
    assert analysis["file"] == "app.py"
    assert analysis["line_number"] == 42
    assert analysis["confidence"] == 1.0
    assert analysis["severity"] == "HIGH"


def test_analyze_finding_never_fabricates_confidence() -> None:
    """The root cause 'confidence' is always the finding's own confidence_score."""
    engine = RootCauseEngine()
    finding = _finding(confidence_score=0.73)

    analysis = engine.analyze_finding(finding)

    assert analysis["confidence"] == 0.73


def test_analyze_finding_assigns_correct_category() -> None:
    engine = RootCauseEngine()
    finding = _finding(entity_type="US_SSN")

    analysis = engine.analyze_finding(finding)

    assert analysis["category"] == RiskCategory.GOVERNMENT_IDS.value


def test_known_entity_type_has_specific_narrative() -> None:
    narrative = narrative_for_entity("CREDIT_CARD")
    assert "payment card" in narrative.root_cause.lower()


def test_organization_has_specific_narrative_and_category() -> None:
    engine = RootCauseEngine()
    finding = _finding(entity_type="ORGANIZATION")

    analysis = engine.analyze_finding(finding)

    assert analysis["category"] == RiskCategory.BUSINESS_INFORMATION.value
    assert "organization" in analysis["root_cause"].lower()
    assert "customer datasets" in analysis["likely_developer_mistake"].lower()
    assert "competitive intelligence" in analysis["security_impact"].lower()


def test_unknown_entity_type_falls_back_to_default_narrative() -> None:
    narrative = narrative_for_entity("SOME_UNKNOWN_ENTITY")
    assert narrative.root_cause
    assert narrative.why_detected
    assert narrative.developer_mistake
    assert narrative.security_impact


def test_analyze_findings_attaches_ids_when_missing() -> None:
    engine = RootCauseEngine()
    findings = [_finding(), _finding(entity_type="PERSON")]

    analyses = engine.analyze_findings(findings)

    assert analyses[0]["finding_id"] == compute_finding_id(0)
    assert analyses[1]["finding_id"] == compute_finding_id(1)


def test_analyze_findings_preserves_order_and_count() -> None:
    engine = RootCauseEngine()
    findings = [_finding(entity_type=t) for t in ("PERSON", "EMAIL_ADDRESS", "US_SSN")]

    analyses = engine.analyze_findings(findings)

    assert len(analyses) == 3
    assert [a["entity_type"] for a in analyses] == ["PERSON", "EMAIL_ADDRESS", "US_SSN"]


def test_analyze_findings_empty_list_returns_empty_list() -> None:
    assert RootCauseEngine().analyze_findings([]) == []
