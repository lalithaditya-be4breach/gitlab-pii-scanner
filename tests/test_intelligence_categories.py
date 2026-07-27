"""
test_intelligence_categories.py
=================================

Tests for Task 2, Phase 4's `scanner.intelligence.categories`: entity
type -> risk category grouping and category counts.
"""

from __future__ import annotations

from scanner.intelligence.categories import (
    RiskCategory,
    build_category_counts,
    categorize_entity,
)


def test_categorize_entity_known_types() -> None:
    assert categorize_entity("CREDIT_CARD") == RiskCategory.FINANCIAL_DATA
    assert categorize_entity("US_SSN") == RiskCategory.GOVERNMENT_IDS
    assert categorize_entity("UK_NHS") == RiskCategory.MEDICAL_DATA
    assert categorize_entity("EMAIL_ADDRESS") == RiskCategory.PERSONAL_INFORMATION
    assert categorize_entity("IP_ADDRESS") == RiskCategory.NETWORK_INFORMATION
    assert categorize_entity("CRYPTO") == RiskCategory.SECRETS
    assert categorize_entity("ORGANIZATION") == RiskCategory.BUSINESS_INFORMATION


def test_categorize_entity_unknown_type_falls_back_to_other() -> None:
    assert categorize_entity("SOMETHING_NEW") == RiskCategory.OTHER


def test_build_category_counts_includes_every_category_with_zero_default() -> None:
    counts = build_category_counts([])
    assert set(counts.keys()) == {category.value for category in RiskCategory}
    assert all(count == 0 for count in counts.values())


def test_build_category_counts_tallies_by_category_not_entity_type() -> None:
    findings = [
        {"entity_type": "US_SSN"},
        {"entity_type": "US_PASSPORT"},
        {"entity_type": "EMAIL_ADDRESS"},
        {"entity_type": "ORGANIZATION"},
    ]
    counts = build_category_counts(findings)
    assert counts[RiskCategory.GOVERNMENT_IDS.value] == 2
    assert counts[RiskCategory.PERSONAL_INFORMATION.value] == 1
    assert counts[RiskCategory.BUSINESS_INFORMATION.value] == 1


def test_build_category_counts_never_fabricates_findings() -> None:
    findings = [{"entity_type": "EMAIL_ADDRESS"}]
    counts = build_category_counts(findings)
    total = sum(counts.values())
    assert total == len(findings)
