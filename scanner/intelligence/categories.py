"""
categories.py
=============

Task 2, Phase 4: groups Presidio entity types into business-facing
risk categories for reporting and dashboards.

This module performs no detection and no scoring of its own -- it only
relabels `entity_type` values that already exist in a Task 2 Phase 1
JSON report's `findings` list (produced by `scanner.pii_detector` via
`scanner.report_generator`) into broader categories a non-technical
stakeholder can scan at a glance (e.g. "Financial Data" instead of
"IBAN_CODE").

The taxonomy intentionally includes categories with no entity type
currently mapped to them (`AUTHENTICATION`). The scanner's Presidio
integration (`scanner.pii_detector`) only ever produces the entity
types enumerated below; `AUTHENTICATION` is kept as a named category so
this taxonomy would not need to change shape again if a future phase
adds a dedicated secrets/credential recognizer (e.g. hardcoded
passwords or API keys) -- it would simply gain entries, not a new
category.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class RiskCategory(str, Enum):
    """Business-facing grouping for a Presidio `entity_type`."""

    SECRETS = "Secrets"
    PERSONAL_INFORMATION = "Personal Information"
    FINANCIAL_DATA = "Financial Data"
    AUTHENTICATION = "Authentication"
    MEDICAL_DATA = "Medical Data"
    GOVERNMENT_IDS = "Government IDs"
    NETWORK_INFORMATION = "Network Information"
    BUSINESS_INFORMATION = "Business Information"
    CREDENTIALS = "Credentials"
    OTHER = "Other"


# ---------------------------------------------------------------------------
# entity_type -> RiskCategory.
#
# This covers exactly the entity types `scanner.pii_detector` classifies
# into a severity (see `_CRITICAL_SEVERITY_ENTITIES` /
# `_HIGH_SEVERITY_ENTITIES` / `_LOW_SEVERITY_ENTITIES` there). Anything
# not listed here (including entity types Presidio could theoretically
# return but the scanner does not currently classify) falls back to
# `RiskCategory.OTHER` rather than raising.
# ---------------------------------------------------------------------------
_ENTITY_CATEGORY: dict[str, RiskCategory] = {
    # Financial data
    "CREDIT_CARD": RiskCategory.FINANCIAL_DATA,
    "IBAN_CODE": RiskCategory.FINANCIAL_DATA,
    "US_BANK_NUMBER": RiskCategory.FINANCIAL_DATA,
    # Secrets / key material
    "CRYPTO": RiskCategory.SECRETS,
    # Government-issued identifiers
    "US_SSN": RiskCategory.GOVERNMENT_IDS,
    "US_ITIN": RiskCategory.GOVERNMENT_IDS,
    "US_PASSPORT": RiskCategory.GOVERNMENT_IDS,
    "IN_AADHAAR": RiskCategory.GOVERNMENT_IDS,
    "IN_PASSPORT": RiskCategory.GOVERNMENT_IDS,
    "US_DRIVER_LICENSE": RiskCategory.GOVERNMENT_IDS,
    # Medical data
    "UK_NHS": RiskCategory.MEDICAL_DATA,
    "MEDICAL_LICENSE": RiskCategory.MEDICAL_DATA,
    # Personal information
    "EMAIL_ADDRESS": RiskCategory.PERSONAL_INFORMATION,
    "PHONE_NUMBER": RiskCategory.PERSONAL_INFORMATION,
    "PERSON": RiskCategory.PERSONAL_INFORMATION,
    "LOCATION": RiskCategory.PERSONAL_INFORMATION,
    "DATE_TIME": RiskCategory.PERSONAL_INFORMATION,
    "NRP": RiskCategory.PERSONAL_INFORMATION,
    # Business information
    "ORGANIZATION": RiskCategory.BUSINESS_INFORMATION,
    # Network information
    "IP_ADDRESS": RiskCategory.NETWORK_INFORMATION,
    "URL": RiskCategory.NETWORK_INFORMATION,
}


def categorize_entity(entity_type: str) -> RiskCategory:
    """
    Map a single Presidio `entity_type` to its `RiskCategory`.

    Args:
        entity_type: The Presidio entity type, e.g. "EMAIL_ADDRESS".

    Returns:
        The matching `RiskCategory`, or `RiskCategory.OTHER` if
        `entity_type` is not recognized.
    """
    return _ENTITY_CATEGORY.get(entity_type, RiskCategory.OTHER)


def build_category_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """
    Count findings per risk category.

    Every category in `RiskCategory` is always present in the result
    (defaulting to 0) so downstream consumers (e.g. `dashboard.py`)
    can render a stable, complete set of categories without needing to
    special-case missing keys.

    Args:
        findings: The `findings` list from a Task 2 Phase 1 JSON report.

    Returns:
        A dict of `RiskCategory.value -> count`.
    """
    counts: dict[str, int] = {category.value: 0 for category in RiskCategory}
    for finding in findings:
        entity_type = finding.get("entity_type", "")
        category = categorize_entity(entity_type)
        counts[category.value] += 1
    return counts
