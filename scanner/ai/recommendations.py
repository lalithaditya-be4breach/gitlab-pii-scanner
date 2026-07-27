"""
recommendations.py
====================

Task 2, Phase 2: deterministic remediation advice derived from
detected entity types.

This module contains no AI calls and no randomness — the same set of
findings always produces the same recommendations, in the same order.
It exists precisely so an AI provider failure never removes
recommendations from the generated Markdown summary: `AIAssistant`
computes these directly from the JSON report, independent of whether
an AI narrative is available.

Recommendations are never fabricated: a recommendation only ever
appears for an `entity_type` that is actually present in the report's
`findings`.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Entity type -> remediation advice.
#
# Kept in one place (per the "dedicated prompt/recommendation builder,
# not scattered across the project" requirement). Anything not listed
# here falls back to `_DEFAULT_RECOMMENDATION`.
# ---------------------------------------------------------------------------
_ENTITY_RECOMMENDATIONS: dict[str, str] = {
    "CREDIT_CARD": (
        "Remove hardcoded payment card data from source. Never store raw "
        "card numbers in code, config, or logs; use a PCI-compliant "
        "payment processor/tokenization service instead."
    ),
    "CRYPTO": (
        "Remove hardcoded cryptocurrency wallet addresses/keys from source. "
        "Store private keys in a secrets manager, never in code."
    ),
    "US_SSN": (
        "Remove hardcoded Social Security Numbers. Replace with synthetic "
        "test data and ensure real SSNs are only handled through "
        "properly access-controlled systems."
    ),
    "US_ITIN": (
        "Remove hardcoded taxpayer identification numbers and replace with "
        "synthetic test data."
    ),
    "US_PASSPORT": (
        "Remove hardcoded passport numbers and replace with synthetic test "
        "data; treat passport data as sensitive PII requiring access "
        "controls."
    ),
    "US_BANK_NUMBER": (
        "Remove hardcoded bank account numbers. Move any required "
        "credentials into a secure secrets management solution."
    ),
    "UK_NHS": (
        "Remove hardcoded NHS numbers and replace with synthetic test data; "
        "treat as sensitive health-related identifier."
    ),
    "IBAN_CODE": (
        "Remove hardcoded IBAN numbers. Use synthetic test data and store "
        "any real banking details via secure secrets management."
    ),
    "MEDICAL_LICENSE": (
        "Remove hardcoded medical license numbers and replace with "
        "synthetic test data."
    ),
    "IN_AADHAAR": (
        "Remove hardcoded Aadhaar numbers and replace with synthetic test "
        "data; treat as sensitive national identifier."
    ),
    "IN_PASSPORT": (
        "Remove hardcoded passport numbers and replace with synthetic test "
        "data."
    ),
    "EMAIL_ADDRESS": (
        "Replace real email addresses in code, fixtures, and test data "
        "with synthetic example addresses (e.g. user@example.com)."
    ),
    "PHONE_NUMBER": (
        "Replace real phone numbers with synthetic test data (e.g. the "
        "555-01xx reserved test range)."
    ),
    "IP_ADDRESS": (
        "Replace real IP addresses in code/config with placeholder or "
        "documentation-reserved ranges; move any environment-specific "
        "addresses into configuration/secrets rather than source."
    ),
    "PERSON": (
        "Replace real customer/employee names in code, comments, and test "
        "fixtures with synthetic test data."
    ),
    "ORGANIZATION": (
        "Review detected organization names to confirm they are intended "
        "to be public. Replace confidential customer, partner, vendor, "
        "supplier, or internal project names with synthetic values in "
        "source, documentation, logs, and test datasets."
    ),
    "LOCATION": (
        "Replace real addresses/locations tied to individuals with "
        "synthetic test data."
    ),
    "US_DRIVER_LICENSE": (
        "Remove hardcoded driver's license numbers and replace with "
        "synthetic test data."
    ),
    "URL": (
        "Review embedded URLs for credentials or internal-only endpoints; "
        "move environment-specific URLs into configuration."
    ),
    "DATE_TIME": (
        "Review embedded dates for anything tied to a real individual "
        "(e.g. a date of birth) and replace with synthetic test data if so."
    ),
    "NRP": (
        "Review nationality/religious/political references for real "
        "individuals and replace with synthetic test data if present."
    ),
}

_DEFAULT_RECOMMENDATION_TEMPLATE = (
    "Review detected {entity_type} values and, where they identify a real "
    "person or system, move them into environment variables or a secure "
    "secrets management solution rather than source, config, or test data."
)

# Recommendations are always emitted highest-severity-first so a reader
# scanning top-to-bottom sees the most urgent remediation first.
_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
}


def recommendation_for_entity(entity_type: str) -> str:
    """Return the remediation advice for a single Presidio entity type."""
    return _ENTITY_RECOMMENDATIONS.get(
        entity_type,
        _DEFAULT_RECOMMENDATION_TEMPLATE.format(entity_type=entity_type),
    )


def build_recommendations(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    """
    Derive deduplicated, severity-ordered recommendations from findings.

    Args:
        findings: The `findings` list from a Task 2 Phase 1 JSON report
            (each a dict with at least `entity_type` and `severity`).

    Returns:
        A list of `{"entity_type", "severity", "recommendation"}` dicts,
        one per distinct `entity_type` actually present in `findings`,
        ordered from the highest severity seen for that entity type
        down to the lowest. Never fabricates an entity type that isn't
        present in `findings`.
    """
    highest_severity_by_entity: dict[str, str] = {}
    for finding in findings:
        entity_type = finding.get("entity_type")
        severity = finding.get("severity")
        if not entity_type or severity not in _SEVERITY_ORDER:
            continue
        current = highest_severity_by_entity.get(entity_type)
        if current is None or _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[current]:
            highest_severity_by_entity[entity_type] = severity

    recommendations = [
        {
            "entity_type": entity_type,
            "severity": severity,
            "recommendation": recommendation_for_entity(entity_type),
        }
        for entity_type, severity in highest_severity_by_entity.items()
    ]
    recommendations.sort(key=lambda item: _SEVERITY_ORDER[item["severity"]], reverse=True)
    return recommendations
