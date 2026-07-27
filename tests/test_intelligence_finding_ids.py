"""
test_intelligence_finding_ids.py
==================================

Tests for Task 2, Phase 4's `scanner.intelligence.finding_ids`:
deterministic, positional finding identifiers that never require a
change to the versioned JSON report schema.
"""

from __future__ import annotations

import pytest

from scanner.intelligence.finding_ids import (
    attach_finding_ids,
    compute_finding_id,
    get_finding_by_id,
    index_from_finding_id,
)


def test_compute_finding_id_is_deterministic() -> None:
    assert compute_finding_id(0) == compute_finding_id(0)
    assert compute_finding_id(0) != compute_finding_id(1)


def test_compute_finding_id_rejects_negative_index() -> None:
    with pytest.raises(ValueError):
        compute_finding_id(-1)


def test_index_from_finding_id_round_trips() -> None:
    finding_id = compute_finding_id(42)
    assert index_from_finding_id(finding_id) == 42


def test_index_from_finding_id_returns_none_for_malformed_input() -> None:
    assert index_from_finding_id("not-an-id") is None
    assert index_from_finding_id("F-abcdef") is None
    assert index_from_finding_id("") is None


def test_attach_finding_ids_does_not_mutate_input() -> None:
    findings = [{"entity_type": "EMAIL_ADDRESS"}]
    enriched = attach_finding_ids(findings)

    assert "finding_id" not in findings[0]
    assert enriched[0]["finding_id"] == compute_finding_id(0)
    assert enriched[0]["entity_type"] == "EMAIL_ADDRESS"


def test_attach_finding_ids_preserves_order() -> None:
    findings = [{"entity_type": "PERSON"}, {"entity_type": "EMAIL_ADDRESS"}]
    enriched = attach_finding_ids(findings)

    assert enriched[0]["finding_id"] == compute_finding_id(0)
    assert enriched[1]["finding_id"] == compute_finding_id(1)


def test_get_finding_by_id_returns_matching_finding() -> None:
    findings = [{"entity_type": "PERSON"}, {"entity_type": "EMAIL_ADDRESS"}]
    finding = get_finding_by_id(findings, compute_finding_id(1))

    assert finding is not None
    assert finding["entity_type"] == "EMAIL_ADDRESS"
    assert finding["finding_id"] == compute_finding_id(1)


def test_get_finding_by_id_returns_none_for_unknown_id() -> None:
    findings = [{"entity_type": "PERSON"}]
    assert get_finding_by_id(findings, "F-999999") is None
    assert get_finding_by_id(findings, "garbage") is None
