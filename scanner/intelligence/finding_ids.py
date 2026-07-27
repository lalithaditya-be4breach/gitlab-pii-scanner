"""
finding_ids.py
==============

Task 2, Phase 4: deterministic identifiers for findings within a
single JSON report.

The Task 2 Phase 1 report schema (`scanner.report_generator`) does not
assign each finding a stable ID -- findings are only ever consumed as
an ordered list, and the schema is not to be changed unless absolutely
necessary (see project requirements). Phase 4's `/api/explain`
endpoint still needs a way to reference one specific finding, so this
module derives an ID purely from a finding's *position* in the
report's `findings` list rather than adding a new field to the
persisted JSON.

This is safe because:
    - `ReportGenerator` always appends findings in the same order
      `ScanEngine` discovered them, for a given scan.
    - A written report file (`reports/latest/scan_report.json` or its history copy)
      is immutable once written -- nothing here re-orders it.

IDs are therefore stable *within* one report, but are intentionally
opaque and are not meant to be compared across two different report
files (a finding's ID may differ between two separate scans, even for
what looks like "the same" finding).
"""

from __future__ import annotations

from typing import Any

#: Prefix + zero-padded width used when rendering a finding index as an
#: ID string (e.g. index 7 -> "F-000007"). Purely cosmetic.
_ID_PREFIX = "F-"
_ID_WIDTH = 6


def compute_finding_id(index: int) -> str:
    """
    Render a finding's position in a report's `findings` list as a
    stable, human-readable ID.

    Args:
        index: Zero-based position of the finding in `report["findings"]`.

    Returns:
        A string such as "F-000007".

    Raises:
        ValueError: if `index` is negative.
    """
    if index < 0:
        raise ValueError(f"index must be >= 0, got {index}")
    return f"{_ID_PREFIX}{index:0{_ID_WIDTH}d}"


def index_from_finding_id(finding_id: str) -> int | None:
    """
    Recover the list index encoded in a finding ID produced by
    `compute_finding_id`.

    Args:
        finding_id: A finding ID, e.g. "F-000007".

    Returns:
        The zero-based index, or `None` if `finding_id` is not a
        recognizable, well-formed ID (never raises on bad input).
    """
    if not isinstance(finding_id, str) or not finding_id.startswith(_ID_PREFIX):
        return None
    raw = finding_id[len(_ID_PREFIX):]
    if not raw.isdigit():
        return None
    return int(raw)


def attach_finding_ids(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Return a new list of finding dicts, each with a `finding_id` key.

    Does not mutate `findings` or any of its dict elements.

    Args:
        findings: The `findings` list from a Task 2 Phase 1 JSON report.

    Returns:
        A new list of shallow-copied finding dicts, each with an
        added `finding_id` field.
    """
    enriched: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        with_id = dict(finding)
        with_id["finding_id"] = compute_finding_id(index)
        enriched.append(with_id)
    return enriched


def get_finding_by_id(
    findings: list[dict[str, Any]], finding_id: str
) -> dict[str, Any] | None:
    """
    Look up a single finding by its deterministic, positional ID.

    Args:
        findings: The `findings` list from a Task 2 Phase 1 JSON report.
        finding_id: A finding ID, as produced by `compute_finding_id`.

    Returns:
        A shallow copy of the matching finding dict (with `finding_id`
        set), or `None` if `finding_id` is malformed or out of range.
        Never raises -- an unknown ID is reported as `None`, not an
        exception, so callers (e.g. the `/api/explain` HTTP handler)
        can turn it into a clean 404 rather than a 500.
    """
    index = index_from_finding_id(finding_id)
    if index is None or index < 0 or index >= len(findings):
        return None
    finding = dict(findings[index])
    finding["finding_id"] = finding_id
    return finding
