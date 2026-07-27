"""
ci
==

Azure DevOps pipeline helper scripts (Task 2, Phase 3).

Everything in this package runs *after* the scanner has already
produced its JSON report. It never re-implements scanning or risk
logic -- it only reads the report's `summary.pipeline_status` field
and translates it into Azure DevOps pipeline behavior.
"""

from __future__ import annotations
