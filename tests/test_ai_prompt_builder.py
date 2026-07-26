"""
test_ai_prompt_builder.py
============================

Tests for Task 2, Phase 2's `scanner.ai.prompt_builder.PromptBuilder`:
prompts are built only from the JSON report and instruct the model not
to change findings, severities, or the risk score/pipeline status.
"""

from __future__ import annotations

from scanner.ai.prompt_builder import PromptBuilder


def _sample_report(**overrides) -> dict:
    report = {
        "schema_version": "1.0",
        "scanner_version": "0.4.0",
        "repository": {"identifier": "https://gitlab.com/group/project.git"},
        "summary": {
            "total_findings": 2,
            "severity_counts": {"LOW": 0, "MEDIUM": 1, "HIGH": 1, "CRITICAL": 0},
            "risk_score": 10,
            "pipeline_status": "WARNING",
            "risk_thresholds": {"warning": 5, "fail": 50},
        },
        "findings": [
            {
                "file": "app.py",
                "line_number": 10,
                "entity_type": "EMAIL_ADDRESS",
                "severity": "HIGH",
                "confidence_score": 0.9,
                "matched_value": "jo***@example.com",
                "redacted": True,
            },
            {
                "file": "config.yml",
                "line_number": 3,
                "entity_type": "PHONE_NUMBER",
                "severity": "MEDIUM",
                "confidence_score": 0.7,
                "matched_value": "***-***-1234",
                "redacted": True,
            },
        ],
    }
    report.update(overrides)
    return report


def test_build_includes_repository_identifier() -> None:
    prompt = PromptBuilder.build(_sample_report())
    assert "https://gitlab.com/group/project.git" in prompt


def test_build_includes_risk_score_and_pipeline_status() -> None:
    prompt = PromptBuilder.build(_sample_report())
    assert '"risk_score": 10' in prompt
    assert '"pipeline_status": "WARNING"' in prompt


def test_build_includes_finding_entity_types() -> None:
    prompt = PromptBuilder.build(_sample_report())
    assert "EMAIL_ADDRESS" in prompt
    assert "PHONE_NUMBER" in prompt


def test_build_never_includes_raw_matched_values() -> None:
    """The prompt should only reference entity types/files, not values."""
    prompt = PromptBuilder.build(_sample_report())
    assert "jo***@example.com" not in prompt
    assert "***-***-1234" not in prompt


def test_build_instructs_model_not_to_change_findings_or_score() -> None:
    prompt = PromptBuilder.build(_sample_report())
    assert "deterministically" in prompt.lower() or "do not" in prompt.lower()
    assert "risk score" in prompt.lower()


def test_build_instructs_model_against_compliance_claims() -> None:
    prompt = PromptBuilder.build(_sample_report())
    assert "compliance" in prompt.lower()
    assert "legal advice" in prompt.lower()


def test_build_truncates_large_findings_lists() -> None:
    many_findings = [
        {
            "file": f"file_{i}.py",
            "line_number": i,
            "entity_type": "PERSON",
            "severity": "LOW",
            "confidence_score": 0.6,
            "matched_value": "***",
            "redacted": True,
        }
        for i in range(100)
    ]
    prompt = PromptBuilder.build(_sample_report(findings=many_findings))

    assert '"findings_sample_is_truncated": true' in prompt


def test_build_handles_empty_report_without_raising() -> None:
    prompt = PromptBuilder.build({})
    assert isinstance(prompt, str)
    assert len(prompt) > 0
