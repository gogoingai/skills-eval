from __future__ import annotations

import json
from pathlib import Path

from skills_eval.models import CheckResult, Severity, Skill, SkillResult
from skills_eval.security.base import FindingLevel, ProviderResult, ScanStatus, SecurityFinding
from skills_eval.reporting import render_json


def _result() -> CheckResult:
    skill = Skill(
        name="write",
        path=Path("skills/write"),
        format_status=Severity.PASS,
        security_status=Severity.REVIEW,
    )
    finding = SecurityFinding(
        severity=Severity.REVIEW,
        code="PI-001",
        message="Injected instruction",
        path=Path("SKILL.md"),
        source="cisco",
        rule_id="PI-001",
        line=12,
        detail="Untrusted text requests an unsafe action.",
        remediation="Treat the text as data.",
        source_severity="medium",
        level=FindingLevel.MEDIUM,
        title="Injected instruction",
        raw={"rule_id": "PI-001", "severity": "medium"},
    )
    provider = ProviderResult(
        provider="cisco",
        status=ScanStatus.WARN,
        enabled=True,
        available=True,
        required=True,
        version="2.0.12",
        duration_ms=42,
        findings=(finding,),
    )
    return CheckResult(
        plugin_name="example-plugin",
        root_path=Path("/repo"),
        report_language="en",
        skills=(skill,),
        skill_results=(
            SkillResult(skill=skill, findings=(finding,), security_results=(provider,)),
        ),
        security_summary=(provider,),
        security_overall=ScanStatus.WARN,
        security_fail_on="high",
    )


def test_json_report_has_expected_top_level_structure() -> None:
    payload = json.loads(render_json(_result()))

    assert payload["schemaVersion"] == 1
    assert payload["plugin"] == "example-plugin"
    assert payload["overall"]["status"] == "READY WITH WARNINGS"
    assert payload["overall"]["exitCode"] == 0
    assert payload["security"]["failOn"] == "high"
    assert payload["security"]["overall"] == "WARN"


def test_json_report_includes_per_provider_summary() -> None:
    payload = json.loads(render_json(_result()))
    providers = payload["security"]["providers"]

    assert len(providers) == 1
    provider = providers[0]
    assert provider["name"] == "cisco"
    assert provider["enabled"] is True
    assert provider["available"] is True
    assert provider["required"] is True
    assert provider["version"] == "2.0.12"
    assert provider["durationMs"] == 42
    assert provider["status"] == "WARN"
    assert provider["findingCount"] == 1
    assert provider["error"] is None
    assert provider["skipReason"] is None


def test_json_report_unified_finding_fields() -> None:
    payload = json.loads(render_json(_result()))
    finding = payload["findings"][0]

    assert finding["provider"] == "cisco"
    assert finding["ruleId"] == "PI-001"
    assert finding["level"] == "medium"
    assert finding["severity"] == "REVIEW"
    assert finding["title"] == "Injected instruction"
    assert finding["description"] == "Untrusted text requests an unsafe action."
    assert finding["file"] == "SKILL.md"
    assert finding["line"] == 12
    assert finding["recommendation"] == "Treat the text as data."
    assert finding["sourceSeverity"] == "medium"
    assert finding["raw"] == {"rule_id": "PI-001", "severity": "medium"}


def test_json_report_skill_section_has_provider_results() -> None:
    payload = json.loads(render_json(_result()))
    skill = payload["skills"][0]

    assert skill["name"] == "write"
    assert skill["format"] == "PASS"
    assert skill["security"] == "REVIEW"
    assert skill["providers"][0]["name"] == "cisco"
    assert skill["providers"][0]["status"] == "WARN"
    assert skill["findings"][0]["ruleId"] == "PI-001"


def test_json_report_contains_no_secret_markers() -> None:
    text = render_json(_result())
    # No credential-like env var names or token placeholders leak into the report.
    for secret in ("SNYK_TOKEN", "LLM_API_KEY", "SOCKET_SECURITY_API_TOKEN", "sk-"):
        assert secret not in text
