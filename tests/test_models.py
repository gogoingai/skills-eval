from pathlib import Path

import pytest

from skills_eval.models import (
    CheckResult,
    CheckStatus,
    Diagnostic,
    Severity,
    Skill,
    SkillResult,
)


def test_result_is_ready_with_warning_when_review_exists() -> None:
    result = CheckResult(
        plugin_name="Example",
        skills=[],
        diagnostics=[Diagnostic(Severity.REVIEW, "TEST", "Review this", Path("a.md"))],
    )

    assert result.status is CheckStatus.READY_WITH_WARNINGS
    assert result.exit_code == 0


def test_skill_frontmatter_is_deeply_immutable() -> None:
    source = {"metadata": {"tags": ["example"]}}
    skill = Skill(name="Example", path=Path("SKILL.md"), frontmatter=source)

    source["metadata"]["tags"].append("changed")

    assert skill.frontmatter == {"metadata": {"tags": ("example",)}}
    with pytest.raises(AttributeError):
        skill.frontmatter["metadata"]["tags"].append("new")
    with pytest.raises(TypeError):
        skill.frontmatter["metadata"]["tags"] = ("new",)


def test_shared_models_expose_service_execution_status() -> None:
    skill = Skill(
        name="write",
        path=Path("write"),
        format_status=Severity.PASS,
        security_status=None,
    )
    result = CheckResult(
        plugin_name="Example",
        skills=[skill],
        dry_run=True,
        planned_security_sources=["cisco"],
        security_sources=[{"name": "cisco", "enabled": True}],
    )

    assert result.dry_run is True
    assert result.planned_security_sources == ("cisco",)
    assert result.security_sources == ({"name": "cisco", "enabled": True},)
    assert result.skills[0].format_status is Severity.PASS
    assert result.skills[0].security_status is None


def test_skill_result_failure_cannot_be_masked_by_passing_skill_statuses() -> None:
    skill = Skill(
        name="write",
        path=Path("write"),
        format_status=Severity.PASS,
        security_status=Severity.PASS,
    )
    result = CheckResult(
        plugin_name="Example",
        skills=[skill],
        skill_results=[
            SkillResult(
                skill=skill,
                diagnostics=[
                    Diagnostic(Severity.FAIL, "NESTED_FAIL", "Must not be masked.")
                ],
            )
        ],
    )

    assert result.severity is Severity.FAIL
    assert result.status is CheckStatus.NOT_READY
