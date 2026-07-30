from pathlib import Path

import pytest

from skills_eval.models import CheckResult, CheckStatus, Diagnostic, Severity, Skill


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
