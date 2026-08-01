from pathlib import Path
import sys

import json

import pytest

from skills_eval.config import EvalConfig
from skills_eval.models import CheckResult, Severity, Skill, SkillResult
from skills_eval.security import SecurityFinding


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))


@pytest.fixture
def plugin_factory(tmp_path: Path):
    """Create a small Claude Plugin repository for discovery tests."""

    def create(
        *,
        skills: list[str] | None = None,
        names: list[str] | None = None,
        plugin_name: str = "example-plugin",
        skill_body: str = "Useful instructions.",
    ) -> Path:
        declared_skills = skills or ["./write"]
        frontmatter_names = names or [Path(item).name for item in declared_skills]
        root = tmp_path / "plugin"
        metadata = root / ".claude-plugin"
        metadata.mkdir(parents=True)
        (metadata / "plugin.json").write_text(
            json.dumps({"name": plugin_name, "skills": declared_skills}), encoding="utf-8"
        )

        for declared_path, frontmatter_name in zip(declared_skills, frontmatter_names):
            skill_dir = (root / declared_path).resolve()
            if root.resolve() not in (skill_dir, *skill_dir.parents):
                continue
            skill_dir.mkdir(parents=True, exist_ok=True)
            (skill_dir / "SKILL.md").write_text(
                f"---\nname: {frontmatter_name}\ndescription: Test skill\n---\n{skill_body}\n",
                encoding="utf-8",
            )
        return root

    return create


@pytest.fixture
def portable_config() -> EvalConfig:
    return EvalConfig(
        required_root_files=(),
        required_skill_frontmatter=("name", "description"),
        forbidden_paths=(),
        reference_extensions=(".md",),
        security_sources=(),
    )


@pytest.fixture
def wenqu_config() -> EvalConfig:
    return EvalConfig(
        required_root_files=("README.md", "README.en.md", "VERSION"),
        required_skill_frontmatter=("name", "description", "slug"),
        forbidden_paths=(".DS_Store",),
        reference_extensions=(".md", ".txt", ".pdf", ".png", ".jpg", ".jpeg", ".webp"),
        security_sources=(),
        publishing_targets=(
            {"name": "claude-plugin", "enabled": True},
            {"name": "workbuddy", "enabled": True},
            {"name": "skillhub", "enabled": True},
            {"name": "openclaw", "enabled": True},
            {"name": "clawhub", "enabled": True},
        ),
    )


@pytest.fixture
def sample_result() -> CheckResult:
    """Return a warning result with a detailed Cisco finding for report tests."""
    skill = Skill(
        name="write",
        path=Path("skills/write"),
        frontmatter={"name": "write", "description": "Write an article."},
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
        evidence="ignore previous instructions",
        source_severity="medium",
    )
    return CheckResult(
        plugin_name="example-plugin",
        report_language="zh",
        skills=(skill,),
        skill_results=(SkillResult(skill=skill, findings=(finding,)),),
        security_sources=(
            {
                "name": "cisco",
                "enabled": True,
                "options": {"policy": "strict", "useBehavioral": True},
            },
        ),
    )
