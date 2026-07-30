"""Claude Plugin manifest discovery and Skill selection."""

from __future__ import annotations

import json
from pathlib import Path

from skills_eval.models import Diagnostic, Plugin, Severity, Skill, parse_frontmatter


def discover_plugin(root: Path) -> tuple[Plugin | None, list[Diagnostic]]:
    """Discover the valid Skills declared by a Claude Plugin manifest.

    A malformed manifest prevents discovery.  A bad individual Skill declaration
    does not prevent valid sibling Skills from being returned.
    """
    root = root.resolve()
    manifest_path = root / ".claude-plugin" / "plugin.json"
    diagnostics: list[Diagnostic] = []
    try:
        raw_manifest = manifest_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, [_diagnostic("PLUGIN_MANIFEST_MISSING", "Plugin manifest is missing.", manifest_path)]
    except OSError as error:
        return None, [_diagnostic("PLUGIN_MANIFEST_UNREADABLE", str(error), manifest_path)]

    try:
        manifest = json.loads(raw_manifest)
    except json.JSONDecodeError as error:
        return None, [_diagnostic("PLUGIN_JSON_INVALID", f"Invalid plugin JSON: {error.msg}.", manifest_path)]

    if not isinstance(manifest, dict):
        return None, [_diagnostic("PLUGIN_JSON_INVALID", "Plugin manifest must be a JSON object.", manifest_path)]

    plugin_name = manifest.get("name")
    if not isinstance(plugin_name, str) or not plugin_name.strip():
        return None, [_diagnostic("PLUGIN_NAME_INVALID", "Plugin name must be a non-empty string.", manifest_path)]

    declared_skills = manifest.get("skills")
    if not isinstance(declared_skills, list) or not declared_skills:
        return None, [_diagnostic("PLUGIN_SKILLS_INVALID", "Plugin skills must be a non-empty list.", manifest_path)]

    skills: list[Skill] = []
    resolved_paths: set[Path] = set()
    frontmatter_names: set[str] = set()
    for declared_path in declared_skills:
        if not isinstance(declared_path, str) or not declared_path.strip():
            diagnostics.append(
                _diagnostic("SKILL_PATH_INVALID", "Skill path must be a non-empty string.", manifest_path)
            )
            continue

        skill_dir = (root / declared_path).resolve()
        if not _is_within(skill_dir, root):
            diagnostics.append(
                _diagnostic(
                    "SKILL_PATH_OUTSIDE_ROOT",
                    f"Skill path {declared_path!r} resolves outside the plugin root.",
                    root / declared_path,
                )
            )
            continue
        if skill_dir in resolved_paths:
            diagnostics.append(
                _diagnostic(
                    "SKILL_PATH_DUPLICATE",
                    f"Skill path {declared_path!r} duplicates an earlier declaration.",
                    skill_dir,
                )
            )
            continue
        resolved_paths.add(skill_dir)

        skill_file = skill_dir / "SKILL.md"
        if not skill_file.is_file():
            diagnostics.append(_diagnostic("SKILL_FILE_MISSING", "Skill directory lacks SKILL.md.", skill_file))
            continue
        try:
            frontmatter = parse_frontmatter(skill_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as error:
            diagnostics.append(_diagnostic("SKILL_FILE_INVALID", str(error), skill_file))
            continue

        frontmatter_name = frontmatter.get("name") if frontmatter is not None else None
        if not isinstance(frontmatter_name, str) or not frontmatter_name.strip():
            diagnostics.append(
                _diagnostic(
                    "SKILL_NAME_INVALID",
                    "SKILL.md frontmatter must contain a non-empty name.",
                    skill_file,
                )
            )
            continue
        if frontmatter_name in frontmatter_names:
            diagnostics.append(
                _diagnostic(
                    "SKILL_NAME_DUPLICATE",
                    f"Skill frontmatter name {frontmatter_name!r} is declared more than once.",
                    skill_file,
                )
            )
        frontmatter_names.add(frontmatter_name)
        skills.append(Skill(name=skill_dir.name, path=skill_dir, frontmatter=frontmatter))

    return Plugin(name=plugin_name, path=root, skills=tuple(skills)), diagnostics


def select_skill(plugin: Plugin, selector: str | None) -> tuple[list[Skill], list[Diagnostic]]:
    """Return all Skills or exactly one uniquely matched named Skill."""
    if selector is None:
        return list(plugin.skills), []

    selected = [
        skill
        for skill in plugin.skills
        if skill.name == selector or _frontmatter_name(skill) == selector
    ]
    if not selected:
        return [], [
            _diagnostic(
                "SKILL_SELECTOR_NOT_FOUND",
                f"No Skill matches selector {selector!r}.",
                plugin.path,
            )
        ]
    if len(selected) > 1:
        return [], [
            _diagnostic(
                "SKILL_SELECTOR_AMBIGUOUS",
                f"Selector {selector!r} matches multiple Skills.",
                plugin.path,
            )
        ]
    return selected, []


def _frontmatter_name(skill: Skill) -> str | None:
    name = skill.frontmatter.get("name") if skill.frontmatter is not None else None
    return name if isinstance(name, str) else None


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _diagnostic(code: str, message: str, path: Path) -> Diagnostic:
    return Diagnostic(Severity.FAIL, code, message, path)
