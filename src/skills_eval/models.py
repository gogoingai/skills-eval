"""Immutable domain models shared by skills-eval checks."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable
from types import MappingProxyType

import yaml


class Severity(str, Enum):
    PASS = "PASS"
    REVIEW = "REVIEW"
    FAIL = "FAIL"


class CheckStatus(str, Enum):
    READY = "READY"
    READY_WITH_WARNINGS = "READY WITH WARNINGS"
    NOT_READY = "NOT READY"


@dataclass(frozen=True)
class Diagnostic:
    severity: Severity
    code: str
    message: str
    path: Path | None = None


@dataclass(frozen=True)
class Skill:
    name: str
    path: Path
    frontmatter: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if self.frontmatter is not None:
            object.__setattr__(self, "frontmatter", _freeze_frontmatter(self.frontmatter))


@dataclass(frozen=True)
class Plugin:
    name: str
    path: Path
    skills: tuple[Skill, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "skills", tuple(self.skills))


@dataclass(frozen=True)
class Finding:
    severity: Severity
    code: str
    message: str
    path: Path | None = None


@dataclass(frozen=True)
class SkillResult:
    skill: Skill
    diagnostics: tuple[Diagnostic, ...] = ()
    findings: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "findings", tuple(self.findings))

    @property
    def severity(self) -> Severity:
        return highest_severity((*self.diagnostics, *self.findings))


@dataclass(frozen=True)
class CheckResult:
    plugin_name: str
    skills: tuple[Skill, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    findings: tuple[Finding, ...] = ()
    skill_results: tuple[SkillResult, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "skills", tuple(self.skills))
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "skill_results", tuple(self.skill_results))

    @property
    def severity(self) -> Severity:
        nested = tuple(
            result
            for skill in self.skill_results
            for result in (*skill.diagnostics, *skill.findings)
        )
        return highest_severity((*self.diagnostics, *self.findings, *nested))

    @property
    def status(self) -> CheckStatus:
        if self.severity is Severity.FAIL:
            return CheckStatus.NOT_READY
        if self.severity is Severity.REVIEW:
            return CheckStatus.READY_WITH_WARNINGS
        return CheckStatus.READY

    @property
    def exit_code(self) -> int:
        return 1 if self.status is CheckStatus.NOT_READY else 0


def highest_severity(items: Iterable[Diagnostic | Finding]) -> Severity:
    """Return the highest severity using FAIL > REVIEW > PASS precedence."""
    severities = {item.severity for item in items}
    if Severity.FAIL in severities:
        return Severity.FAIL
    if Severity.REVIEW in severities:
        return Severity.REVIEW
    return Severity.PASS


def _freeze_frontmatter(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_frontmatter(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze_frontmatter(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(_freeze_frontmatter(item) for item in value)
    return value


def parse_frontmatter(text: str) -> dict[str, object] | None:
    """Parse YAML frontmatter, returning ``None`` when it is absent or not a map."""
    if not text.startswith("---"):
        return None

    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return None

    for index, line in enumerate(lines[1:], start=1):
        if line in {"---", "..."}:
            parsed: Any = yaml.safe_load("\n".join(lines[1:index]))
            return parsed if isinstance(parsed, dict) else None
    return None
