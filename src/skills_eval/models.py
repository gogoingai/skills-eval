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

    @property
    def is_execution_error(self) -> bool:
        """Return whether this diagnostic represents a tool execution error."""
        return False


@dataclass(frozen=True)
class Skill:
    name: str
    path: Path
    frontmatter: Mapping[str, object] | None = None
    format_status: Severity = Severity.PASS
    security_status: Severity | None = None

    def __post_init__(self) -> None:
        if self.frontmatter is not None:
            object.__setattr__(self, "frontmatter", _freeze_frontmatter(self.frontmatter))

    @property
    def severity(self) -> Severity:
        return highest_status((self.format_status, self.security_status or Severity.PASS))

    @property
    def status(self) -> CheckStatus:
        return status_for_severity(self.severity)


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
    root_path: Path | None = None
    selector: str | None = None
    report_language: str = "en"
    skills: tuple[Skill, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    findings: tuple[Finding, ...] = ()
    skill_results: tuple[SkillResult, ...] = ()
    dry_run: bool = False
    planned_security_sources: tuple[str, ...] = ()
    security_sources: tuple[Mapping[str, object], ...] = ()
    format_checks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "skills", tuple(self.skills))
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "skill_results", tuple(self.skill_results))
        object.__setattr__(
            self,
            "planned_security_sources",
            tuple(self.planned_security_sources),
        )
        object.__setattr__(self, "security_sources", tuple(self.security_sources))
        object.__setattr__(self, "format_checks", tuple(self.format_checks))

    @property
    def severity(self) -> Severity:
        nested_items = tuple(
            item
            for skill in self.skill_results
            for item in (*skill.diagnostics, *skill.findings)
        )
        item_severities = tuple(
            item.severity
            for item in (*self.diagnostics, *self.findings, *nested_items)
        )
        skill_severities = tuple(skill.severity for skill in self.skills)
        return highest_status((*item_severities, *skill_severities))

    @property
    def status(self) -> CheckStatus:
        return status_for_severity(self.severity)

    @property
    def exit_code(self) -> int:
        diagnostics = (
            *self.diagnostics,
            *(
                diagnostic
                for skill_result in self.skill_results
                for diagnostic in skill_result.diagnostics
            ),
        )
        if any(_uses_error_exit_code(diagnostic) for diagnostic in diagnostics):
            return 2
        return 1 if self.status is CheckStatus.NOT_READY else 0


def highest_severity(items: Iterable[Diagnostic | Finding]) -> Severity:
    """Return the highest severity using FAIL > REVIEW > PASS precedence."""
    return highest_status(item.severity for item in items)


def highest_status(statuses: Iterable[Severity]) -> Severity:
    """Return the highest status using FAIL > REVIEW > PASS precedence."""
    severities = set(statuses)
    if Severity.FAIL in severities:
        return Severity.FAIL
    if Severity.REVIEW in severities:
        return Severity.REVIEW
    return Severity.PASS


def status_for_severity(severity: Severity) -> CheckStatus:
    if severity is Severity.FAIL:
        return CheckStatus.NOT_READY
    if severity is Severity.REVIEW:
        return CheckStatus.READY_WITH_WARNINGS
    return CheckStatus.READY


def _uses_error_exit_code(diagnostic: Diagnostic) -> bool:
    return diagnostic.is_execution_error or diagnostic.code in {
        "CONFIG_INVALID",
        "SKILL_SELECTOR_NOT_FOUND",
        "SKILL_SELECTOR_AMBIGUOUS",
    }


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
