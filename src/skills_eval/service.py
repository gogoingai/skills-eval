"""Deterministic orchestration for repository release checks."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from skills_eval.config import EvalConfig, load_config
from skills_eval.discovery import discover_plugin, select_skill
from skills_eval.format_checks import check_format
from skills_eval.models import (
    CheckResult,
    CheckStatus,
    Diagnostic,
    Finding,
    Severity,
    Skill,
    SkillResult,
    highest_severity,
)
from skills_eval.security import ExecutionDiagnostic, ScannerRegistry


@dataclass(frozen=True)
class CheckedSkill(Skill):
    """A discovered Skill enriched with the checks performed by this service."""

    format_status: Severity = Severity.PASS
    security_status: Severity | None = None
    planned_security_sources: tuple[str, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    findings: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        object.__setattr__(
            self,
            "planned_security_sources",
            tuple(self.planned_security_sources),
        )
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "findings", tuple(self.findings))

    @property
    def severity(self) -> Severity:
        return _highest_status(
            self.format_status,
            self.security_status or Severity.PASS,
        )

    @property
    def status(self) -> CheckStatus:
        return _check_status(self.severity)


@dataclass(frozen=True)
class ServiceCheckResult(CheckResult):
    """A shared CheckResult with service execution metadata."""

    dry_run: bool = False
    planned_security_sources: tuple[str, ...] = ()
    security_sources: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        object.__setattr__(
            self,
            "planned_security_sources",
            tuple(self.planned_security_sources),
        )
        object.__setattr__(self, "security_sources", tuple(self.security_sources))

    @property
    def severity(self) -> Severity:
        global_severity = highest_severity((*self.diagnostics, *self.findings))
        skill_severities = tuple(
            skill.severity
            for skill in self.skills
            if isinstance(skill, CheckedSkill)
        )
        return _highest_status(global_severity, *skill_severities)

    @property
    def exit_code(self) -> int:
        diagnostics = (
            *self.diagnostics,
            *(
                diagnostic
                for skill in self.skills
                if isinstance(skill, CheckedSkill)
                for diagnostic in skill.diagnostics
            ),
        )
        if any(_is_invocation_or_execution_error(item) for item in diagnostics):
            return 2
        return super().exit_code


def run_check(root: Path, selector: str | None, dry_run: bool) -> CheckResult:
    """Run configured format and security checks in deterministic order."""
    root = root.resolve()

    config, config_diagnostics = load_config(root)
    plugin, discovery_diagnostics = discover_plugin(root)
    global_diagnostics = [*config_diagnostics, *discovery_diagnostics]
    enabled_sources = _enabled_sources(config)
    planned_sources = tuple(_source_name(source) for source in enabled_sources)

    if plugin is None:
        return ServiceCheckResult(
            plugin_name=root.name,
            diagnostics=tuple(global_diagnostics),
            dry_run=dry_run,
            planned_security_sources=planned_sources,
            security_sources=enabled_sources,
        )

    selected_skills, selection_diagnostics = select_skill(plugin, selector)
    global_diagnostics.extend(selection_diagnostics)

    format_diagnostics = check_format(root, plugin, selected_skills, config)
    skill_format_diagnostics, repository_format_diagnostics = (
        _associate_format_diagnostics(selected_skills, format_diagnostics)
    )
    global_diagnostics.extend(repository_format_diagnostics)

    scanner_entries: list[tuple[str, object, dict[str, object]]] = []
    scanner_creation_failed = False
    if not dry_run:
        for source in enabled_sources:
            name = _source_name(source)
            try:
                scanner = ScannerRegistry.create(name)
            except Exception as error:
                scanner_creation_failed = True
                global_diagnostics.append(
                    ExecutionDiagnostic(
                        severity=Severity.FAIL,
                        code="SCANNER_CREATE_FAILED",
                        message=f"Security scanner {name!r} could not be created: {error}",
                    )
                )
                continue
            scanner_entries.append((name, scanner, _source_options(source)))

    checked_skills: list[CheckedSkill] = []
    skill_results: list[SkillResult] = []
    for skill in selected_skills:
        format_items = skill_format_diagnostics.get(skill.path, [])
        security_status: Severity | None = None
        security_diagnostics: list[Diagnostic] = []
        findings: list[Finding] = []

        if not dry_run:
            security_statuses: list[Severity] = []
            if scanner_creation_failed:
                security_statuses.append(Severity.FAIL)
            for name, scanner, options in scanner_entries:
                try:
                    outcome = scanner.scan(skill.path, options)
                except Exception as error:
                    security_statuses.append(Severity.FAIL)
                    security_diagnostics.append(
                        ExecutionDiagnostic(
                            severity=Severity.FAIL,
                            code="SCANNER_EXECUTION_ERROR",
                            message=f"Security scanner {name!r} failed: {error}",
                            path=skill.path,
                        )
                    )
                    continue
                security_statuses.append(outcome.status)
                findings.extend(outcome.findings)
                if outcome.diagnostic is not None:
                    security_diagnostics.append(outcome.diagnostic)
            security_status = _highest_status(*security_statuses)

        diagnostics = (*format_items, *security_diagnostics)
        checked_skill = CheckedSkill(
            name=skill.name,
            path=skill.path,
            frontmatter=skill.frontmatter,
            format_status=highest_severity(format_items),
            security_status=security_status,
            planned_security_sources=planned_sources,
            diagnostics=diagnostics,
            findings=tuple(findings),
        )
        checked_skills.append(checked_skill)
        skill_results.append(
            SkillResult(
                skill=checked_skill,
                diagnostics=diagnostics,
                findings=tuple(findings),
            )
        )

    return ServiceCheckResult(
        plugin_name=plugin.name,
        skills=tuple(checked_skills),
        diagnostics=tuple(global_diagnostics),
        skill_results=tuple(skill_results),
        dry_run=dry_run,
        planned_security_sources=planned_sources,
        security_sources=enabled_sources,
    )


def _enabled_sources(config: EvalConfig) -> tuple[Mapping[str, object], ...]:
    return tuple(
        source for source in config.security_sources if source.get("enabled") is True
    )


def _source_name(source: Mapping[str, object]) -> str:
    name = source.get("name")
    assert isinstance(name, str)
    return name


def _source_options(source: Mapping[str, object]) -> dict[str, object]:
    options = source.get("options", {})
    assert isinstance(options, Mapping)
    return dict(options)


def _associate_format_diagnostics(
    skills: list[Skill],
    diagnostics: list[Diagnostic],
) -> tuple[dict[Path, list[Diagnostic]], list[Diagnostic]]:
    associated = {skill.path: [] for skill in skills}
    repository: list[Diagnostic] = []
    most_specific_skills = sorted(
        skills,
        key=lambda skill: len(skill.path.parts),
        reverse=True,
    )

    for diagnostic in diagnostics:
        if diagnostic.path is None:
            repository.append(diagnostic)
            continue
        matching_skill = next(
            (
                skill
                for skill in most_specific_skills
                if diagnostic.path == skill.path
                or skill.path in diagnostic.path.parents
            ),
            None,
        )
        if matching_skill is None:
            repository.append(diagnostic)
        else:
            associated[matching_skill.path].append(diagnostic)
    return associated, repository


def _highest_status(*statuses: Severity) -> Severity:
    if Severity.FAIL in statuses:
        return Severity.FAIL
    if Severity.REVIEW in statuses:
        return Severity.REVIEW
    return Severity.PASS


def _check_status(severity: Severity) -> CheckStatus:
    if severity is Severity.FAIL:
        return CheckStatus.NOT_READY
    if severity is Severity.REVIEW:
        return CheckStatus.READY_WITH_WARNINGS
    return CheckStatus.READY


def _is_invocation_or_execution_error(diagnostic: Diagnostic) -> bool:
    return isinstance(diagnostic, ExecutionDiagnostic) or diagnostic.code in {
        "CONFIG_INVALID",
        "SKILL_SELECTOR_NOT_FOUND",
        "SKILL_SELECTOR_AMBIGUOUS",
    }
