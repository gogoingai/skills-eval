"""Deterministic orchestration for repository release checks."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from skills_eval.config import EvalConfig, load_config
from skills_eval.discovery import discover_plugin, select_skill
from skills_eval.format_checks import check_format
from skills_eval.localization import resolve_report_language
from skills_eval.models import (
    CheckResult,
    Diagnostic,
    Finding,
    Severity,
    Skill,
    SkillResult,
    highest_severity,
    highest_status,
)
from skills_eval.security import (
    ExecutionDiagnostic,
    ScannerRegistry,
    SecurityScanner,
)


def run_check(root: Path, selector: str | None, dry_run: bool) -> CheckResult:
    """Run configured format and security checks in deterministic order."""
    root = root.resolve()

    config, config_diagnostics = load_config(root)
    plugin, discovery_diagnostics = discover_plugin(root)
    global_diagnostics = [*config_diagnostics, *discovery_diagnostics]
    enabled_sources = _enabled_sources(config)
    planned_sources = tuple(_source_name(source) for source in enabled_sources)
    report_language = resolve_report_language(getattr(config, "report_language", "auto"))
    format_rules = _format_rules(config, report_language)

    if plugin is None:
        return CheckResult(
            plugin_name=root.name,
            root_path=root,
            selector=selector,
            report_language=report_language,
            diagnostics=tuple(global_diagnostics),
            dry_run=dry_run,
            planned_security_sources=planned_sources,
            security_sources=enabled_sources,
            format_checks=format_rules,
        )

    selected_skills, selection_diagnostics = select_skill(plugin, selector)
    global_diagnostics.extend(selection_diagnostics)

    format_diagnostics = check_format(root, plugin, selected_skills, config)
    skill_format_diagnostics, repository_format_diagnostics = (
        _associate_format_diagnostics(selected_skills, format_diagnostics)
    )
    global_diagnostics.extend(repository_format_diagnostics)

    scanner_entries: list[tuple[str, SecurityScanner, dict[str, object]]] = []
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

    checked_skills: list[Skill] = []
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
            security_status = highest_status(security_statuses)

        diagnostics = (*format_items, *security_diagnostics)
        checked_skill = Skill(
            name=skill.name,
            path=skill.path,
            frontmatter=skill.frontmatter,
            format_status=highest_severity(format_items),
            security_status=security_status,
        )
        checked_skills.append(checked_skill)
        skill_results.append(
            SkillResult(
                skill=checked_skill,
                diagnostics=diagnostics,
                findings=tuple(findings),
            )
        )

    return CheckResult(
        plugin_name=plugin.name,
        root_path=root,
        selector=selector,
        report_language=report_language,
        skills=tuple(checked_skills),
        diagnostics=tuple(global_diagnostics),
        skill_results=tuple(skill_results),
        dry_run=dry_run,
        planned_security_sources=planned_sources,
        security_sources=enabled_sources,
        format_checks=format_rules,
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


def _format_rules(config: EvalConfig, language: str) -> tuple[str, ...]:
    """Describe exactly which format checks this configuration enables."""
    if language == "en":
        rules = [
            "Claude Plugin manifest validity and declared Skill discovery",
            "Unique Skill names and non-conflicting declared Skill paths",
            "SKILL.md presence, YAML frontmatter, and required fields",
            "Local file references within the selected Skill directories",
            "Configured temporary or forbidden files",
        ]
        if config.require_marketplace_metadata:
            rules.append("Wenqu release metadata consistency")
        if config.require_openclaw_metadata:
            rules.append("OpenClaw homepage metadata")
        if config.require_image_references:
            rules.append("Wenqu image asset references")
        return tuple(rules)
    rules = [
        "Claude Plugin 清单有效性和已声明 Skill 的识别",
        "Skill 名称唯一性与声明路径冲突",
        "SKILL.md、YAML frontmatter 和必填字段",
        "所选 Skill 目录内的本地文件引用",
        "配置中禁止发布的临时文件",
    ]
    if config.require_marketplace_metadata:
        rules.append("Wenqu 发布元数据一致性")
    if config.require_openclaw_metadata:
        rules.append("OpenClaw 主页元数据")
    if config.require_image_references:
        rules.append("Wenqu 图片资源引用")
    return tuple(rules)


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
