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
from skills_eval.publishing_checks import run_publishing_checks
from skills_eval.security import (
    ExecutionDiagnostic,
    ScannerRegistry,
    SecurityScanner,
)


def run_check(
    root: Path,
    selector: str | None,
    dry_run: bool,
    external: bool = False,
    external_targets: tuple[str, ...] = (),
) -> CheckResult:
    """Run configured format and security checks in deterministic order."""
    root = root.resolve()

    config, config_diagnostics = load_config(root)
    plugin, discovery_diagnostics = discover_plugin(root)
    global_diagnostics = [*config_diagnostics, *discovery_diagnostics]
    enabled_sources = _enabled_sources(config)
    enabled_publishing_targets = _enabled_publishing_targets(config)
    selected_publishing_targets, target_diagnostics = _select_publishing_targets(
        enabled_publishing_targets, external_targets
    )
    global_diagnostics.extend(target_diagnostics)
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
            publishing_targets=enabled_publishing_targets,
            format_checks=format_rules,
            external_checks_requested=external or bool(external_targets),
            requested_external_targets=external_targets,
        )

    selected_skills, selection_diagnostics = select_skill(plugin, selector)
    global_diagnostics.extend(selection_diagnostics)

    format_diagnostics = check_format(root, plugin, selected_skills, config)
    skill_format_diagnostics, repository_format_diagnostics = (
        _associate_format_diagnostics(selected_skills, format_diagnostics)
    )
    global_diagnostics.extend(repository_format_diagnostics)

    publishing_checks = run_publishing_checks(
        root,
        tuple(selected_skills),
        selected_publishing_targets,
        dry_run=dry_run,
        requested=external or bool(external_targets),
    )

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
        publishing_targets=enabled_publishing_targets,
        format_checks=format_rules,
        publishing_checks=publishing_checks,
        external_checks_requested=external or bool(external_targets),
        requested_external_targets=external_targets,
    )


def _enabled_sources(config: EvalConfig) -> tuple[Mapping[str, object], ...]:
    return tuple(
        source for source in config.security_sources if source.get("enabled") is True
    )


def _enabled_publishing_targets(config: EvalConfig) -> tuple[Mapping[str, object], ...]:
    return tuple(
        target
        for target in getattr(config, "publishing_targets", ())
        if target.get("enabled") is True
    )


def _select_publishing_targets(
    enabled_targets: tuple[Mapping[str, object], ...],
    requested_targets: tuple[str, ...],
) -> tuple[tuple[Mapping[str, object], ...], tuple[Diagnostic, ...]]:
    """Select explicitly requested native validators without enabling disabled targets."""
    if not requested_targets:
        return enabled_targets, ()

    requested_names = set(requested_targets)
    enabled_by_name = {_source_name(target): target for target in enabled_targets}
    diagnostics: list[Diagnostic] = []
    for name in dict.fromkeys(requested_targets):
        if name not in enabled_by_name:
            diagnostics.append(
                Diagnostic(
                    Severity.FAIL,
                    "PUBLISHING_TARGET_NOT_ENABLED",
                    f"External publishing target {name!r} is not enabled by this configuration.",
                )
            )
    selected = tuple(
        target for target in enabled_targets if _source_name(target) in requested_names
    )
    return selected, tuple(diagnostics)


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
        rules.extend(_publishing_target_rules(config, "en"))
        return tuple(rules)
    rules = [
        "Claude Plugin 清单有效性和已声明 Skill 的识别",
        "Skill 名称唯一性与声明路径冲突",
        "SKILL.md、YAML frontmatter 和必填字段",
        "所选 Skill 目录内的本地文件引用",
        "配置中禁止发布的临时文件",
    ]
    rules.extend(_publishing_target_rules(config, "zh"))
    return tuple(rules)


def _publishing_target_rules(config: EvalConfig, language: str) -> list[str]:
    enabled = {_source_name(target) for target in _enabled_publishing_targets(config)}
    if not enabled:
        return []
    if language == "en":
        rules = ["Wenqu release version, changelog, and image asset references"]
        descriptions = {
            "claude-plugin": "claude-plugin: plugin and marketplace metadata; undeclared wenqu-* Skills",
            "workbuddy": "workbuddy: display name, version, summary, and license metadata",
            "skillhub": "skillhub: unique valid slugs and no images inside a Skill package",
            "openclaw": "openclaw: plugin version and HTTPS homepage metadata",
            "clawhub": "clawhub: package identity and version consistency",
        }
    else:
        rules = ["Wenqu 共用基线：版本、变更日志和图片资源引用"]
        descriptions = {
            "claude-plugin": "claude-plugin：plugin 与 marketplace 元数据；未声明的 wenqu-* Skill",
            "workbuddy": "workbuddy：displayName、version、summary、license 元数据",
            "skillhub": "skillhub：合法且唯一的 slug；Skill 包内禁止图片",
            "openclaw": "openclaw：插件版本和 HTTPS 主页元数据",
            "clawhub": "clawhub：package 包名与版本一致性",
        }
    rules.extend(descriptions[name] for name in descriptions if name in enabled)
    return rules


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
