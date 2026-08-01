"""Human-readable terminal and Markdown reports for completed checks."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
import json
import os
from pathlib import Path
import tempfile

from skills_eval.models import CheckResult, Diagnostic, Finding, Severity, Skill
from skills_eval.security import SecurityFinding


_CISCO_DISCLAIMER = (
    "Cisco AI Skill Scanner 只能提供辅助判断，不能保证某个 Skill 绝对安全。"
)


def render_terminal(result: CheckResult) -> str:
    """Render a concise, line-oriented summary suitable for a terminal."""
    lines = [f"Plugin: {_terminal_text(result.plugin_name)}", "Skills:"]
    if not result.skills:
        lines.append("  (none discovered)")
    for skill in result.skills:
        lines.extend(
            (
                f"- {_terminal_text(skill.name)}",
                f"  Format      {skill.format_status.value}",
                f"  Security    {_security_status(skill)}",
            )
        )
    if result.diagnostics:
        lines.extend(("Repository diagnostics:",))
        lines.extend(_terminal_diagnostic_line(diagnostic) for diagnostic in result.diagnostics)
    lines.append(f"Result: {result.status.value}")
    if result.dry_run:
        scanners = ", ".join(result.planned_security_sources) or "none"
        lines.append(f"Dry run: security scanners were not run (planned: {scanners}).")
    return "\n".join(lines)


def write_markdown_report(result: CheckResult, path: Path) -> None:
    """Write a complete Markdown report atomically to ``path``."""
    path = Path(path)
    report = _render_markdown(result, path)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(report)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _render_markdown(result: CheckResult, path: Path) -> str:
    if result.report_language == "en":
        return _render_markdown_en(result, path)
    return _render_markdown_zh(result, path)


def _render_markdown_zh(result: CheckResult, path: Path) -> str:
    lines = [
        "# Skills 审查报告",
        "",
        "## 本次结论",
        "",
        f"- 插件：{_markdown(result.plugin_name)}",
        f"- 审查结果：{result.status.value}",
        f"- 发布建议：{_release_recommendation(result, 'zh')}",
        f"- 演练模式：{'是（未执行安全扫描）' if result.dry_run else '否'}",
        "",
        "## 一句话总结",
        "",
        *_plain_summary(result, "zh"),
        "",
        "## 审查范围",
        "",
        f"- 目标目录：{_markdown(result.root_path) if result.root_path else '未记录'}",
        f"- 指定 Skill：{_markdown(result.selector) if result.selector else '全部已发现的 Skill'}",
        f"- 已检查 Skill：{len(result.skills)} 个",
        "- 安全扫描范围：逐个递归扫描已检查的 Skill 目录。",
        "",
        "## 已执行的格式检查",
        "",
    ]
    if result.format_checks:
        lines.extend(f"- {_markdown(rule)}" for rule in result.format_checks)
    else:
        lines.append("本次没有记录格式检查明细。")
    lines.extend(
        (
            "",
            "## 每个 Skill 检查了什么",
            "",
        )
    )
    if not result.skills:
        lines.append("没有选中任何 Skill。")
    else:
        for skill in result.skills:
            lines.extend(
                (
                    f"### {_markdown(skill.name)}",
                    "",
                    f"- 目录：{_markdown(skill.path)}",
                    "- 格式：SKILL.md、frontmatter、本地引用和已配置的文件规则。",
                    f"- 安全：{_security_coverage(result, skill, 'zh')}",
                    "",
                )
            )
    lines.extend(
        (
            "## 逐项结果",
            "",
        )
    )
    if not result.skills:
        lines.append("未发现任何 Skill。")
    else:
        for skill in result.skills:
            lines.extend(
                (
                    f"### {_markdown(skill.name)}",
                    "",
                    f"- 目录：{_markdown(skill.path)}",
                    f"- 格式：{skill.format_status.value}",
                    f"- 安全：{_security_status(skill)}",
                    "",
                )
            )

    lines.extend(("## 已启用的安全扫描器", ""))
    sources = tuple(source for source in result.security_sources if _is_enabled(source))
    if not sources:
        lines.append("没有启用安全扫描器。")
    else:
        for source in sources:
            name = source.get("name", "unknown")
            options = source.get("options", {})
            lines.append(f"- {_markdown(name)}: {_markdown(_json(options))}")
    lines.append("")

    lines.extend(("## 汇总", "", f"整体结果：{result.status.value}", ""))
    for skill in result.skills:
        lines.append(
            f"- {_markdown(skill.name)}：格式 {skill.format_status.value}；"
            f"安全 {_security_status(skill)}"
        )
    lines.append("")

    format_diagnostics, security_diagnostics = _group_diagnostics(result)
    lines.extend(("## 格式问题", ""))
    _append_grouped_diagnostics(lines, format_diagnostics, "zh")
    lines.extend(("", "## 安全问题", ""))
    _append_security_details(lines, result, security_diagnostics, "zh")
    lines.extend(("", "## Cisco 扫描器说明", "", _CISCO_DISCLAIMER, ""))
    return "\n".join(lines)


def _render_markdown_en(result: CheckResult, path: Path) -> str:
    lines = [
        "# Skills evaluation report",
        "",
        "## Result",
        "",
        f"- Plugin: {_markdown(result.plugin_name)}",
        f"- Status: {result.status.value}",
        f"- Release recommendation: {_release_recommendation(result, 'en')}",
        f"- Dry run: {'yes (security scanners were not run)' if result.dry_run else 'no'}",
        "",
        "## At a glance",
        "",
        *_plain_summary(result, "en"),
        "",
        "## Inspection scope",
        "",
        f"- Target directory: {_markdown(result.root_path) if result.root_path else 'not recorded'}",
        f"- Requested Skill: {_markdown(result.selector) if result.selector else 'all discovered Skills'}",
        f"- Skills checked: {len(result.skills)}",
        "- Security scan scope: each checked Skill directory, recursively.",
        "",
        "## Format checks performed",
        "",
    ]
    if result.format_checks:
        lines.extend(f"- {_markdown(rule)}" for rule in result.format_checks)
    else:
        lines.append("Format check details were not recorded for this run.")

    lines.extend(("", "## Skill results", ""))
    if not result.skills:
        lines.append("No Skills were selected for checking.")
    else:
        for skill in result.skills:
            lines.extend(
                (
                    f"### {_markdown(skill.name)}",
                    "",
                    f"- Directory: {_markdown(skill.path)}",
                    f"- Format: {skill.format_status.value}",
                    f"- Security: {_security_coverage(result, skill, 'en')}",
                    "",
                )
            )

    lines.extend(("## Enabled security scanners", ""))
    sources = tuple(source for source in result.security_sources if _is_enabled(source))
    if not sources:
        lines.append("No security scanners are enabled.")
    else:
        for source in sources:
            name = source.get("name", "unknown")
            options = source.get("options", {})
            lines.append(f"- {_markdown(name)}: {_markdown(_json(options))}")
    lines.append("")

    format_diagnostics, security_diagnostics = _group_diagnostics(result)
    lines.extend(("## Format diagnostics", ""))
    _append_grouped_diagnostics(lines, format_diagnostics, "en")
    lines.extend(("", "## Security findings", ""))
    _append_security_details(lines, result, security_diagnostics, "en")
    lines.extend(
        (
            "",
            "## Cisco scanner disclaimer",
            "",
            "Cisco AI Skill Scanner is a best-effort tool and does not guarantee that a Skill is safe.",
            "",
        )
    )
    return "\n".join(lines)


def _group_diagnostics(
    result: CheckResult,
) -> tuple[dict[str, list[Diagnostic]], dict[str, list[Diagnostic]]]:
    format_diagnostics: dict[str, list[Diagnostic]] = defaultdict(list)
    security_diagnostics: dict[str, list[Diagnostic]] = defaultdict(list)
    for diagnostic in result.diagnostics:
        target = security_diagnostics if diagnostic.is_execution_error else format_diagnostics
        target["Repository"].append(diagnostic)
    for skill_result in result.skill_results:
        for diagnostic in skill_result.diagnostics:
            target = security_diagnostics if diagnostic.is_execution_error else format_diagnostics
            target[skill_result.skill.name].append(diagnostic)
    return format_diagnostics, security_diagnostics


def _append_grouped_diagnostics(
    lines: list[str], diagnostics: dict[str, list[Diagnostic]], language: str
) -> None:
    if not diagnostics:
        lines.append("No format diagnostics." if language == "en" else "未发现格式问题。")
        return
    for group, group_diagnostics in diagnostics.items():
        lines.extend((f"### {_markdown(group)}", ""))
        for diagnostic in group_diagnostics:
            lines.append(_diagnostic_line(diagnostic))
        lines.append("")
    lines.pop()


def _append_security_details(
    lines: list[str], result: CheckResult, diagnostics: dict[str, list[Diagnostic]], language: str
) -> None:
    result_by_path = {skill_result.skill.path: skill_result for skill_result in result.skill_results}
    has_content = False
    for skill in result.skills:
        skill_diagnostics = diagnostics.get(skill.name, [])
        skill_result = result_by_path.get(skill.path)
        findings = skill_result.findings if skill_result is not None else ()
        if not skill_diagnostics and not findings:
            continue
        has_content = True
        lines.extend((f"### {_markdown(skill.name)}", ""))
        for diagnostic in skill_diagnostics:
            lines.append(_diagnostic_line(diagnostic))
        for finding in findings:
            _append_finding(lines, finding, language)
        lines.append("")

    repository_diagnostics = diagnostics.get("Repository", [])
    if repository_diagnostics:
        has_content = True
        lines.extend((("### Repository" if language == "en" else "### 仓库级问题"), ""))
        for diagnostic in repository_diagnostics:
            lines.append(_diagnostic_line(diagnostic))
        lines.append("")

    if not has_content:
        lines.append("No security findings." if language == "en" else "未发现安全问题。")
    elif lines[-1] == "":
        lines.pop()


def _append_finding(lines: list[str], finding: Finding, language: str) -> None:
    lines.append(
        f"- [{finding.severity.value}] {_markdown(finding.code)}: "
        f"{_markdown(_finding_summary(finding, language))}{_location(finding.path)}"
    )
    if isinstance(finding, SecurityFinding):
        details = (
            *((
                ("Source", finding.source),
                ("Rule", finding.rule_id),
                ("Source severity", finding.source_severity),
                ("Line", finding.line),
                ("Detail", finding.detail),
                ("Remediation", finding.remediation),
                ("Evidence", finding.evidence),
            ) if language == "en" else (
                ("来源", finding.source),
                ("规则", finding.rule_id),
                ("来源等级", finding.source_severity),
                ("行号", finding.line),
                ("原始详情", finding.detail),
                ("原始建议", finding.remediation),
                ("原始证据", finding.evidence),
            )),
        )
        for label, value in details:
            if value is not None and value != "":
                lines.append(f"  - {label}: {_markdown(value)}")


def _diagnostic_line(diagnostic: Diagnostic) -> str:
    return (
        f"- [{diagnostic.severity.value}] {_markdown(diagnostic.code)}: "
        f"{_markdown(diagnostic.message)}{_location(diagnostic.path)}"
    )


def _terminal_diagnostic_line(diagnostic: Diagnostic) -> str:
    location = "" if diagnostic.path is None else f" (path: {diagnostic.path})"
    return f"- [{diagnostic.severity.value}] {diagnostic.code}: {diagnostic.message}{location}"


def _location(path: Path | None) -> str:
    return "" if path is None else f" (path: {_markdown(path)})"


def _security_status(skill: Skill) -> str:
    return skill.security_status.value if skill.security_status is not None else "NOT RUN"


def _security_coverage(result: CheckResult, skill: Skill, language: str) -> str:
    if result.dry_run:
        sources = ", ".join(result.planned_security_sources)
        if language == "en":
            return f"not run (dry run; planned: {_markdown(sources or 'no enabled scanners')})"
        return f"未执行（演练模式；计划使用：{_markdown(sources or '没有启用扫描器')}）"
    sources = ", ".join(
        str(source.get("name", "unknown"))
        for source in result.security_sources
        if _is_enabled(source)
    )
    if not sources:
        return "no enabled scanners" if language == "en" else "没有启用扫描器"
    return f"{_markdown(sources)} — {_security_status(skill)}"


def _finding_summary(finding: Finding, language: str) -> str:
    if language == "en":
        return finding.message
    summaries = {
        "FILE_MAGIC_MISMATCH": "文件扩展名与扫描器识别的内容类型不一致，需要人工确认。",
        "PYCACHE_FILES_DETECTED": "发现 Python 缓存文件，不应随 Skill 一起发布。",
    }
    return summaries.get(finding.code, finding.message)


def _release_recommendation(result: CheckResult, language: str) -> str:
    if result.status.value == "READY":
        return "ready to publish" if language == "en" else "可以发布"
    if result.status.value == "READY WITH WARNINGS":
        return (
            "ready to publish, but review the REVIEW items first"
            if language == "en"
            else "可以发布，但请先查看“安全问题”中的 REVIEW 项"
        )
    return (
        "not ready to publish; resolve format or security findings first"
        if language == "en"
        else "暂不建议发布；请先处理“格式问题”或“安全问题”"
    )


def _plain_summary(result: CheckResult, language: str) -> tuple[str, str]:
    format_failures = [skill.name for skill in result.skills if skill.format_status is Severity.FAIL]
    if format_failures:
        format_summary = (
            f"- Format: {', '.join(format_failures)} did not pass and needs attention."
            if language == "en"
            else f"- 格式：{', '.join(format_failures)} 未通过，需要修复。"
        )
    else:
        format_summary = (
            "- Format: every checked Skill passed."
            if language == "en"
            else "- 格式：所有已检查的 Skill 均通过。"
        )

    if result.dry_run:
        security_summary = (
            "- Security: dry run; security scanners were not run."
            if language == "en"
            else "- 安全：演练模式，尚未执行安全扫描。"
        )
    else:
        reviews = [
            skill.name
            for skill in result.skills
            if skill.security_status is Severity.REVIEW
        ]
        failures = [
            skill.name for skill in result.skills if skill.security_status is Severity.FAIL
        ]
        if failures:
            security_summary = (
                f"- Security: {', '.join(failures)} did not pass and needs attention."
                if language == "en"
                else f"- 安全：{', '.join(failures)} 未通过，需要修复。"
            )
        elif reviews:
            security_summary = (
                f"- Security: {', '.join(reviews)} needs review; all others passed."
                if language == "en"
                else f"- 安全：{', '.join(reviews)} 需要人工确认；其余通过。"
            )
        else:
            security_summary = (
                "- Security: every checked Skill passed."
                if language == "en"
                else "- 安全：所有已检查的 Skill 均通过。"
            )
    return format_summary, security_summary


def _is_enabled(source: Mapping[str, object]) -> bool:
    return source.get("enabled") is not False


def _json(value: object) -> str:
    return json.dumps(_json_value(value), default=str, ensure_ascii=False, sort_keys=True)


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _markdown(value: object) -> str:
    """Escape external text before it is interpolated into Markdown."""
    replacements = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "\\": "\\\\",
        "`": "\\`",
        "*": "\\*",
        "_": "\\_",
        "[": "\\[",
        "]": "\\]",
        "(": "\\(",
        ")": "\\)",
        "#": "\\#",
        "+": "\\+",
        "!": "\\!",
        "|": "\\|",
        "{": "\\{",
        "}": "\\}",
        "\r": "",
        "\n": "\\n",
    }
    return "".join(replacements.get(character, character) for character in str(value))


def _terminal_text(value: object) -> str:
    """Keep untrusted names from injecting terminal control lines."""
    return "".join(
        " " if character in "\r\n\t" else character
        for character in str(value)
        if ord(character) >= 32
    )
