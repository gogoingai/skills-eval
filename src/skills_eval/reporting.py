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
    "Cisco AI Skill Scanner is a best-effort tool and does not guarantee "
    "that a Skill is safe."
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
    lines = [
        "# Skills evaluation report",
        "",
        "## Run metadata",
        "",
        f"- Plugin: {_markdown(result.plugin_name)}",
        f"- Result: {result.status.value}",
        f"- Dry run: {'yes' if result.dry_run else 'no'}",
        f"- Report path: {_markdown(path)}",
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
    lines.extend(
        (
            "",
            "## Per-Skill coverage",
            "",
        )
    )
    if not result.skills:
        lines.append("No Skills were selected for checking.")
    else:
        for skill in result.skills:
            lines.extend(
                (
                    f"### {_markdown(skill.name)}",
                    "",
                    f"- Directory: {_markdown(skill.path)}",
                    "- Format coverage: SKILL.md, frontmatter, local references, and configured file rules.",
                    f"- Security coverage: {_security_coverage(result, skill)}",
                    "",
                )
            )
    lines.extend(
        (
            "## Discovered Skills",
            "",
        )
    )
    if not result.skills:
        lines.append("No Skills were discovered.")
    else:
        for skill in result.skills:
            lines.extend(
                (
                    f"### {_markdown(skill.name)}",
                    "",
                    f"- Path: {_markdown(skill.path)}",
                    f"- Format: {skill.format_status.value}",
                    f"- Security: {_security_status(skill)}",
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

    lines.extend(("## Status summary", "", f"Overall result: {result.status.value}", ""))
    for skill in result.skills:
        lines.append(
            f"- {_markdown(skill.name)} — Format: {skill.format_status.value}; "
            f"Security: {_security_status(skill)}"
        )
    lines.append("")

    format_diagnostics, security_diagnostics = _group_diagnostics(result)
    lines.extend(("## Format diagnostics", ""))
    _append_grouped_diagnostics(lines, format_diagnostics)
    lines.extend(("", "## Security findings", ""))
    _append_security_details(lines, result, security_diagnostics)
    lines.extend(("", "## Cisco scanner disclaimer", "", _CISCO_DISCLAIMER, ""))
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
    lines: list[str], diagnostics: dict[str, list[Diagnostic]]
) -> None:
    if not diagnostics:
        lines.append("No format diagnostics.")
        return
    for group, group_diagnostics in diagnostics.items():
        lines.extend((f"### {_markdown(group)}", ""))
        for diagnostic in group_diagnostics:
            lines.append(_diagnostic_line(diagnostic))
        lines.append("")
    lines.pop()


def _append_security_details(
    lines: list[str], result: CheckResult, diagnostics: dict[str, list[Diagnostic]]
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
            _append_finding(lines, finding)
        lines.append("")

    repository_diagnostics = diagnostics.get("Repository", [])
    if repository_diagnostics:
        has_content = True
        lines.extend(("### Repository", ""))
        for diagnostic in repository_diagnostics:
            lines.append(_diagnostic_line(diagnostic))
        lines.append("")

    if not has_content:
        lines.append("No security findings.")
    elif lines[-1] == "":
        lines.pop()


def _append_finding(lines: list[str], finding: Finding) -> None:
    lines.append(
        f"- [{finding.severity.value}] {_markdown(finding.code)}: "
        f"{_markdown(finding.message)}{_location(finding.path)}"
    )
    if isinstance(finding, SecurityFinding):
        details = (
            ("Source", finding.source),
            ("Rule", finding.rule_id),
            ("Source severity", finding.source_severity),
            ("Line", finding.line),
            ("Detail", finding.detail),
            ("Remediation", finding.remediation),
            ("Evidence", finding.evidence),
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


def _security_coverage(result: CheckResult, skill: Skill) -> str:
    if result.dry_run:
        sources = ", ".join(result.planned_security_sources) or "no enabled scanners"
        return f"not run (dry run; planned: {_markdown(sources)})"
    sources = ", ".join(
        str(source.get("name", "unknown"))
        for source in result.security_sources
        if _is_enabled(source)
    )
    if not sources:
        return "no enabled scanners"
    return f"{_markdown(sources)} — {_security_status(skill)}"


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
