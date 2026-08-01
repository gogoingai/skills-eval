from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import pytest

from skills_eval.models import CheckResult, CheckStatus, Diagnostic, Severity, Skill
from skills_eval.reporting import render_terminal, write_markdown_report


def test_markdown_report_includes_cisco_disclaimer(sample_result, tmp_path) -> None:
    output = tmp_path / "skills-eval-report.md"

    write_markdown_report(sample_result, output)

    text = output.read_text(encoding="utf-8")
    assert "READY WITH WARNINGS" in text
    assert "不能保证某个 Skill 绝对安全" in text


def test_markdown_report_describes_scope_and_per_skill_coverage(sample_result, tmp_path) -> None:
    output = tmp_path / "skills-eval-report.md"

    write_markdown_report(sample_result, output)

    text = output.read_text(encoding="utf-8")
    assert "## 审查范围" in text
    assert "已检查 Skill：1 个" in text
    assert "## 已执行的格式检查" in text
    assert "## 每个 Skill 检查了什么" in text
    assert "安全：cisco — REVIEW" in text
    assert "格式：所有已检查的 Skill 均通过。" in text
    assert "安全：write 需要人工确认；其余通过。" in text


def test_terminal_summary_uses_requested_status_labels(sample_result) -> None:
    terminal = render_terminal(sample_result)

    assert "Format      PASS" in terminal
    assert "Security    REVIEW" in terminal


def test_terminal_summary_includes_repository_diagnostics() -> None:
    result = CheckResult(
        plugin_name="example",
        diagnostics=(Diagnostic(Severity.FAIL, "CONFIG_INVALID", "Bad config"),),
    )

    terminal = render_terminal(result)

    assert "Repository diagnostics:" in terminal
    assert "[FAIL] CONFIG_INVALID: Bad config" in terminal


@pytest.mark.parametrize(
    ("severity", "expected_status"),
    [
        (Severity.PASS, CheckStatus.READY.value),
        (Severity.REVIEW, CheckStatus.READY_WITH_WARNINGS.value),
        (Severity.FAIL, CheckStatus.NOT_READY.value),
    ],
)
def test_terminal_renders_each_overall_status(severity, expected_status) -> None:
    skill = Skill(
        name="write",
        path=Path("write"),
        format_status=severity,
        security_status=Severity.PASS,
    )

    terminal = render_terminal(CheckResult(plugin_name="example", skills=(skill,)))

    assert f"Result: {expected_status}" in terminal


def test_markdown_report_escapes_repository_supplied_metadata(tmp_path) -> None:
    skill = Skill(
        name="name ](https://unsafe.example)",
        path=Path("skills/<script>"),
        frontmatter={"description": "not trusted"},
    )
    result = CheckResult(
        plugin_name="plugin <img src=x>",
        skills=(skill,),
        diagnostics=(
            Diagnostic(
                Severity.REVIEW,
                "FORMAT-1",
                "[change](https://unsafe.example) <script>",
                Path("<untrusted>.md"),
            ),
        ),
        security_sources=(
            {"name": "cisco", "enabled": True, "options": {"note": "<unsafe>"}},
        ),
    )
    output = tmp_path / "report.md"

    write_markdown_report(result, output)

    text = output.read_text(encoding="utf-8")
    assert "plugin &lt;img src=x&gt;" in text
    assert r"\[change\]\(https://unsafe.example\) &lt;script&gt;" in text
    assert "<script>" not in text
    assert "<img src=x>" not in text


def test_markdown_report_includes_detailed_cisco_finding(sample_result, tmp_path) -> None:
    output = tmp_path / "report.md"

    write_markdown_report(sample_result, output)

    text = output.read_text(encoding="utf-8")
    assert "PI-001" in text
    assert "来源等级: medium" in text
    assert "行号: 12" in text
    assert "Untrusted text requests an unsafe action." in text
    assert "Treat the text as data." in text
    assert "ignore previous instructions" in text


def test_markdown_report_writes_to_the_requested_path_without_temp_files(
    sample_result, tmp_path
) -> None:
    output = tmp_path / "nested" / "report.md"
    output.parent.mkdir()

    write_markdown_report(sample_result, output)

    assert output.exists()
    assert list(output.parent.glob(".report.md.*.tmp")) == []


def test_markdown_report_serializes_immutable_scanner_options(tmp_path) -> None:
    result = CheckResult(
        plugin_name="example",
        security_sources=(
            MappingProxyType(
                {
                    "name": "cisco",
                    "enabled": True,
                    "options": MappingProxyType({"policy": "strict"}),
                }
            ),
        ),
    )
    output = tmp_path / "report.md"

    write_markdown_report(result, output)

    assert '"policy": "strict"' in output.read_text(encoding="utf-8")
