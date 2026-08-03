from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from skills_eval.cli import app
from skills_eval.models import Severity
from skills_eval.security.base import (
    FindingLevel,
    ScanOutcome,
    ScanStatus,
    SecurityFinding,
)
from skills_eval.service import run_check


class _PerSkillScanner:
    """A mock provider returning a different outcome per skill directory name."""

    def __init__(self, name, outcomes):
        self.name = name
        self._outcomes = outcomes
        self.calls = []

    def is_available(self) -> bool:
        return True

    def get_version(self) -> str | None:
        return "1.0"

    def normalize_result(self, raw_result: object) -> tuple:
        return ()

    def scan(self, skill_path: Path, options: dict) -> ScanOutcome:
        self.calls.append(skill_path)
        return self._outcomes.get(skill_path.name, ScanOutcome(status=ScanStatus.PASS))


def _configure(root, sources):
    (root / ".skills-eval.json").write_text(
        json.dumps({"schemaVersion": 1, "security": {"sources": sources}}),
        encoding="utf-8",
    )


def test_multiple_providers_run_sequentially_and_isolate_failures(
    plugin_factory, monkeypatch
) -> None:
    root = plugin_factory(skills=["./safe", "./dangerous"])
    _configure(
        root,
        [
            {"name": "cisco", "enabled": True, "required": True},
            {"name": "skillspector", "enabled": True, "required": False},
        ],
    )
    cisco = _PerSkillScanner(
        "cisco",
        {
            "safe": ScanOutcome(status=ScanStatus.PASS),
            "dangerous": ScanOutcome(
                status=ScanStatus.FAIL,
                findings=(
                    SecurityFinding(
                        severity=Severity.FAIL,
                        code="C-HIGH",
                        message="Dangerous command",
                        source="cisco",
                        rule_id="C-HIGH",
                        level=FindingLevel.HIGH,
                    ),
                ),
            ),
        },
    )
    skillspector = _PerSkillScanner(
        "skillspector",
        {
            "safe": ScanOutcome(status=ScanStatus.WARN, findings=(
                SecurityFinding(
                    severity=Severity.REVIEW,
                    code="S-MED",
                    message="Vague description",
                    source="skillspector",
                    rule_id="S-MED",
                    level=FindingLevel.MEDIUM,
                ),
            ),),
            "dangerous": ScanOutcome(status=ScanStatus.PASS),
        },
    )
    monkeypatch.setattr(
        "skills_eval.security.summary.ScannerRegistry.create",
        lambda n: {"cisco": cisco, "skillspector": skillspector}[n],
    )

    result = run_check(root, selector=None, dry_run=False)

    # Both providers ran against both skills.
    assert len(cisco.calls) == 2
    assert len(skillspector.calls) == 2

    by_name = {s.name: s for s in result.skills}
    assert by_name["safe"].security_status is Severity.REVIEW  # skillspector WARN
    assert by_name["dangerous"].security_status is Severity.FAIL  # cisco FAIL

    assert result.security_overall is ScanStatus.FAIL
    assert result.exit_code == 1


def test_reports_generate_in_markdown_and_json(plugin_factory, monkeypatch, tmp_path) -> None:
    root = plugin_factory()
    _configure(root, [{"name": "cisco", "enabled": True, "required": True}])
    cisco = _PerSkillScanner(
        "cisco",
        {"write": ScanOutcome(status=ScanStatus.WARN, findings=(
            SecurityFinding(
                severity=Severity.REVIEW,
                code="PI-001",
                message="Injected instruction",
                source="cisco",
                rule_id="PI-001",
                level=FindingLevel.MEDIUM,
            ),
        ),)},
    )
    monkeypatch.setattr(
        "skills_eval.security.summary.ScannerRegistry.create",
        lambda n: cisco,
    )

    md_report = root / "skills-eval-report.md"
    json_report = tmp_path / "report.json"

    md_result = CliRunner().invoke(app, ["check", str(root)])
    json_result = CliRunner().invoke(
        app, ["check", str(root), "--format", "json", "--output", str(json_report)]
    )

    assert md_result.exit_code == 0, md_result.stdout
    assert md_report.is_file()
    md_text = md_report.read_text(encoding="utf-8")
    assert "## Security summary" in md_text or "## 安全汇总" in md_text
    assert "PI-001" in md_text

    assert json_result.exit_code == 0, json_result.stdout
    assert json_report.is_file()
    payload = json.loads(json_report.read_text(encoding="utf-8"))
    assert payload["security"]["overall"] == "WARN"
    assert payload["security"]["providers"][0]["name"] == "cisco"
    assert payload["security"]["providers"][0]["status"] == "WARN"
    assert payload["findings"][0]["ruleId"] == "PI-001"


def test_json_to_stdout_when_no_output(plugin_factory, monkeypatch) -> None:
    root = plugin_factory()
    _configure(root, [{"name": "cisco", "enabled": True, "required": True}])
    monkeypatch.setattr(
        "skills_eval.security.summary.ScannerRegistry.create",
        lambda n: _PerSkillScanner("cisco", {"write": ScanOutcome(status=ScanStatus.PASS)}),
    )

    result = CliRunner().invoke(app, ["check", str(root), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["security"]["overall"] == "PASS"
    # No markdown report is written in JSON-to-stdout mode.
    assert not (root / "skills-eval-report.md").exists()


def test_required_provider_error_returns_exit_code_two(plugin_factory, monkeypatch) -> None:
    root = plugin_factory()
    _configure(root, [{"name": "cisco", "enabled": True, "required": True}])

    class MissingCisco:
        name = "cisco"

        def is_available(self) -> bool:
            return False

        def get_version(self) -> str | None:
            return None

        def normalize_result(self, raw_result: object) -> tuple:
            return ()

        def scan(self, skill_path: Path, options: dict) -> ScanOutcome:
            raise AssertionError("should not scan when unavailable")

    monkeypatch.setattr(
        "skills_eval.security.summary.ScannerRegistry.create",
        lambda n: MissingCisco(),
    )

    result = CliRunner().invoke(app, ["check", str(root)])

    assert result.exit_code == 2
