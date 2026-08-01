from __future__ import annotations

import subprocess
from pathlib import Path

from skills_eval.models import Severity, Skill
from skills_eval.publishing_checks import run_publishing_checks


def _skill(name: str) -> Skill:
    return Skill(name=name, path=Path("/repo") / name)


def _targets(*names: str) -> tuple[dict[str, object], ...]:
    return tuple({"name": name, "enabled": True} for name in names)


def test_external_dry_run_plans_fixed_non_publishing_validation_commands() -> None:
    results = run_publishing_checks(
        Path("/repo"),
        (_skill("write"), _skill("translate")),
        _targets("claude-plugin", "workbuddy", "skillhub", "clawhub"),
        dry_run=True,
        requested=True,
    )

    assert [(result.target, result.status, result.command) for result in results] == [
        ("claude-plugin", None, ("claude", "plugin", "validate", ".")),
        ("workbuddy", None, results[1].command),
        ("skillhub", None, ("skillhub", "publish", "/repo/write", "--dry-run")),
        ("skillhub", None, ("skillhub", "publish", "/repo/translate", "--dry-run")),
        ("clawhub", None, ("clawhub", "package", "validate", ".")),
    ]
    assert results[1].command[1:] == (
        "plugin", "validate", ".claude-plugin/marketplace.json"
    )


def test_external_checks_only_run_for_selected_skill(monkeypatch) -> None:
    monkeypatch.setattr("skills_eval.publishing_checks._executable_exists", lambda command: True)
    calls: list[tuple[str, ...]] = []

    def runner(command, root):
        del root
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, "ok", "")

    results = run_publishing_checks(
        Path("/repo"),
        (_skill("translate"),),
        _targets("skillhub"),
        dry_run=False,
        requested=True,
        command_runner=runner,
    )

    assert calls == [("skillhub", "publish", "/repo/translate", "--dry-run")]
    assert results[0].status is Severity.PASS


def test_workbuddy_uses_configured_cli_path(monkeypatch) -> None:
    monkeypatch.setenv("CODEBUDDY_BIN", "/custom/codebuddy")
    monkeypatch.setattr("skills_eval.publishing_checks._executable_exists", lambda command: True)

    results = run_publishing_checks(
        Path("/repo"), (), _targets("workbuddy"), dry_run=True, requested=True
    )

    assert results[0].command[0] == "/custom/codebuddy"


def test_missing_external_cli_is_an_environment_error(monkeypatch) -> None:
    monkeypatch.setattr("skills_eval.publishing_checks._executable_exists", lambda command: False)

    results = run_publishing_checks(
        Path("/repo"), (), _targets("clawhub"), dry_run=False, requested=True
    )

    assert results[0].status is Severity.FAIL
    assert results[0].execution_error is True
    assert "Required executable was not found" in str(results[0].message)


def test_external_validator_failure_is_reported_as_a_validation_failure(monkeypatch) -> None:
    monkeypatch.setattr("skills_eval.publishing_checks._executable_exists", lambda command: True)

    results = run_publishing_checks(
        Path("/repo"),
        (),
        _targets("claude-plugin"),
        dry_run=False,
        requested=True,
        command_runner=lambda command, root: subprocess.CompletedProcess(
            command, 1, "", "manifest is invalid"
        ),
    )

    assert results[0].status is Severity.FAIL
    assert results[0].execution_error is False
    assert "manifest is invalid" in str(results[0].message)


def test_external_checks_are_opt_in() -> None:
    results = run_publishing_checks(
        Path("/repo"), (), _targets("claude-plugin"), dry_run=False, requested=False
    )

    assert results == ()
