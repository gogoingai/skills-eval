from __future__ import annotations

import json
from pathlib import Path

from skills_eval.models import CheckResult, CheckStatus, Severity, Skill
from skills_eval.security import ExecutionDiagnostic, ScanOutcome, SecurityFinding
from skills_eval.service import run_check


class RecordingScanner:
    def __init__(self, outcomes: dict[str, ScanOutcome] | None = None) -> None:
        self.outcomes = outcomes or {}
        self.calls: list[tuple[Path, dict[str, object]]] = []

    def scan(self, skill_path: Path, options: dict[str, object]) -> ScanOutcome:
        self.calls.append((skill_path, options))
        return self.outcomes.get(skill_path.name, ScanOutcome(status=Severity.PASS))


class RaisingScanner:
    def scan(self, skill_path: Path, options: dict[str, object]) -> ScanOutcome:
        raise RuntimeError("adapter escaped its normal error boundary")


def _write_security_config(root: Path, sources: list[dict[str, object]]) -> None:
    (root / ".skills-eval.json").write_text(
        json.dumps({"schemaVersion": 1, "security": {"sources": sources}}),
        encoding="utf-8",
    )


def test_dry_run_discovers_checks_but_never_invokes_scanner(
    plugin_factory,
    monkeypatch,
) -> None:
    root = plugin_factory()
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("scanner must not run")

    monkeypatch.setattr("skills_eval.service.ScannerRegistry.create", fail_if_called)

    result = run_check(root, selector=None, dry_run=True)

    assert type(result) is CheckResult
    assert result.dry_run is True
    assert called is False
    assert result.planned_security_sources == ("cisco",)
    assert type(result.skills[0]) is Skill
    assert result.skills[0].format_status is Severity.PASS
    assert result.skills[0].security_status is None


def test_external_checks_only_receive_enabled_publishing_targets(
    plugin_factory,
    monkeypatch,
) -> None:
    root = plugin_factory()
    (root / ".skills-eval.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "publishing": {
                    "targets": [
                        {"name": "claude-plugin", "enabled": True},
                        {"name": "skillhub", "enabled": False},
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def record_checks(root, skills, targets, **kwargs):
        captured.update(skills=skills, targets=targets, kwargs=kwargs)
        return ()

    monkeypatch.setattr("skills_eval.service.run_publishing_checks", record_checks)

    run_check(root, selector=None, dry_run=True, external=True)

    assert [target["name"] for target in captured["targets"]] == ["claude-plugin"]
    assert captured["kwargs"] == {"dry_run": True, "requested": True}


def test_selector_scans_only_the_selected_skill_with_configured_options(
    plugin_factory,
    monkeypatch,
) -> None:
    root = plugin_factory(skills=["./write", "./translate"])
    _write_security_config(
        root,
        [
            {
                "name": "cisco",
                "enabled": True,
                "options": {"policy": "strict", "useBehavioral": True},
            }
        ],
    )
    scanner = RecordingScanner()
    monkeypatch.setattr(
        "skills_eval.service.ScannerRegistry.create",
        lambda name: scanner,
    )

    result = run_check(root, selector="translate", dry_run=False)

    assert [skill.name for skill in result.skills] == ["translate"]
    assert scanner.calls == [
        (
            (root / "translate").resolve(),
            {"policy": "strict", "useBehavioral": True},
        )
    ]


def test_format_failure_does_not_prevent_independent_security_scan(
    plugin_factory,
    monkeypatch,
) -> None:
    root = plugin_factory()
    skill_file = root / "write" / "SKILL.md"
    skill_file.write_text(
        "---\nname: write\n---\nUseful instructions.\n",
        encoding="utf-8",
    )
    scanner = RecordingScanner(
        {
            "write": ScanOutcome(
                status=Severity.REVIEW,
                findings=(
                    SecurityFinding(
                        severity=Severity.REVIEW,
                        code="CISCO-1",
                        message="Review this behavior.",
                        source="cisco",
                        rule_id="CISCO-1",
                    ),
                ),
            )
        }
    )
    monkeypatch.setattr(
        "skills_eval.service.ScannerRegistry.create",
        lambda name: scanner,
    )

    result = run_check(root, selector=None, dry_run=False)

    skill = result.skills[0]
    assert scanner.calls[0][0] == (root / "write").resolve()
    assert skill.format_status is Severity.FAIL
    assert skill.security_status is Severity.REVIEW
    assert [item.code for item in result.skill_results[0].diagnostics] == [
        "FRONTMATTER_REQUIRED"
    ]
    assert [item.code for item in result.skill_results[0].findings] == ["CISCO-1"]
    assert result.status is CheckStatus.NOT_READY
    assert result.exit_code == 1


def test_scanner_execution_diagnostic_is_associated_with_the_scanned_skill(
    plugin_factory,
    monkeypatch,
) -> None:
    root = plugin_factory()
    scanner = RecordingScanner(
        {
            "write": ScanOutcome(
                status=Severity.FAIL,
                diagnostic=ExecutionDiagnostic(
                    severity=Severity.FAIL,
                    code="CISCO_PROCESS_FAILED",
                    message="Cisco scanner failed.",
                ),
            )
        }
    )
    monkeypatch.setattr(
        "skills_eval.service.ScannerRegistry.create",
        lambda name: scanner,
    )

    result = run_check(root, selector=None, dry_run=False)

    assert result.skills[0].security_status is Severity.FAIL
    assert [item.code for item in result.skill_results[0].diagnostics] == [
        "CISCO_PROCESS_FAILED"
    ]
    assert result.diagnostics == ()
    assert result.status is CheckStatus.NOT_READY
    assert result.exit_code == 2


def test_unexpected_scanner_exception_becomes_per_skill_execution_error(
    plugin_factory,
    monkeypatch,
) -> None:
    root = plugin_factory()
    monkeypatch.setattr(
        "skills_eval.service.ScannerRegistry.create",
        lambda name: RaisingScanner(),
    )

    result = run_check(root, selector=None, dry_run=False)

    assert result.skills[0].security_status is Severity.FAIL
    assert [item.code for item in result.skill_results[0].diagnostics] == [
        "SCANNER_EXECUTION_ERROR"
    ]
    assert result.exit_code == 2


def test_invalid_configuration_remains_global_while_safe_checks_continue(
    plugin_factory,
    monkeypatch,
) -> None:
    root = plugin_factory()
    (root / ".skills-eval.json").write_text(
        json.dumps({"schemaVersion": 1, "unexpected": True}),
        encoding="utf-8",
    )
    scanner = RecordingScanner()
    monkeypatch.setattr(
        "skills_eval.service.ScannerRegistry.create",
        lambda name: scanner,
    )

    result = run_check(root, selector=None, dry_run=False)

    assert [item.code for item in result.diagnostics] == ["CONFIG_INVALID"]
    assert result.skill_results[0].diagnostics == ()
    assert result.skills[0].security_status is Severity.PASS
    assert len(scanner.calls) == 1
    assert result.status is CheckStatus.NOT_READY
    assert result.exit_code == 2


def test_selector_error_uses_invocation_exit_code(plugin_factory) -> None:
    root = plugin_factory()

    result = run_check(root, selector="missing", dry_run=True)

    assert [item.code for item in result.diagnostics] == [
        "SKILL_SELECTOR_NOT_FOUND"
    ]
    assert result.exit_code == 2


def test_all_enabled_scanners_run_and_fail_takes_precedence(
    plugin_factory,
    monkeypatch,
) -> None:
    root = plugin_factory()
    scanners = {
        "first": RecordingScanner(
            {
                "write": ScanOutcome(
                    status=Severity.REVIEW,
                    findings=(
                        SecurityFinding(
                            severity=Severity.REVIEW,
                            code="FIRST-1",
                            message="Review.",
                            source="first",
                            rule_id="FIRST-1",
                        ),
                    ),
                )
            }
        ),
        "second": RecordingScanner(
            {
                "write": ScanOutcome(
                    status=Severity.FAIL,
                    findings=(
                        SecurityFinding(
                            severity=Severity.FAIL,
                            code="SECOND-1",
                            message="Block.",
                            source="second",
                            rule_id="SECOND-1",
                        ),
                    ),
                )
            }
        ),
    }
    monkeypatch.setattr(
        "skills_eval.service.load_config",
        lambda checked_root: (
            type(
                "Config",
                (),
                {
                    "required_root_files": (),
                    "required_skill_frontmatter": ("name", "description"),
                    "forbidden_paths": (),
                    "reference_extensions": (".md",),
                    "publishing_targets": (),
                    "security_sources": (
                        {"name": "first", "enabled": True},
                        {"name": "disabled", "enabled": False},
                        {"name": "second", "enabled": True},
                    ),
                },
            )(),
            [],
        ),
    )
    monkeypatch.setattr(
        "skills_eval.service.ScannerRegistry.create",
        lambda name: scanners[name],
    )

    result = run_check(root, selector=None, dry_run=False)

    assert result.planned_security_sources == ("first", "second")
    assert result.skills[0].security_status is Severity.FAIL
    assert [item.code for item in result.skill_results[0].findings] == [
        "FIRST-1",
        "SECOND-1",
    ]
    assert len(scanners["first"].calls) == 1
    assert len(scanners["second"].calls) == 1
    assert result.exit_code == 1
