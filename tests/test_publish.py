from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from skills_eval.models import CheckResult, Diagnostic, Severity
from skills_eval.publish import run_publish

ENV = {"GITHUB_SHA": "abc123def456", "GITHUB_REF_NAME": "master"}

CLAWHUB_TARGET = {
    "name": "clawhub",
    "enabled": True,
    "options": {
        "packageName": "@gogoingai/wenqu-skills",
        "owner": "gogoingai",
        "sourceRepo": "gogoingai/wenqu-skills",
    },
}
SKILLHUB_TARGET = {"name": "skillhub", "enabled": True}


def make_repo(
    tmp_path: Path,
    *,
    skills: tuple[str, ...] = ("wenqu-write", "wenqu-review"),
    targets: list[dict[str, object]] | None = None,
    version: str | None = "0.2.0",
) -> Path:
    root = tmp_path / "plugin"
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "wenqu-skills", "skills": [f"./{skill}" for skill in skills]}),
        encoding="utf-8",
    )
    for skill in skills:
        skill_dir = root / skill
        skill_dir.mkdir()
        version_line = f"version: {version}\n" if version else ""
        (skill_dir / "SKILL.md").write_text(
            f"---\nname: {skill}\ndescription: test\nslug: {skill}\n"
            f"displayName: {skill.title()}\n{version_line}---\nbody\n",
            encoding="utf-8",
        )
    (root / "VERSION").write_text("0.2.0\n", encoding="utf-8")
    (root / ".skills-eval.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "publishing": {"targets": targets or [CLAWHUB_TARGET, SKILLHUB_TARGET]},
            }
        ),
        encoding="utf-8",
    )
    return root


def ok(command, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 0, stdout, stderr)


def fail(command, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 1, "", stderr)


@pytest.fixture
def logged_in(monkeypatch):
    """Bypass CLI presence checks and the defensive check gate."""
    monkeypatch.setattr("skills_eval.publish._executable_exists", lambda command: True)
    monkeypatch.setattr(
        "skills_eval.publish.run_check",
        lambda *args, **kwargs: CheckResult(plugin_name="wenqu-skills"),
    )


def publish(root: Path, calls: list[tuple[str, ...]], out: list[str], **kwargs):
    def runner(command, root):
        command = tuple(command)
        calls.append(command)
        if command[0] == "git":
            return ok(command)
        if command[1:] == ("whoami",) or command[1:] == ("auth", "whoami"):
            return ok(command, stdout="gogoingai")
        return ok(command)

    kwargs.setdefault("command_runner", runner)
    kwargs.setdefault("sleeper", lambda seconds: None)
    kwargs.setdefault("env", ENV)
    kwargs.setdefault("out", out.append)
    return run_publish(root, **kwargs)


def test_dry_run_plans_commands_without_executing(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    calls: list[tuple[str, ...]] = []
    out: list[str] = []

    summary = publish(root, calls, out, dry_run=True, targets=("clawhub",), changelog="测试发布")

    assert summary.exit_code == 0
    assert calls == []
    planned = [line for line in out if "[dry-run]" in line]
    assert len(planned) == 3  # two skills + plugin package
    assert (
        f"clawhub skill publish {root / 'wenqu-write'} --slug wenqu-write "
        "--name Wenqu-Write --version 0.2.0 --owner gogoingai --changelog '测试发布' "
        "--source-commit abc123def456 --source-ref master --source-path wenqu-write "
        "--source-repo gogoingai/wenqu-skills"
    ) in planned[0]
    assert (
        "clawhub package publish . --family bundle-plugin "
        "--name @gogoingai/wenqu-skills --version 0.2.0 --owner gogoingai"
    ) in planned[2]
    assert "预检完成" in out[-1]


def test_dry_run_plans_skillhub_commands(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    out: list[str] = []

    summary = publish(root, [], out, dry_run=True, targets=("skillhub",))

    assert summary.exit_code == 0
    planned = [line for line in out if "[dry-run]" in line]
    assert planned == [
        f"  [dry-run] skillhub publish {root / 'wenqu-write'} --changelog '发布'",
        f"  [dry-run] skillhub publish {root / 'wenqu-review'} --changelog '发布'",
    ]


def test_clawhub_publish_runs_validate_login_and_publish(
    tmp_path: Path, logged_in
) -> None:
    root = make_repo(tmp_path)
    calls: list[tuple[str, ...]] = []
    out: list[str] = []

    summary = publish(root, calls, out, targets=("clawhub",), changelog="修复画图")

    assert summary.exit_code == 0
    assert ("clawhub", "whoami") in calls
    assert calls.index(("clawhub", "whoami")) < calls.index(
        next(call for call in calls if call[1:3] == ("skill", "publish"))
    )
    skill_calls = [call for call in calls if call[1:3] == ("skill", "publish")]
    assert [call[3] for call in skill_calls] == [
        str(root / "wenqu-write"),
        str(root / "wenqu-review"),
    ]
    assert ("--changelog", "修复画图") == tuple(
        skill_calls[0][skill_calls[0].index("--changelog") :][:2]
    )
    assert ("clawhub", "package", "validate", ".") in calls
    package_call = next(call for call in calls if call[1:3] == ("package", "publish"))
    assert package_call[:6] == (
        "clawhub", "package", "publish", ".", "--family", "bundle-plugin",
    )
    assert "发布完成" in "\n".join(out[-2:])


def test_rate_limit_retries_with_growing_delays(tmp_path: Path, logged_in) -> None:
    root = make_repo(tmp_path, skills=("wenqu-write",))
    attempts = {"count": 0}
    delays: list[float] = []

    def runner(command, root):
        command = tuple(command)
        if command[1:3] == ("skill", "publish"):
            attempts["count"] += 1
            if attempts["count"] < 3:
                return fail(command, stderr="429 too many requests")
        return ok(command)

    summary = run_publish(
        root,
        targets=("clawhub",),
        skills_only=True,
        command_runner=runner,
        sleeper=delays.append,
        env=ENV,
        out=lambda line: None,
    )

    assert summary.exit_code == 0
    assert attempts["count"] == 3
    assert delays == [60, 120]


def test_inspector_block_counts_as_failure_despite_zero_exit(
    tmp_path: Path, logged_in
) -> None:
    root = make_repo(tmp_path, skills=("wenqu-write",))

    def runner(command, root):
        command = tuple(command)
        if command[1:3] == ("skill", "publish"):
            return ok(command, stdout="Plugin Inspector blocked publish: risky content")
        return ok(command)

    summary = run_publish(
        root,
        targets=("clawhub",),
        skills_only=True,
        command_runner=runner,
        env=ENV,
        out=lambda line: None,
    )

    assert summary.exit_code == 1
    assert summary.failed[0].item == "wenqu-write@0.2.0"


def test_skillhub_rate_limit_waits_75_seconds(tmp_path: Path, logged_in) -> None:
    root = make_repo(tmp_path, skills=("wenqu-write",))
    attempts = {"count": 0}
    delays: list[float] = []

    def runner(command, root):
        command = tuple(command)
        if command[1] == "publish":
            attempts["count"] += 1
            if attempts["count"] == 1:
                return fail(command, stderr="发布频率过高，请稍后再试")
        return ok(command)

    summary = run_publish(
        root,
        targets=("skillhub",),
        command_runner=runner,
        sleeper=delays.append,
        env=ENV,
        out=lambda line: None,
    )

    assert summary.exit_code == 0
    assert attempts["count"] == 2
    assert delays == [75]


def test_missing_skill_version_fails_that_item(tmp_path: Path, logged_in) -> None:
    root = make_repo(tmp_path, skills=("wenqu-write",), version=None)
    out: list[str] = []

    summary = publish(root, [], out, targets=("clawhub",), skills_only=True)

    assert summary.exit_code == 1
    assert summary.failed[0].item == "wenqu-write"
    assert "缺 version" in "\n".join(out)


def test_missing_owner_fails_clawhub_items(tmp_path: Path, logged_in) -> None:
    target = {"name": "clawhub", "enabled": True, "options": {"packageName": "@o/p"}}
    root = make_repo(tmp_path, targets=[target])

    summary = publish(root, [], [], targets=("clawhub",))

    assert summary.exit_code == 1
    assert all("options.owner" in result.message for result in summary.failed)


def test_token_login_runs_first_and_never_prints_token(tmp_path: Path, logged_in) -> None:
    root = make_repo(tmp_path, skills=("wenqu-write",))
    calls: list[tuple[str, ...]] = []
    out: list[str] = []
    env = {**ENV, "CLAWHUB_TOKEN": "clh_secret"}

    summary = publish(root, calls, out, targets=("clawhub",), skills_only=True, env=env)

    assert summary.exit_code == 0
    login_call = ("clawhub", "login", "--token", "clh_secret")
    assert login_call in calls
    assert calls.index(login_call) < calls.index(("clawhub", "whoami"))
    assert "clh_secret" not in "\n".join(out)


def test_missing_login_is_a_setup_error(tmp_path: Path, monkeypatch) -> None:
    root = make_repo(tmp_path)
    monkeypatch.setattr("skills_eval.publish._executable_exists", lambda command: True)
    calls: list[tuple[str, ...]] = []

    def runner(command, root):
        command = tuple(command)
        calls.append(command)
        if command[1:] == ("whoami",) or command[1:] == ("auth", "whoami"):
            return fail(command, stderr="not logged in")
        return ok(command)

    summary = run_publish(root, command_runner=runner, env=ENV, out=lambda line: None)

    assert summary.exit_code == 2
    assert not [call for call in calls if "publish" in call]


def test_unknown_or_disabled_target_is_a_setup_error(tmp_path: Path) -> None:
    root = make_repo(tmp_path, targets=[CLAWHUB_TARGET])

    unknown = publish(root, [], [], targets=("gitlab",), dry_run=True)
    disabled = publish(root, [], [], targets=("skillhub",), dry_run=True)

    assert unknown.exit_code == 2
    assert disabled.exit_code == 2


def test_selector_limits_published_skills(tmp_path: Path, logged_in) -> None:
    root = make_repo(tmp_path)
    calls: list[tuple[str, ...]] = []

    summary = publish(
        root, calls, [], targets=("skillhub",), selectors=("wenqu-review",)
    )

    assert summary.exit_code == 0
    publish_calls = [call for call in calls if call[1] == "publish"]
    assert publish_calls == [
        ("skillhub", "publish", str(root / "wenqu-review"), "--changelog", "发布")
    ]


def test_unknown_selector_is_an_error(tmp_path: Path) -> None:
    root = make_repo(tmp_path)

    summary = publish(root, [], [], selectors=("nope",), dry_run=True)

    assert summary.exit_code == 1


def test_check_gate_failure_blocks_publishing(tmp_path: Path, monkeypatch) -> None:
    root = make_repo(tmp_path)
    monkeypatch.setattr("skills_eval.publish._executable_exists", lambda command: True)
    monkeypatch.setattr(
        "skills_eval.publish.run_check",
        lambda *args, **kwargs: CheckResult(
            plugin_name="wenqu-skills",
            diagnostics=(Diagnostic(Severity.FAIL, "FORMAT", "broken"),),
        ),
    )
    calls: list[tuple[str, ...]] = []

    summary = publish(root, calls, [], targets=("clawhub",))

    assert summary.exit_code == 1
    assert not [call for call in calls if "publish" in call]


def test_skip_check_bypasses_gate(tmp_path: Path, monkeypatch) -> None:
    root = make_repo(tmp_path, skills=("wenqu-write",))
    monkeypatch.setattr("skills_eval.publish._executable_exists", lambda command: True)

    def explode(*args, **kwargs):
        raise AssertionError("run_check must not run")

    monkeypatch.setattr("skills_eval.publish.run_check", explode)

    summary = publish(root, [], [], targets=("skillhub",), skip_check=True)

    assert summary.exit_code == 0


def test_dirty_working_tree_warns(tmp_path: Path, logged_in) -> None:
    root = make_repo(tmp_path, skills=("wenqu-write",))
    out: list[str] = []

    def runner(command, root):
        command = tuple(command)
        if command[:2] == ("git", "status"):
            return ok(command, stdout=" M wenqu-write/SKILL.md")
        return ok(command)

    summary = run_publish(
        root,
        targets=("skillhub",),
        command_runner=runner,
        env=ENV,
        out=out.append,
    )

    assert summary.exit_code == 0
    assert any("工作区不干净" in line for line in out)


def test_plugin_only_skips_skillhub(tmp_path: Path, logged_in) -> None:
    root = make_repo(tmp_path, skills=("wenqu-write",))
    out: list[str] = []

    summary = publish(root, [], out, plugin_only=True)

    assert summary.exit_code == 0
    assert [result.item for result in summary.results] == ["@gogoingai/wenqu-skills@0.2.0"]
    assert any("skillhub 无插件包维度" in line for line in out)
