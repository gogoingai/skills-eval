"""Explicit opt-in publishing to platforms such as ClawHub and SkillHub.

``skills-eval check`` never publishes.  This module is the counterpart that
actually pushes Skills and the plugin package, after login verification and a
defensive check gate.  Platform credentials only ever come from the
environment (``CLAWHUB_TOKEN`` / ``SKILLHUB_TOKEN``) or a pre-existing CLI
login; tokens are never printed or embedded in reported commands.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from skills_eval.config import load_config
from skills_eval.discovery import discover_plugin, select_skill
from skills_eval.models import Plugin, Severity, Skill
from skills_eval.publishing_checks import (
    CommandRunner,
    _executable_exists,
    _run_command,
)
from skills_eval.reporting import render_terminal
from skills_eval.service import run_check

PUBLISHABLE_TARGETS = frozenset({"clawhub", "skillhub"})

_MAX_ATTEMPTS = 4
_CLAWHUB_RATE_LIMIT = re.compile(r"429|rate|frequency|频繁|频率|reset in", re.IGNORECASE)
_CLAWHUB_SOFT_ERROR = re.compile(
    r"(?:^|\n)Error:\s|Plugin Inspector blocked publish", re.IGNORECASE
)
_SKILLHUB_RATE_LIMIT = re.compile(r"发布频率过高|429|请求过于频繁")
_DEFAULT_SKILLHUB_HOST = "https://api.skillhub.cn"


@dataclass(frozen=True)
class PublishItemResult:
    """Outcome of publishing one Skill or the plugin package."""

    target: str
    item: str
    ok: bool
    message: str = ""


@dataclass(frozen=True)
class PublishSummary:
    """Aggregated publishing outcome; ``exit_code`` follows the CLI contract.

    Exit codes: 0 everything published; 1 a publish item or the defensive
    check gate failed; 2 a prerequisite (CLI, login, target selection) is
    missing.
    """

    results: tuple[PublishItemResult, ...] = ()
    errors: tuple[str, ...] = ()
    setup_errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "results", tuple(self.results))
        object.__setattr__(self, "errors", tuple(self.errors))
        object.__setattr__(self, "setup_errors", tuple(self.setup_errors))

    @property
    def succeeded(self) -> tuple[PublishItemResult, ...]:
        return tuple(result for result in self.results if result.ok)

    @property
    def failed(self) -> tuple[PublishItemResult, ...]:
        return tuple(result for result in self.results if not result.ok)

    @property
    def exit_code(self) -> int:
        if self.setup_errors:
            return 2
        if self.errors or self.failed:
            return 1
        return 0


@dataclass(frozen=True)
class PublishContext:
    """Everything a platform publisher needs; functions stay injectable."""

    root: Path
    plugin: Plugin
    skills: tuple[Skill, ...]
    target: str
    options: Mapping[str, object]
    release: Mapping[str, object]
    changelog: str
    dry_run: bool
    skills_only: bool
    plugin_only: bool
    source_commit: str
    source_ref: str
    env: Mapping[str, str]
    command_runner: CommandRunner
    sleeper: Callable[[float], None]
    out: Callable[[str], None]


class PublisherRegistry:
    """Registry for platform publishers, parallel to PublishingCheckRegistry."""

    _publishers: ClassVar[dict[str, Callable[[PublishContext], tuple[PublishItemResult, ...]]]] = {}

    @classmethod
    def register(
        cls,
        name: str,
        publisher: Callable[[PublishContext], tuple[PublishItemResult, ...]],
    ) -> None:
        cls._publishers[name] = publisher

    @classmethod
    def create(cls, name: str) -> Callable[[PublishContext], tuple[PublishItemResult, ...]]:
        return cls._publishers[name]


def run_publish(
    root: Path,
    *,
    selectors: tuple[str, ...] = (),
    targets: tuple[str, ...] = (),
    changelog: str = "发布",
    dry_run: bool = False,
    skills_only: bool = False,
    plugin_only: bool = False,
    skip_check: bool = False,
    command_runner: CommandRunner = _run_command,
    sleeper: Callable[[float], None] = time.sleep,
    env: Mapping[str, str] | None = None,
    out: Callable[[str], None] = print,
) -> PublishSummary:
    """Publish selected Skills and the plugin package to enabled platforms."""
    root = root.resolve()
    environ: Mapping[str, str] = os.environ if env is None else env

    config, config_diagnostics = load_config(root)
    plugin, discovery_diagnostics = discover_plugin(root)
    blocking = [
        diagnostic
        for diagnostic in (*config_diagnostics, *discovery_diagnostics)
        if diagnostic.severity is Severity.FAIL
    ]
    if plugin is None or blocking:
        for diagnostic in blocking:
            out(f"✗ {diagnostic.message}")
        messages = tuple(diagnostic.message for diagnostic in blocking)
        return PublishSummary(errors=messages or ("Plugin discovery failed.",))

    selected_skills, selection_errors = _select_skills(plugin, selectors)
    if selection_errors:
        for message in selection_errors:
            out(f"✗ {message}")
        return PublishSummary(errors=tuple(selection_errors))

    target_configs, target_errors = _select_targets(config.publishing_targets, targets)
    if target_errors:
        for message in target_errors:
            out(f"✗ {message}")
        return PublishSummary(setup_errors=tuple(target_errors))

    base_context = PublishContext(
        root=root,
        plugin=plugin,
        skills=selected_skills,
        target="",
        options={},
        release=config.release,
        changelog=changelog,
        dry_run=dry_run,
        skills_only=skills_only,
        plugin_only=plugin_only,
        source_commit=environ.get("GITHUB_SHA") or _git(root, command_runner, "rev-parse", "HEAD"),
        source_ref=environ.get("GITHUB_REF_NAME")
        or _git(root, command_runner, "rev-parse", "--abbrev-ref", "HEAD"),
        env=environ,
        command_runner=command_runner,
        sleeper=sleeper,
        out=out,
    )

    if not dry_run:
        _warn_dirty_tree(base_context)
        setup_errors = [
            error
            for target_config in target_configs
            if (error := _login(_context_for(base_context, target_config))) is not None
        ]
        if setup_errors:
            for error in setup_errors:
                out(f"✗ {error}")
            return PublishSummary(setup_errors=tuple(setup_errors))

        if not skip_check:
            check = run_check(
                root,
                selector=None,
                dry_run=False,
                external=True,
                external_targets=tuple(str(target["name"]) for target in target_configs),
            )
            out(render_terminal(check))
            if check.exit_code != 0:
                out("✗ skills-eval 审查未通过，终止发布")
                return PublishSummary(errors=("skills-eval check gate failed.",))

    results: list[PublishItemResult] = []
    for target_config in target_configs:
        context = _context_for(base_context, target_config)
        out(f"→ 发布到 {context.target} ...")
        target_results = PublisherRegistry.create(context.target)(context)
        succeeded = [r for r in target_results if r.ok]
        failed = [r for r in target_results if not r.ok]
        out(f"  完成: {len(succeeded)} 成功, {len(failed)} 失败")
        results.extend(target_results)

    summary = PublishSummary(results=tuple(results))
    _print_summary(summary, dry_run, out)
    return summary


def _context_for(base: PublishContext, target_config: Mapping[str, object]) -> PublishContext:
    options = target_config.get("options", {})
    assert isinstance(options, Mapping)
    return PublishContext(
        root=base.root,
        plugin=base.plugin,
        skills=base.skills,
        target=str(target_config["name"]),
        options=options,
        release=base.release,
        changelog=base.changelog,
        dry_run=base.dry_run,
        skills_only=base.skills_only,
        plugin_only=base.plugin_only,
        source_commit=base.source_commit,
        source_ref=base.source_ref,
        env=base.env,
        command_runner=base.command_runner,
        sleeper=base.sleeper,
        out=base.out,
    )


def _select_skills(
    plugin: Plugin, selectors: tuple[str, ...]
) -> tuple[tuple[Skill, ...], list[str]]:
    if not selectors:
        return plugin.skills, []
    selected: list[Skill] = []
    seen: set[Path] = set()
    errors: list[str] = []
    for selector in dict.fromkeys(selectors):
        skills, diagnostics = select_skill(plugin, selector)
        errors.extend(diagnostic.message for diagnostic in diagnostics)
        for skill in skills:
            if skill.path not in seen:
                seen.add(skill.path)
                selected.append(skill)
    return tuple(selected), errors


def _select_targets(
    configured: tuple[Mapping[str, object], ...], requested: tuple[str, ...]
) -> tuple[tuple[Mapping[str, object], ...], list[str]]:
    """Resolve requested publish targets against the enabled configuration."""
    enabled = [
        target
        for target in configured
        if target.get("enabled") is True and target.get("name") in PUBLISHABLE_TARGETS
    ]
    errors: list[str] = []
    for name in dict.fromkeys(requested):
        if name not in PUBLISHABLE_TARGETS:
            errors.append(f"Publishing target {name!r} is not publishable by skills-eval.")
        elif all(target.get("name") != name for target in enabled):
            errors.append(f"Publishing target {name!r} is not enabled by this configuration.")
    if errors:
        return (), errors
    if requested:
        enabled = [target for target in enabled if target.get("name") in set(requested)]
    if not enabled:
        return (), ["No publishable targets are enabled by this configuration."]
    return tuple(enabled), []


def _login(context: PublishContext) -> str | None:
    """Verify (or establish, via env token) platform login. Never prints tokens."""
    if context.target == "clawhub":
        binary = context.env.get("CLAWHUB_BIN") or "clawhub"
        token = context.env.get("CLAWHUB_TOKEN")
        login_command = (binary, "login", "--token", token or "")
        whoami_command = (binary, "whoami")
        install_hint = f"clawhub CLI 未找到 ({binary})。安装: npm i -g clawhub (需 Node >=22)"
        login_hint = "未登录 clawhub。执行: clawhub login --token clh_xxx 或配置 CLAWHUB_TOKEN"
    else:
        binary = context.env.get("SKILLHUB_BIN") or "skillhub"
        host = str(context.options.get("host") or _DEFAULT_SKILLHUB_HOST)
        token = context.env.get("SKILLHUB_TOKEN")
        login_command = (binary, "login", "--key", token or "", "--host", host)
        whoami_command = (binary, "auth", "whoami")
        install_hint = (
            f"skillhub CLI 未找到 ({binary})。安装: "
            "curl -fsSL https://skillhub.cn/install/install.sh | bash -s -- --cli-only"
        )
        login_hint = "未登录 skillhub。执行: skillhub login --key <skh_xxx> 或配置 SKILLHUB_TOKEN"

    if not _executable_exists(binary):
        return install_hint
    if token:
        logged_in = _run_quietly(context, tuple(login_command))
        if logged_in is None or logged_in.returncode != 0:
            return f"{context.target} 登录失败（token 无效或网络问题）"
    whoami = _run_quietly(context, whoami_command)
    if whoami is None or whoami.returncode != 0:
        return login_hint
    context.out(f"登录态: {(whoami.stdout or '').strip()}")
    return None


def _publish_clawhub(context: PublishContext) -> tuple[PublishItemResult, ...]:
    binary = context.env.get("CLAWHUB_BIN") or "clawhub"
    owner = str(context.options.get("owner") or "")
    source_repo = _source_repo(context)
    results: list[PublishItemResult] = []

    if not context.plugin_only:
        if not owner:
            results.append(
                PublishItemResult("clawhub", "skills", False, "clawhub target requires options.owner")
            )
        else:
            context.out(f"\n=== 技能{'预检' if context.dry_run else '发布'} ({len(context.skills)}) ===")
            for index, skill in enumerate(context.skills):
                results.append(_clawhub_skill(context, binary, owner, source_repo, skill))
                if index < len(context.skills) - 1 and not context.dry_run:
                    context.sleeper(4)

    if not context.skills_only:
        results.append(_clawhub_package(context, binary, owner, source_repo))
    return tuple(results)


def _clawhub_skill(
    context: PublishContext,
    binary: str,
    owner: str,
    source_repo: str,
    skill: Skill,
) -> PublishItemResult:
    slug = _frontmatter_text(skill, "slug") or skill.name
    name = _frontmatter_text(skill, "displayName") or slug
    version = _frontmatter_text(skill, "version")
    if not version:
        context.out(f"✗ {slug}: SKILL.md 缺 version")
        return PublishItemResult("clawhub", slug, False, "SKILL.md lacks a version field.")
    command = [
        binary, "skill", "publish", str(skill.path),
        "--slug", slug, "--name", name, "--version", version,
        "--owner", owner, "--changelog", context.changelog,
        "--source-commit", context.source_commit,
        "--source-ref", context.source_ref,
        "--source-path", str(skill.path.relative_to(context.root)),
    ]
    if source_repo:
        command.extend(("--source-repo", source_repo))
    return _publish_with_retry(
        context,
        "clawhub",
        f"{slug}@{version}",
        tuple(command),
        rate_limit=_CLAWHUB_RATE_LIMIT,
        retry_delay=lambda attempt: 60 * attempt,
        soft_error=_CLAWHUB_SOFT_ERROR,
    )


def _clawhub_package(
    context: PublishContext, binary: str, owner: str, source_repo: str
) -> PublishItemResult:
    package_name = str(context.options.get("packageName") or "")
    if not owner:
        return PublishItemResult("clawhub", "plugin", False, "clawhub target requires options.owner")
    if not package_name:
        return PublishItemResult(
            "clawhub", "plugin", False, "clawhub target requires options.packageName"
        )
    version_file = context.root / str(context.release.get("versionFile") or "VERSION")
    try:
        version = version_file.read_text(encoding="utf-8").strip()
    except OSError as error:
        return PublishItemResult("clawhub", "plugin", False, f"Cannot read {version_file}: {error}")
    label = f"{package_name}@{version}"
    context.out(f"\n=== 插件包{'预检' if context.dry_run else '发布'} {label} ===")

    if not context.dry_run:
        validate = _run_quietly(context, (binary, "package", "validate", "."))
        if validate is None or validate.returncode != 0:
            context.out("✗ package validate 失败")
            return PublishItemResult("clawhub", "plugin", False, "package validate failed")

    command = [
        binary, "package", "publish", ".", "--family", "bundle-plugin",
        "--name", package_name, "--version", version,
        "--owner", owner, "--changelog", context.changelog,
        "--source-commit", context.source_commit,
        "--source-ref", context.source_ref,
        "--source-path", ".",
    ]
    if source_repo:
        command.extend(("--source-repo", source_repo))
    return _publish_with_retry(
        context,
        "clawhub",
        label,
        tuple(command),
        rate_limit=_CLAWHUB_RATE_LIMIT,
        retry_delay=lambda attempt: 60 * attempt,
        soft_error=_CLAWHUB_SOFT_ERROR,
    )


def _publish_skillhub(context: PublishContext) -> tuple[PublishItemResult, ...]:
    binary = context.env.get("SKILLHUB_BIN") or "skillhub"
    if context.plugin_only:
        context.out("skillhub 无插件包维度，跳过")
        return ()
    context.out(f"\n=== 技能{'预检' if context.dry_run else '发布'} ({len(context.skills)}) ===")
    results: list[PublishItemResult] = []
    for index, skill in enumerate(context.skills):
        slug = _frontmatter_text(skill, "slug") or skill.name
        command = (binary, "publish", str(skill.path), "--changelog", context.changelog)
        results.append(
            _publish_with_retry(
                context,
                "skillhub",
                slug,
                command,
                rate_limit=_SKILLHUB_RATE_LIMIT,
                retry_delay=lambda attempt: 75,
            )
        )
        if index < len(context.skills) - 1 and not context.dry_run:
            context.sleeper(4)
    return tuple(results)


def _publish_with_retry(
    context: PublishContext,
    target: str,
    item: str,
    command: tuple[str, ...],
    *,
    rate_limit: re.Pattern[str],
    retry_delay: Callable[[int], float],
    soft_error: re.Pattern[str] | None = None,
) -> PublishItemResult:
    if context.dry_run:
        context.out(f"  [dry-run] {shlex.join(command)}")
        return PublishItemResult(target, item, True, "planned")

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        completed = _run_quietly(context, command)
        if completed is None:
            context.out(f"✗ {item} 无法执行 {command[0]}")
            return PublishItemResult(target, item, False, f"Could not execute {command[0]!r}.")
        output = f"{completed.stdout or ''}{completed.stderr or ''}"
        if completed.returncode == 0 and not (soft_error and soft_error.search(output)):
            context.out(f"✓ {item}")
            return PublishItemResult(target, item, True)
        if rate_limit.search(output) and attempt < _MAX_ATTEMPTS:
            delay = retry_delay(attempt)
            context.out(f"  ⏳ {item} 限频，等 {delay}s 重试 ({attempt}/{_MAX_ATTEMPTS})...")
            context.sleeper(delay)
            continue
        context.out(f"✗ {item} 失败 (rc={completed.returncode})")
        return PublishItemResult(target, item, False, output.strip()[-500:])
    return PublishItemResult(target, item, False, "rate limited after 4 attempts")


def _source_repo(context: PublishContext) -> str:
    configured = context.options.get("sourceRepo") or context.env.get("CLAWHUB_SOURCE_REPO")
    if configured:
        return str(configured)
    url = _git(context.root, context.command_runner, "remote", "get-url", "origin")
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    return match.group(1) if match else ""


def _git(root: Path, command_runner: CommandRunner, *args: str) -> str:
    try:
        completed = command_runner(("git", *args), root)
    except OSError:
        return ""
    return (completed.stdout or "").strip() if completed.returncode == 0 else ""


def _warn_dirty_tree(context: PublishContext) -> None:
    if _git(context.root, context.command_runner, "status", "--porcelain"):
        short_sha = context.source_commit[:8] or "?"
        context.out(
            f"⚠️ 工作区不干净。provenance 会指向 {short_sha}，但发布内容含未提交改动。\n"
            "   标准流程：先 git commit + push，再发布。\n"
        )


def _run_quietly(
    context: PublishContext, command: tuple[str, ...]
) -> subprocess.CompletedProcess[str] | None:
    try:
        return context.command_runner(command, context.root)
    except OSError:
        return None


def _frontmatter_text(skill: Skill, key: str) -> str:
    value = (skill.frontmatter or {}).get(key)
    return value.strip() if isinstance(value, str) else ""


def _print_summary(
    summary: PublishSummary, dry_run: bool, out: Callable[[str], None]
) -> None:
    out("\n" + "=" * 48)
    succeeded = summary.succeeded
    out(f"成功: {len(succeeded)}{'  -> ' + ' '.join(r.item for r in succeeded) if succeeded else ''}")
    if summary.failed:
        out(f"失败: {len(summary.failed)}  -> {' '.join(r.item for r in summary.failed)}")
    else:
        out("预检完成" if dry_run else "发布完成（平台审核状态以各平台后台为准）")


PublisherRegistry.register("clawhub", _publish_clawhub)
PublisherRegistry.register("skillhub", _publish_skillhub)
