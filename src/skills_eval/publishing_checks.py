"""Opt-in native validation commands for publishing platforms.

These checks only validate a repository.  They deliberately never invoke a
publishing command without a platform-provided dry-run flag.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from skills_eval.models import PublishingCheckResult, Severity, Skill

CommandRunner = Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]]


def _run_command(command: Sequence[str], root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )


@dataclass(frozen=True)
class PublishingValidation:
    """A planned external platform validation command."""

    target: str
    command: tuple[str, ...]


class PublishingCheckRegistry:
    """Registry for native validation adapters, parallel to security sources."""

    _factories: ClassVar[dict[
        str, Callable[[Path, tuple[Skill, ...], Mapping[str, object]], tuple[PublishingValidation, ...]]
    ]] = {}

    @classmethod
    def register(
        cls,
        name: str,
        factory: Callable[[Path, tuple[Skill, ...], Mapping[str, object]], tuple[PublishingValidation, ...]],
    ) -> None:
        cls._factories[name] = factory

    @classmethod
    def create(
        cls,
        name: str,
        root: Path,
        skills: tuple[Skill, ...],
        options: Mapping[str, object],
    ) -> tuple[PublishingValidation, ...]:
        return cls._factories[name](root, skills, options)


def run_publishing_checks(
    root: Path,
    skills: tuple[Skill, ...],
    targets: tuple[Mapping[str, object], ...],
    *,
    dry_run: bool,
    requested: bool,
    command_runner: CommandRunner = _run_command,
) -> tuple[PublishingCheckResult, ...]:
    """Run selected native validators, or return their plan in dry-run mode."""
    if not requested:
        return ()

    results: list[PublishingCheckResult] = []
    for target in targets:
        name = str(target["name"])
        if name not in PublishingCheckRegistry._factories:
            continue
        options = target.get("options", {})
        assert isinstance(options, Mapping)
        for validation in PublishingCheckRegistry.create(name, root, skills, options):
            if dry_run:
                results.append(
                    PublishingCheckResult(
                        target=name,
                        command=validation.command,
                        status=None,
                        message="planned",
                    )
                )
                continue
            results.append(_execute(validation, root, command_runner))
    return tuple(results)


def _execute(
    validation: PublishingValidation,
    root: Path,
    command_runner: CommandRunner,
) -> PublishingCheckResult:
    executable = validation.command[0]
    if not _executable_exists(executable):
        return PublishingCheckResult(
            target=validation.target,
            command=validation.command,
            status=Severity.FAIL,
            message=f"Required executable was not found: {executable!r}.",
            execution_error=True,
        )
    try:
        completed = command_runner(validation.command, root)
    except OSError as error:
        return PublishingCheckResult(
            target=validation.target,
            command=validation.command,
            status=Severity.FAIL,
            message=f"Could not run external validation: {error}",
            execution_error=True,
        )
    if completed.returncode == 0:
        return PublishingCheckResult(
            target=validation.target,
            command=validation.command,
            status=Severity.PASS,
        )
    output = (completed.stderr or completed.stdout or "").strip()
    return PublishingCheckResult(
        target=validation.target,
        command=validation.command,
        status=Severity.FAIL,
        message=(
            f"Validation command exited with status {completed.returncode}."
            + (f" {output}" if output else "")
        ),
    )


def _executable_exists(command: str) -> bool:
    return Path(command).is_file() if os.path.sep in command else shutil.which(command) is not None


def _claude_plugin(
    root: Path, skills: tuple[Skill, ...], options: Mapping[str, object]
) -> tuple[PublishingValidation, ...]:
    del root, skills, options
    return (PublishingValidation("claude-plugin", ("claude", "plugin", "validate", ".")),)


def _workbuddy(
    root: Path, skills: tuple[Skill, ...], options: Mapping[str, object]
) -> tuple[PublishingValidation, ...]:
    del root, skills, options
    candidates = (
        os.environ.get("CODEBUDDY_BIN"),
        shutil.which("codebuddy"),
        "/Applications/WorkBuddy.app/Contents/Resources/app.asar.unpacked/cli/bin/codebuddy",
    )
    command = next(
        (
            candidate
            for candidate in candidates
            if candidate and _executable_exists(candidate)
        ),
        "codebuddy",
    )
    return (
        PublishingValidation(
            "workbuddy",
            (command, "plugin", "validate", ".claude-plugin/marketplace.json"),
        ),
    )


def _skillhub(
    root: Path, skills: tuple[Skill, ...], options: Mapping[str, object]
) -> tuple[PublishingValidation, ...]:
    del root, options
    command = os.environ.get("SKILLHUB_BIN") or "skillhub"
    return tuple(
        PublishingValidation("skillhub", (command, "publish", str(skill.path), "--dry-run"))
        for skill in skills
    )


def _clawhub(
    root: Path, skills: tuple[Skill, ...], options: Mapping[str, object]
) -> tuple[PublishingValidation, ...]:
    del skills, options
    command = os.environ.get("CLAWHUB_BIN") or "clawhub"
    return (PublishingValidation("clawhub", (command, "package", "validate", ".")),)


PublishingCheckRegistry.register("claude-plugin", _claude_plugin)
PublishingCheckRegistry.register("workbuddy", _workbuddy)
PublishingCheckRegistry.register("skillhub", _skillhub)
PublishingCheckRegistry.register("clawhub", _clawhub)
