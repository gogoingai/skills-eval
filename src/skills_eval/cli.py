"""Command line entry point for Skills Eval."""

from __future__ import annotations

from importlib.metadata import version
from pathlib import Path

import typer

from skills_eval.publish import run_publish
from skills_eval.reporting import render_json, render_terminal, write_markdown_report
from skills_eval.service import run_check


app = typer.Typer(no_args_is_help=True, add_completion=False)

_FORMATS = {"terminal", "markdown", "json"}


def _validate_format(value: str) -> str:
    if value not in _FORMATS:
        raise typer.BadParameter(f"format must be one of {', '.join(sorted(_FORMATS))}")
    return value


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"skills-eval {version('skills-eval')}")
        raise typer.Exit()


@app.callback()
def main(
    show_version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed Skills Eval version.",
    ),
) -> None:
    """Release checks for Claude Plugin Skill repositories."""


@app.command()
def check(
    path: Path = typer.Argument(..., exists=True, file_okay=False, readable=True),
    skill: str | None = typer.Option(None, "--skill", help="Check one Skill by directory or name."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show planned checks without scanning or writing a report."),
    external: bool = typer.Option(
        False,
        "--external",
        help="Run configured native publishing-platform validations; never publishes.",
    ),
    external_target: list[str] | None = typer.Option(
        None,
        "--external-target",
        help="Run native validation only for this enabled publishing target; repeatable.",
    ),
    report_format: str = typer.Option(
        "terminal",
        "--format",
        help="Report format: terminal (default), markdown, or json.",
        callback=_validate_format,
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Write the report to this path (format inferred from --format or .json suffix).",
    ),
) -> None:
    """Check a Claude Plugin repository before release."""
    result = run_check(
        path,
        selector=skill,
        dry_run=dry_run,
        external=external or bool(external_target),
        external_targets=tuple(external_target or ()),
    )
    fmt = report_format
    if fmt == "terminal" and output is not None and output.suffix.lower() == ".json":
        fmt = "json"

    if fmt == "json":
        payload = render_json(result)
        if output is not None and not dry_run:
            output.write_text(payload + "\n", encoding="utf-8")
            typer.echo(f"Report: {output}")
        else:
            typer.echo(payload)
    else:
        typer.echo(render_terminal(result))
        if not dry_run:
            report_path = output if output is not None else path.resolve() / "skills-eval-report.md"
            write_markdown_report(result, report_path)
            typer.echo(f"Report: {report_path}")
    raise typer.Exit(code=result.exit_code)


@app.command()
def publish(
    path: Path = typer.Argument(..., exists=True, file_okay=False, readable=True),
    target: list[str] | None = typer.Option(
        None,
        "--target",
        help="Publish only to this enabled target (clawhub, skillhub); repeatable. Defaults to every enabled publishable target.",
    ),
    skill: list[str] | None = typer.Option(
        None, "--skill", help="Publish only this Skill by directory or name; repeatable."
    ),
    changelog: str = typer.Option(
        "发布", "--changelog", help="Changelog entry sent to the publishing platforms."
    ),
    skills_only: bool = typer.Option(
        False, "--skills-only", help="Publish Skills only, skip the plugin package."
    ),
    plugin_only: bool = typer.Option(
        False, "--plugin-only", help="Publish the plugin package only, skip Skills."
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the planned publish commands without logging in, checking, or publishing.",
    ),
    skip_check: bool = typer.Option(
        False, "--skip-check", help="Skip the defensive skills-eval check gate before publishing."
    ),
) -> None:
    """Publish Skills and the plugin package to enabled platforms.

    Credentials come from CLAWHUB_TOKEN / SKILLHUB_TOKEN in the environment or
    a pre-existing CLI login; tokens are never printed.
    """
    if skills_only and plugin_only:
        raise typer.BadParameter("--skills-only and --plugin-only cannot be combined.")
    summary = run_publish(
        path,
        selectors=tuple(skill or ()),
        targets=tuple(target or ()),
        changelog=changelog,
        dry_run=dry_run,
        skills_only=skills_only,
        plugin_only=plugin_only,
        skip_check=skip_check,
    )
    raise typer.Exit(code=summary.exit_code)
