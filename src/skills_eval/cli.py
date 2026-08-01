"""Command line entry point for Skills Eval."""

from __future__ import annotations

from importlib.metadata import version
from pathlib import Path

import typer

from skills_eval.reporting import render_terminal, write_markdown_report
from skills_eval.service import run_check


app = typer.Typer(no_args_is_help=True, add_completion=False)


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
) -> None:
    """Check a Claude Plugin repository before release."""
    result = run_check(path, selector=skill, dry_run=dry_run, external=external)
    typer.echo(render_terminal(result))
    if not dry_run:
        report_path = path.resolve() / "skills-eval-report.md"
        write_markdown_report(result, report_path)
        typer.echo(f"Report: {report_path}")
    raise typer.Exit(code=result.exit_code)
