"""Command line entry point for Skills Eval."""

from __future__ import annotations

from pathlib import Path

import typer

from skills_eval.reporting import render_terminal, write_markdown_report
from skills_eval.service import run_check


app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.callback()
def main() -> None:
    """Release checks for Claude Plugin Skill repositories."""


@app.command()
def check(
    path: Path = typer.Argument(..., exists=True, file_okay=False, readable=True),
    skill: str | None = typer.Option(None, "--skill", help="Check one Skill by directory or name."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show planned checks without scanning or writing a report."),
) -> None:
    """Check a Claude Plugin repository before release."""
    result = run_check(path, selector=skill, dry_run=dry_run)
    typer.echo(render_terminal(result))
    if not dry_run:
        report_path = path.resolve() / "skills-eval-report.md"
        write_markdown_report(result, report_path)
        typer.echo(f"Report: {report_path}")
    raise typer.Exit(code=result.exit_code)
