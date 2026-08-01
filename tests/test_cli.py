from typer.testing import CliRunner

from skills_eval.cli import app


def test_check_dry_run_does_not_write_report(plugin_factory) -> None:
    root = plugin_factory()

    result = CliRunner().invoke(app, ["check", str(root), "--dry-run"])

    assert result.exit_code == 0
    assert "Dry run:" in result.stdout
    assert not (root / "skills-eval-report.md").exists()


def test_check_writes_report(plugin_factory, monkeypatch) -> None:
    root = plugin_factory()

    result = CliRunner().invoke(app, ["check", str(root)])

    assert result.exit_code == 0
    assert "Report:" in result.stdout
    assert (root / "skills-eval-report.md").exists()
