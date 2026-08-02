from importlib.metadata import version

from typer.testing import CliRunner

from skills_eval.cli import app


def test_version_option_prints_installed_package_version() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == f"skills-eval {version('skills-eval')}\n"


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


def test_check_passes_external_selection_to_service(plugin_factory, monkeypatch) -> None:
    root = plugin_factory()
    captured: dict[str, object] = {}

    def fake_run_check(path, selector, dry_run, external=False, external_targets=()):
        captured.update(
            path=path,
            selector=selector,
            dry_run=dry_run,
            external=external,
            external_targets=external_targets,
        )
        from skills_eval.models import CheckResult

        return CheckResult(plugin_name="example")

    monkeypatch.setattr("skills_eval.cli.run_check", fake_run_check)

    result = CliRunner().invoke(
        app,
        ["check", str(root), "--external-target", "claude-plugin", "--dry-run"],
    )

    assert result.exit_code == 0
    assert captured["external"] is True
    assert captured["dry_run"] is True
    assert captured["external_targets"] == ("claude-plugin",)


def test_publish_dry_run_plans_without_side_effects(plugin_factory) -> None:
    import json

    root = plugin_factory()
    (root / ".skills-eval.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "publishing": {
                    "targets": [{"name": "skillhub", "enabled": True}],
                },
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["publish", str(root), "--dry-run"])

    assert result.exit_code == 0
    assert "[dry-run] skillhub publish" in result.stdout
    assert "预检完成" in result.stdout


def test_publish_rejects_conflicting_scope_flags(plugin_factory) -> None:
    root = plugin_factory()

    result = CliRunner().invoke(
        app, ["publish", str(root), "--skills-only", "--plugin-only"]
    )

    assert result.exit_code == 2


def test_publish_requires_an_enabled_publishable_target(plugin_factory) -> None:
    root = plugin_factory()

    result = CliRunner().invoke(app, ["publish", str(root), "--dry-run"])

    assert result.exit_code == 2
    assert "No publishable targets" in result.stdout
