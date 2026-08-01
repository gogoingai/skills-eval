from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def test_action_installs_requested_cli_and_uploads_report() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))

    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["path"]["default"] == "."
    assert action["inputs"]["version"]["default"] == "skills-eval>=0.1.5,<0.2"
    assert action["outputs"]["report-path"]
    assert any(step.get("uses") == "actions/setup-python@v5" for step in action["runs"]["steps"])
    assert any(step.get("uses") == "actions/upload-artifact@v4" for step in action["runs"]["steps"])
    command = next(step["run"] for step in action["runs"]["steps"] if step.get("id") == "check")
    assert "python -m pipx run" in command
    assert "skills-eval check" in command


def test_readme_documents_reusable_github_action() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "uses: gogoingai/skills-eval@v0.1.5" in readme
