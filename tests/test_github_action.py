from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def test_action_installs_requested_cli_and_uploads_report() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))

    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["path"]["default"] == "."
    assert action["inputs"]["version"]["default"] == "skills-eval>=0.1.9,<0.2"
    assert action["inputs"]["external"]["default"] == "false"
    assert action["outputs"]["report-path"]
    assert any(step.get("uses") == "actions/setup-python@v5" for step in action["runs"]["steps"])
    assert any(step.get("uses") == "actions/upload-artifact@v4" for step in action["runs"]["steps"])
    command = next(step["run"] for step in action["runs"]["steps"] if step.get("id") == "check")
    assert "python -m pipx run" in command
    assert "skills-eval check" in command
    assert "--external" in command


def test_action_updates_one_pr_comment_after_uploading_the_report() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]

    assert action["inputs"]["comment"]["default"] == "true"
    assert "github-token" not in action["inputs"]
    upload_index = next(
        index for index, step in enumerate(steps) if step.get("uses") == "actions/upload-artifact@v4"
    )
    comment_index, comment_step = next(
        (index, step)
        for index, step in enumerate(steps)
        if step.get("uses") == "actions/github-script@v7"
    )

    assert upload_index < comment_index
    assert "github.event_name == 'pull_request'" in comment_step["if"]
    assert "skills-eval-report" in comment_step["with"]["script"]
    assert "issues.updateComment" in comment_step["with"]["script"]
    assert "issues.createComment" in comment_step["with"]["script"]
    assert "Powered by [Skills Eval]" in comment_step["with"]["script"]
    assert "pull_request.head.sha" in comment_step["with"]["script"]
    assert "此评论会随 PR 后续提交原地更新" in comment_step["with"]["script"]
    assert "This comment updates in place" in comment_step["with"]["script"]
    assert comment_step["with"]["github-token"] == "${{ github.token }}"
    assert comment_step["continue-on-error"] is True


def test_readme_documents_reusable_github_action() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "uses: gogoingai/skills-eval@v0.1.9" in readme
    assert "pull-requests: write" in readme
    assert "automatic\n`GITHUB_TOKEN`" in readme
    assert "external: true" in readme
