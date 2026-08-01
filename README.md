# skills-eval

`skills-eval` is a pre-release CLI for Claude Plugin repositories containing one
or more Skills. It validates the publishable structure and runs configured
security scanners before release.

## Install

```bash
pipx install skills-eval
```

## Use

```bash
# Check every Skill declared by the plugin.
skills-eval check .

# Check one Skill by name or directory.
skills-eval check . --skill wenqu-write

# Show the selected scope and format checks without running security scanners
# or writing a report.
skills-eval check . --dry-run

# Before releasing to a configured platform, also run its native validator.
# This validates only: it never publishes a Skill or package.
skills-eval check . --external
```

A normal run prints a compact summary and writes `skills-eval-report.md` in the
target repository. The report records the selected Skills, each format rule,
enabled publishing targets, security scanner configuration, and every finding.

## Checks

The portable checks cover the plugin manifest, declared Skills, `SKILL.md` and
frontmatter, local file references, duplicate names or paths, and configured
temporary files. The bundled Cisco AI Skill Scanner reviews each selected Skill
directory for risky commands, prompt injection, secret exposure, network
access, and persistence-related behavior.

Scanner findings are signals for review, not a guarantee that a Skill is safe.

## Configuration

Create `.skills-eval.json` in the plugin root. JSON Schema support is available
through the GitHub-hosted schema URL:

```json
{
  "$schema": "https://raw.githubusercontent.com/gogoingai/skills-eval/main/src/skills_eval/schemas/skills-eval.schema.json",
  "schemaVersion": 1,
  "extends": ["wenqu"],
  "publishing": {
    "targets": [
      { "name": "claude-plugin", "enabled": true },
      { "name": "workbuddy", "enabled": true },
      { "name": "skillhub", "enabled": true },
      { "name": "openclaw", "enabled": true },
      { "name": "clawhub", "enabled": true }
    ]
  },
  "report": {
    "language": "auto"
  },
  "security": {
    "sources": [
      {
        "name": "cisco",
        "enabled": true,
        "options": {
          "policy": "balanced",
          "useBehavioral": true
        }
      }
    ]
  }
}
```

The `wenqu` profile enables `claude-plugin`, `workbuddy`, `skillhub`,
`openclaw`, and `clawhub`. Each target owns only its own static rules: version
and changelog are the shared Wenqu baseline; package metadata, Skill metadata,
slugs and package contents, and OpenClaw homepage metadata are checked only
when their corresponding target is enabled. A project can override any profile
target by repeating its `name` in `publishing.targets`; unsupported or duplicate
target names are configuration errors. `options` is reserved for future
target-specific behavior such as external validation and dry runs.

Security sources are a configured list so future scanners can be added without
changing the command interface.

## Native platform validation

The regular check is safe for local development and GitHub Actions. Before a
platform release, add `--external` to run native checks for the enabled
publishing targets:

- `claude-plugin`: `claude plugin validate .`
- `workbuddy`: `codebuddy plugin validate .claude-plugin/marketplace.json`
- `skillhub`: `skillhub publish <selected-skill> --dry-run`
- `clawhub`: `clawhub package validate .`

`openclaw` currently has no separate native CLI validation. Missing tools,
login failures, and network errors are reported as an **external publishing
validation** environment failure, never as a Skill security finding. Use
`CODEBUDDY_BIN`, `SKILLHUB_BIN`, or `CLAWHUB_BIN` when a CLI is not on `PATH`.
The SkillHub command always includes `--dry-run`; Skills Eval never invokes a
publish command without that platform-provided safety flag.

`report.language` accepts `auto` (the default), `zh`, or `en`. In `auto` mode,
Skills Eval reads the computer's preferred language: Chinese preferences render
the report in Chinese; every other preference renders it in English.

## Release automation

Tagged releases (`v*`) build the package and publish with PyPI Trusted
Publishing through GitHub Actions OIDC. The publish job uses the `pypi`
environment and `id-token: write`; it does not use a `PYPI_TOKEN`.

## GitHub Action

The repository also provides a reusable GitHub Action. It installs the selected
published CLI version, runs the check, and uploads `skills-eval-report.md` as an
artifact even when the check fails. For pull requests, it creates one marked
comment and updates that same comment after each later push, so the result is
visible without downloading the report.

```yaml
name: Skills review

on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: gogoingai/skills-eval@v0.1.10
        with:
          path: .
```

`pull_request` runs when a PR opens and on every later push to its branch, so
maintainers see an up-to-date **Skills Eval 审查结果** comment as well as the
result in the PR's **Checks** tab. The comment identifies the checked commit,
completion time, and workflow run, and includes a link to download the full
report; the same artifact is also available from the run in the
repository's **Actions** page. The comment step uses the automatic
`GITHUB_TOKEN`; no secret needs to be configured. On a PR from an external fork
GitHub can deny comment write access; the audit and artifact still complete
because commenting is non-fatal. Set `comment: false` to disable PR comments.
The caller controls triggers; this Action never publishes a package, creates a
tag, or changes repository files.

Set `external: true` only on a protected, release-only workflow runner that has
the required platform CLIs and credentials. It is `false` by default, so PR
checks remain portable:

```yaml
      - uses: gogoingai/skills-eval@v0.1.10
        with:
          path: .
          external: true
```
