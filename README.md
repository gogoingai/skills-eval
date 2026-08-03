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

# Before a full platform release, run every enabled native validator.
# This validates only: it never publishes a Skill or package.
skills-eval check . --external

# On a pull request, run only the native validators that do not need a
# platform login. Repeat --external-target to select them explicitly.
skills-eval check . \
  --external-target claude-plugin \
  --external-target workbuddy \
  --external-target clawhub
```

A normal run prints a compact summary and writes `skills-eval-report.md` in the
target repository. The report records the selected Skills, each format rule,
enabled publishing targets, security scanner configuration, and every finding.

Choose an output format with `--format` (terminal, markdown, or json) and an
explicit report path with `--output`. JSON is intended for GitHub Actions and
platform integration:

```bash
skills-eval check .                  # terminal summary + skills-eval-report.md
skills-eval check . --format json    # JSON report to stdout
skills-eval check . --format json --output report.json
skills-eval check . --format markdown --output audit.md
```

## Checks

The portable checks cover the plugin manifest, declared Skills, `SKILL.md` and
frontmatter, local file references, duplicate names or paths, and configured
temporary files. A unified multi-provider security layer then reviews each
selected Skill directory.

Scanner findings are signals for review, not a guarantee that a Skill is safe.

## Security providers

Security scanning is a unified Provider architecture. Each provider reports a
status (`PASS`, `WARN`, `FAIL`, `ERROR`, `SKIPPED`) and normalized findings with
a five-level severity (`info`, `low`, `medium`, `high`, `critical`). The overall
result follows the worst provider: any `critical`/`high` finding is `FAIL` by
default; only `medium` and below is `WARN`; the threshold is configurable via
`security.failOn`. A **required** provider that cannot run makes the overall
result `ERROR` (exit code 2); an **optional** provider error is shown but does
not override other valid results.

| Provider | Default | Local | Account | LLM | PR | Type | Data leaves host |
|---|---:|---:|---:|---:|---:|---|---:|
| Cisco AI Skill Scanner | enabled | yes | no | no | yes | Skill content (local) | no |
| NVIDIA SkillSpector | enabled | yes | no (with `--no-llm`) | no (with `--no-llm`) | yes | Skill content (static) | dependency names → OSV.dev |
| Tencent aig-skill-scan | off | yes | yes (LLM key) | yes | yes (with key) | Skill content (LLM) | Skill content → LLM endpoint |
| Snyk | off | CLI | yes (`SNYK_TOKEN`) | no | yes (with token) | dependency / SAST | source/manifests → Snyk |

- **Cisco** and **SkillSpector** are local detectors and run by default.
- **Tencent AIG** is an open-source enhanced detector that needs an
  OpenAI-compatible LLM endpoint (configurable base URL + model; not bound to a
  vendor).
- **Snyk** is an optional networked detector that scans SKILL.md instruction
  content (prompt injection, malicious payloads, credential handling) via
  `snyk-agent-scan` (`uvx snyk-agent-scan@latest`). Skill content is sent to
  Snyk's verification server; enable it only when that is acceptable.

### Install

```bash
pipx install skills-eval                                   # core (includes Cisco)
pip install "skills-eval[tencent-aig]"                     # add Tencent aig-skill-scan
uv tool install git+https://github.com/NVIDIA/skillspector.git  # NVIDIA SkillSpector (Python 3.12+)
# Snyk Agent Scan: uvx snyk-agent-scan@latest (requires uv + SNYK_TOKEN)
```

SkillSpector is git-only and requires Python 3.12-3.14, but `uv tool install`
gives it an isolated interpreter, so skills-eval's Python 3.10+ baseline is
unaffected. Snyk Agent Scan runs via `uvx` (part of uv). When a provider
is enabled but not installed, skills-eval reports `SKIPPED` (or `ERROR` if that
provider is `required`) with the install command - it never silently fakes a
pass.

### Status meanings

- `PASS` - no findings reached the warning threshold.
- `WARN` - findings exist but none reached the blocking threshold (`failOn`).
- `FAIL` - blocking findings exist; the Skill is not ready to publish.
- `ERROR` - the scanner failed to run, timed out, or produced unparseable output
  (distinct from a security finding). Required-provider errors set exit code 2.
- `SKIPPED` - the provider is disabled, not installed, or missing optional
  credentials.

## Configuration

Create `.skills-eval.json` in the plugin root. JSON Schema support is available
through the GitHub-hosted schema URL:

```json
{
  "$schema": "https://raw.githubusercontent.com/gogoingai/skills-eval/main/src/skills_eval/schemas/skills-eval.schema.json",
  "schemaVersion": 1,
  "format": {
    "requiredRootFiles": ["README.md"],
    "requiredSkillFrontmatter": ["license"],
    "forbiddenPaths": [".DS_Store"],
    "referenceExtensions": [".md", ".txt"]
  },
  "release": {
    "versionFile": "VERSION",
    "requireVersionSemver": true,
    "changelogFile": "CHANGELOG.md",
    "changelogVersionHeading": "## {version}"
  },
  "publishing": {
    "targets": [
      {
        "name": "claude-plugin",
        "enabled": true,
        "options": { "skillDirectoryPrefix": "skills-" }
      },
      {
        "name": "clawhub",
        "enabled": true,
        "options": { "packageName": "@example/skills" }
      }
    ]
  },
  "report": {
    "language": "auto"
  },
  "security": {
    "failOn": "high",
    "sources": [
      {
        "name": "cisco",
        "enabled": true,
        "required": true,
        "options": {
          "policy": "balanced",
          "useBehavioral": true
        }
      },
      { "name": "skillspector", "enabled": true, "required": false, "options": { "useLlm": false } },
      { "name": "tencent-aig", "enabled": false, "options": { "apiKeyEnv": "LLM_API_KEY", "baseUrlEnv": "LLM_BASE_URL", "modelEnv": "LLM_MODEL" } },
      { "name": "snyk", "enabled": false, "options": { "tokenEnv": "SNYK_TOKEN" } },
    ]
  }
}
```

Skills Eval has no project-specific profiles or defaults. Each repository owns
its own `.skills-eval.json`: `format` and `release` express repository
conventions, while each enabled publishing target contributes only that
platform's static checks. `release.assetReferences` can optionally define an
asset directory, a documentation directory, and the reference prefix that must
link them. Target `options` hold project-specific identities where a platform
does not supply one itself—for example, `claude-plugin.skillDirectoryPrefix`
and `clawhub.packageName`. Unsupported or duplicate target names are
configuration errors.

Security sources are a configured list so scanners can be added without
changing the command interface. `security.failOn` sets the blocking threshold
(`info`/`low`/`medium`/`high`/`critical`, default `high`). `required` controls
whether a provider that cannot run fails the check (`ERROR`, exit 2) or is
merely skipped; Cisco defaults to required, every other provider defaults to
optional. Unrecognized provider names or options are configuration errors.
Credentials for networked providers are read from the environment variables
named in `options` and are never placed on the command line or written to
reports. See [Security providers](#security-providers) for install commands and
the data-egress implications of each provider.

## Native platform validation

The regular check is safe for local development and GitHub Actions. Before a
platform release, add `--external` to run native checks for the enabled
publishing targets:

- `claude-plugin`: `claude plugin validate .`
- `workbuddy`: `codebuddy plugin validate .claude-plugin/marketplace.json`
- `skillhub`: `skillhub publish <selected-skill> --dry-run`
- `clawhub`: `clawhub package validate . --out <temporary directory>`

`openclaw` currently has no separate native CLI validation. Use
`--external-target <name>` repeatedly to select only configured and enabled
targets; a selected target is shown in the terminal and Markdown report.
Missing tools, login failures, and network errors are reported as an **external
publishing validation** environment failure, never as a Skill security finding.
Use `CODEBUDDY_BIN`, `SKILLHUB_BIN`, or `CLAWHUB_BIN` when a CLI is not on
`PATH`. The SkillHub command always includes `--dry-run`; `skills-eval check`
never invokes a publish command without that platform-provided safety flag.

`report.language` accepts `auto` (the default), `zh`, or `en`. In `auto` mode,
Skills Eval reads the computer's preferred language: Chinese preferences render
the report in Chinese; every other preference renders it in English.

## Publishing

`skills-eval publish` is the explicit opt-in counterpart of `check`: it pushes
the declared Skills and the plugin package to the enabled publishing platforms
(currently `clawhub` and `skillhub`). Every run verifies the platform login,
re-runs the full `skills-eval check` (including native validations for the
selected targets) as a defensive gate, then publishes with rate-limit retries
and a final summary.

```bash
# Preview the exact publish commands without logging in or publishing.
skills-eval publish . --dry-run

# Publish every Skill and the plugin package to all enabled targets.
skills-eval publish . --changelog "0.2.0 修复画图"

# Publish one Skill to one platform.
skills-eval publish . --target clawhub --skill wenqu-write --changelog "修复画图"

# Publish only the plugin package (clawhub), or only Skills.
skills-eval publish . --plugin-only
skills-eval publish . --skills-only
```

Credentials come from the environment—`CLAWHUB_TOKEN` or `SKILLHUB_TOKEN`—or
from a pre-existing `clawhub login` / `skillhub login` session; tokens are
never printed or embedded in reported commands. Platform identities live in the
target `options` of `.skills-eval.json`: `clawhub.owner` and
`clawhub.packageName` are required for ClawHub publishing, `clawhub.sourceRepo`
pins the provenance repository (otherwise derived from the `origin` remote),
and `skillhub.host` overrides the default API host. Provenance commits and refs
come from `GITHUB_SHA` / `GITHUB_REF_NAME` when present.

Exit codes: `0` everything published; `1` a publish item or the defensive check
gate failed; `2` a prerequisite (CLI missing, not logged in, unknown or
disabled target) is unmet. `--skip-check` bypasses the gate for emergencies.

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
      - uses: gogoingai/skills-eval@v0.2.1
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

For a PR, set `external-targets` to the validators to run. The Action installs
the corresponding CLIs on the runner, then records exactly these commands in
the report. `claude-plugin`, `workbuddy`, and `clawhub` are local validations
that need no credential:

```yaml
      - uses: gogoingai/skills-eval@v0.2.1
        with:
          path: .
          external-targets: claude-plugin,workbuddy,clawhub
```

`skillhub` is a remote `--dry-run` and needs a login. Add it to
`external-targets` and pass `skillhub-token` (a repository secret); the Action
installs the SkillHub CLI, logs in with the token, and retries 429 responses
automatically. The token is exposed only as an environment variable:

```yaml
      - uses: gogoingai/skills-eval@v0.2.1
        with:
          path: .
          external-targets: claude-plugin,workbuddy,clawhub,skillhub
          skillhub-token: ${{ secrets.SKILLHUB_TOKEN }}
```

To run every enabled native validator without per-target selection, use
`external: true`; that mode assumes the required tools and credentials are
already available on the runner.

## GitHub Action: publish

A separate composite Action at `gogoingai/skills-eval/publish` runs
`skills-eval publish`—the check Action above keeps its "never publishes"
guarantee. A typical tag-triggered release workflow:

```yaml
name: Publish

on:
  push:
    tags: ["v*"]

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: release
    concurrency: publish
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: gogoingai/skills-eval/publish@v0.2.1
        with:
          targets: clawhub,skillhub
          changelog: ${{ github.ref_name }}
          clawhub-token: ${{ secrets.CLAWHUB_TOKEN }}
          skillhub-token: ${{ secrets.SKILLHUB_TOKEN }}
```

The Action installs the platform CLIs (Node 22 for `clawhub`, the official
installer for `skillhub`), passes tokens only as environment variables, and
uploads the publish log as an artifact. Set `dry-run: "true"` (for example from
a `workflow_dispatch` input) to preview the planned commands without
publishing. Use a GitHub environment with required reviewers on `release` when
a human approval gate is desired; without reviewers the tag push publishes
directly.
