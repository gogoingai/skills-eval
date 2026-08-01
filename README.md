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
```

A normal run prints a compact summary and writes `skills-eval-report.md` in the
target repository. The report records the selected Skills, each format rule,
security scanner configuration, and every finding.

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

The `wenqu` profile adds Wenqu-specific release metadata, OpenClaw homepage,
and image-asset checks. Security sources are a configured list so future
scanners can be added without changing the command interface.

`report.language` accepts `auto` (the default), `zh`, or `en`. In `auto` mode,
Skills Eval reads the computer's preferred language: Chinese preferences render
the report in Chinese; every other preference renders it in English.

## Release automation

Tagged releases (`v*`) build the package and publish with PyPI Trusted
Publishing through GitHub Actions OIDC. The publish job uses the `pypi`
environment and `id-token: write`; it does not use a `PYPI_TOKEN`.
