"""Isolated command-line adapter for Cisco's AI Skill Scanner."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any

from skills_eval.models import Severity
from skills_eval.security.base import (
    ExecutionDiagnostic,
    ScanOutcome,
    SecurityFinding,
)


_POLICIES = frozenset({"balanced", "strict", "permissive"})
_FAIL_SEVERITIES = frozenset({"critical", "high"})
_REVIEW_SEVERITIES = frozenset({"medium", "low", "info"})
_DETAIL_LIMIT = 2_000


def run_scanner(args: list[str]) -> tuple[int, str, str]:
    """Run the external scanner without invoking a shell."""
    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


class CiscoScanner:
    """Normalize Cisco AI Skill Scanner JSON into shared evaluation models."""

    def __init__(self, executable: str = "skill-scanner") -> None:
        self.executable = executable

    def scan(self, skill_path: Path, options: dict[str, object]) -> ScanOutcome:
        option_error = _validate_options(options)
        if option_error is not None:
            return _failed("CISCO_OPTIONS_INVALID", option_error)

        policy = options.get("policy", "balanced")
        assert isinstance(policy, str)
        output_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="skills-eval-cisco-",
                suffix=".json",
                delete=False,
            ) as output:
                output_path = Path(output.name)

            args = [
                self.executable,
                "scan",
                str(skill_path),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--policy",
                policy,
            ]
            if options.get("useBehavioral") is True:
                args.append("--use-behavioral")

            try:
                return_code, stdout, stderr = run_scanner(args)
            except FileNotFoundError:
                return _failed(
                    "CISCO_EXECUTABLE_MISSING",
                    f"Cisco scanner executable was not found: {self.executable!r}.",
                )
            except OSError as error:
                return _failed(
                    "CISCO_PROCESS_ERROR",
                    "Cisco scanner could not be started.",
                    error=str(error),
                )

            if return_code != 0:
                return _failed(
                    "CISCO_PROCESS_FAILED",
                    f"Cisco scanner exited with status {return_code}.",
                    stdout=stdout,
                    stderr=stderr,
                )

            try:
                output_text = output_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                return _failed(
                    "CISCO_OUTPUT_UNREADABLE",
                    "Cisco scanner JSON output could not be read.",
                    stdout=stdout,
                    stderr=stderr,
                    error=str(error),
                )

            # The real CLI writes to --output. Accept returned stdout as a
            # compatibility path for process doubles and older CLI builds.
            if not output_text.strip():
                output_text = stdout
            if not output_text.strip():
                return _failed(
                    "CISCO_OUTPUT_UNREADABLE",
                    "Cisco scanner did not produce JSON output.",
                    stdout=stdout,
                    stderr=stderr,
                )

            try:
                payload = json.loads(output_text)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                return _failed(
                    "CISCO_OUTPUT_INVALID",
                    "Cisco scanner output is not valid JSON.",
                    output=output_text,
                    stderr=stderr,
                    error=str(error),
                )

            try:
                findings = _normalize_findings(payload)
            except ValueError as error:
                return _failed(
                    "CISCO_PAYLOAD_INVALID",
                    f"Cisco scanner returned an unexpected payload: {error}",
                    output=output_text,
                    stderr=stderr,
                )

            status = _outcome_status(findings)
            return ScanOutcome(status=status, findings=findings)
        except OSError as error:
            return _failed(
                "CISCO_OUTPUT_UNREADABLE",
                "Cisco scanner temporary output could not be created.",
                error=str(error),
            )
        finally:
            if output_path is not None:
                try:
                    output_path.unlink(missing_ok=True)
                except OSError:
                    pass


def _validate_options(options: dict[str, object]) -> str | None:
    policy = options.get("policy", "balanced")
    if not isinstance(policy, str) or policy not in _POLICIES:
        return "Cisco option 'policy' must be balanced, strict, or permissive."
    use_behavioral = options.get("useBehavioral", False)
    if not isinstance(use_behavioral, bool):
        return "Cisco option 'useBehavioral' must be a boolean."
    return None


def _normalize_findings(payload: Any) -> tuple[SecurityFinding, ...]:
    if not isinstance(payload, dict):
        raise ValueError("top-level value must be an object")
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        raise ValueError("'findings' must be an array")

    findings: list[SecurityFinding] = []
    for index, raw_finding in enumerate(raw_findings):
        if not isinstance(raw_finding, dict):
            raise ValueError(f"finding {index} must be an object")

        rule_id = _nonempty_string(raw_finding.get("rule_id"))
        if rule_id is None:
            raise ValueError(f"finding {index} has no valid rule_id")

        raw_severity = _nonempty_string(raw_finding.get("severity"))
        if raw_severity is None:
            raise ValueError(f"finding {index} has no valid severity")
        source_severity = raw_severity.lower()
        if source_severity in _FAIL_SEVERITIES:
            severity = Severity.FAIL
        elif source_severity in _REVIEW_SEVERITIES:
            severity = Severity.REVIEW
        else:
            raise ValueError(f"finding {index} has unsupported severity")

        message = _optional_string(raw_finding, "message", index)
        title = _optional_string(raw_finding, "title", index)
        description = _optional_string(raw_finding, "description", index)
        summary = message or title or description
        if summary is None:
            raise ValueError(f"finding {index} has no message, description, or title")

        raw_path = _optional_string(raw_finding, "file_path", index)
        path = Path(raw_path) if raw_path else None

        line = raw_finding.get("line_number")
        if line is not None and (
            isinstance(line, bool) or not isinstance(line, int) or line < 1
        ):
            raise ValueError(f"finding {index} has an invalid line_number")

        remediation = _optional_string(raw_finding, "remediation", index)
        evidence = _optional_string(raw_finding, "snippet", index)
        findings.append(
            SecurityFinding(
                severity=severity,
                code=rule_id,
                message=summary,
                path=path,
                source="cisco",
                rule_id=rule_id,
                line=line,
                detail=description,
                remediation=remediation,
                evidence=evidence,
                source_severity=source_severity,
            )
        )
    return tuple(findings)


def _nonempty_string(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _optional_string(
    raw_finding: dict[str, object],
    key: str,
    index: int,
) -> str | None:
    value = raw_finding.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"finding {index} has an invalid {key}")
    return value.strip() or None


def _outcome_status(findings: tuple[SecurityFinding, ...]) -> Severity:
    if any(finding.severity is Severity.FAIL for finding in findings):
        return Severity.FAIL
    if findings:
        return Severity.REVIEW
    return Severity.PASS


def _failed(code: str, message: str, **details: str) -> ScanOutcome:
    detail = "\n".join(
        f"{label}: {_bounded(value)}"
        for label, value in details.items()
        if value
    )
    return ScanOutcome(
        status=Severity.FAIL,
        diagnostic=ExecutionDiagnostic(
            severity=Severity.FAIL,
            code=code,
            message=message,
            detail=detail,
        ),
    )


def _bounded(value: str) -> str:
    if len(value) <= _DETAIL_LIMIT:
        return value
    return f"{value[:_DETAIL_LIMIT]}… [truncated]"
