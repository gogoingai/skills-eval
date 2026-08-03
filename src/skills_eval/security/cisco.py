"""Isolated command-line adapter for Cisco's AI Skill Scanner."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from importlib import metadata
from pathlib import Path
from typing import Any

from skills_eval.models import Severity, parse_frontmatter
from skills_eval.security.base import (
    ExecutionDiagnostic,
    FindingLevel,
    ScanOutcome,
    ScanStatus,
    SecurityFinding,
    level_to_severity,
)
from skills_eval.security.runner import (
    executable_path,
    resolve_executable,
    run_subprocess,
    staged_scan_input,
)

_POLICIES = frozenset({"balanced", "strict", "permissive"})
_LEVEL_BY_SOURCE = {
    "critical": FindingLevel.CRITICAL,
    "high": FindingLevel.HIGH,
    "medium": FindingLevel.MEDIUM,
    "low": FindingLevel.LOW,
    "info": FindingLevel.INFO,
}
_DETAIL_LIMIT = 2_000
_PROCESS_OUTPUT_LIMIT = 64 * 1024
_JSON_OUTPUT_LIMIT = 16 * 1024 * 1024
_SCANNER_TIMEOUT_SECONDS = 300.0
_SUPPORTED_OPTIONS = frozenset({"policy", "useBehavioral"})


def run_scanner(args: list[str]) -> tuple[int, str, str]:
    """Run the external scanner with bounded execution and captured output."""
    return run_subprocess(
        args,
        timeout=_SCANNER_TIMEOUT_SECONDS,
        stdout_limit=_PROCESS_OUTPUT_LIMIT,
        stderr_limit=_PROCESS_OUTPUT_LIMIT,
    )


class CiscoScanner:
    """Normalize Cisco AI Skill Scanner JSON into shared evaluation models."""

    name = "cisco"

    def __init__(self, executable: str = "skill-scanner") -> None:
        self.executable = executable
        self._version: str | None = None

    def is_available(self) -> bool:
        """Return whether the Cisco scanner executable can be resolved."""
        return executable_path(self.executable) is not None

    def get_version(self) -> str | None:
        """Return the installed Cisco scanner version, cached after the first call."""
        if self._version is None:
            try:
                self._version = metadata.version("cisco-ai-skill-scanner")
            except metadata.PackageNotFoundError:
                self._version = ""
        return self._version or None

    def normalize_result(self, raw_result: object) -> tuple[SecurityFinding, ...]:
        """Normalize a parsed Cisco payload into security findings."""
        return _normalize_findings(raw_result)

    def scan(self, skill_path: Path, options: dict[str, object]) -> ScanOutcome:
        option_error = _validate_options(options)
        if option_error is not None:
            return _failed("CISCO_OPTIONS_INVALID", option_error)

        policy = options.get("policy", "balanced")
        assert isinstance(policy, str)
        output_path: Path | None = None
        version = self.get_version()

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="skills-eval-cisco-",
                suffix=".json",
                delete=False,
            ) as output:
                output_path = Path(output.name)

            with staged_scan_input(skill_path) as scan_path:
                args = [
                    resolve_executable(self.executable),
                    "scan",
                    str(scan_path),
                    "--format",
                    "json",
                    "--output",
                    str(output_path),
                    "--policy",
                    policy,
                ]
                if options.get("useBehavioral") is True:
                    args.append("--use-behavioral")

                start = time.monotonic()
                try:
                    return_code, stdout, stderr = run_scanner(args)
                except subprocess.TimeoutExpired as error:
                    return _failed(
                        "CISCO_PROCESS_TIMEOUT",
                        f"Cisco scanner exceeded the {error.timeout:g}-second execution limit.",
                        stdout=_output_text(error.stdout),
                        stderr=_output_text(error.stderr),
                    )
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
                duration_ms = int((time.monotonic() - start) * 1000)

            if return_code != 0:
                return _failed(
                    "CISCO_PROCESS_FAILED",
                    f"Cisco scanner exited with status {return_code}.",
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=duration_ms,
                    version=version,
                )

            try:
                output_text = _read_json_output(output_path)
            except _OutputTooLarge:
                return _failed(
                    "CISCO_OUTPUT_TOO_LARGE",
                    f"Cisco scanner JSON output exceeds the {_JSON_OUTPUT_LIMIT}-byte limit.",
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=duration_ms,
                    version=version,
                )
            except (OSError, UnicodeDecodeError) as error:
                return _failed(
                    "CISCO_OUTPUT_UNREADABLE",
                    "Cisco scanner JSON output could not be read.",
                    stdout=stdout,
                    stderr=stderr,
                    error=str(error),
                    duration_ms=duration_ms,
                    version=version,
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
                    duration_ms=duration_ms,
                    version=version,
                )
            if len(output_text) > _JSON_OUTPUT_LIMIT:
                return _failed(
                    "CISCO_OUTPUT_TOO_LARGE",
                    f"Cisco scanner JSON output exceeds the {_JSON_OUTPUT_LIMIT}-character limit.",
                    stderr=stderr,
                    duration_ms=duration_ms,
                    version=version,
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
                    duration_ms=duration_ms,
                    version=version,
                )

            try:
                findings = _normalize_findings(payload)
            except ValueError as error:
                return _failed(
                    "CISCO_PAYLOAD_INVALID",
                    f"Cisco scanner returned an unexpected payload: {error}",
                    output=output_text,
                    stderr=stderr,
                    duration_ms=duration_ms,
                    version=version,
                )

            findings = _filter_markdown_magic_mismatches(findings, skill_path)
            status = _outcome_status(findings)
            return ScanOutcome(
                status=status,
                findings=findings,
                duration_ms=duration_ms,
                version=version,
                raw_result=payload if isinstance(payload, dict) else None,
            )
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
    unknown_options = sorted(set(options) - _SUPPORTED_OPTIONS)
    if unknown_options:
        return f"Unknown Cisco option: {unknown_options[0]!r}."
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
        level = _LEVEL_BY_SOURCE.get(source_severity)
        if level is None:
            raise ValueError(f"finding {index} has unsupported severity")
        severity = level_to_severity(level)

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
                level=level,
                title=title,
                raw=dict(raw_finding),
            )
        )
    return tuple(findings)


def _filter_markdown_magic_mismatches(
    findings: tuple[SecurityFinding, ...], skill_path: Path
) -> tuple[SecurityFinding, ...]:
    """Drop Cisco's isolated type warning for valid Markdown frontmatter.

    Cisco's Magika classifier can label a Markdown document as YAML when its
    frontmatter or embedded YAML examples dominate. The warning is suppressed
    only if it is the sole rule reported and every referenced file is valid
    Markdown with mapping YAML frontmatter.
    """
    if not findings or any(finding.code != "FILE_MAGIC_MISMATCH" for finding in findings):
        return findings
    if all(_is_markdown_with_frontmatter(finding.path, skill_path) for finding in findings):
        return ()
    return findings


def _is_markdown_with_frontmatter(path: Path | None, skill_path: Path) -> bool:
    if path is None or path.suffix.lower() != ".md":
        return False
    candidate = path if path.is_absolute() else skill_path / path
    try:
        candidate = candidate.resolve(strict=True)
        candidate.relative_to(skill_path.resolve(strict=True))
        return parse_frontmatter(candidate.read_text(encoding="utf-8")) is not None
    except (OSError, UnicodeDecodeError, ValueError):
        return False


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


def _outcome_status(findings: tuple[SecurityFinding, ...]) -> ScanStatus:
    if any(finding.severity is Severity.FAIL for finding in findings):
        return ScanStatus.FAIL
    if findings:
        return ScanStatus.WARN
    return ScanStatus.PASS


def _failed(
    code: str,
    message: str,
    *,
    duration_ms: int | None = None,
    version: str | None = None,
    **details: str,
) -> ScanOutcome:
    detail = "\n".join(
        f"{label}: {_bounded(value)}" for label, value in details.items() if value
    )
    return ScanOutcome(
        status=ScanStatus.ERROR,
        diagnostic=ExecutionDiagnostic(
            severity=Severity.FAIL,
            code=code,
            message=message,
            detail=detail,
        ),
        duration_ms=duration_ms,
        version=version,
    )


def _bounded(value: str) -> str:
    if len(value) <= _DETAIL_LIMIT:
        return value
    return f"{value[:_DETAIL_LIMIT]}… [truncated]"


class _OutputTooLarge(ValueError):
    """Raised before loading an oversized scanner artifact."""


def _read_json_output(path: Path) -> str:
    with path.open("rb") as output:
        contents = output.read(_JSON_OUTPUT_LIMIT + 1)
    if len(contents) > _JSON_OUTPUT_LIMIT:
        raise _OutputTooLarge
    return contents.decode("utf-8")


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
