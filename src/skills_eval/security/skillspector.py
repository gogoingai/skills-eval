"""NVIDIA SkillSpector adapter (local static analysis by default)."""

from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from skills_eval.models import Severity
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

_SCANNER_TIMEOUT_SECONDS = 300.0
_VERSION_TIMEOUT_SECONDS = 10.0
_DETAIL_LIMIT = 2_000
_SUPPORTED_OPTIONS = frozenset({"useLlm", "executable"})
_LEVEL_BY_SOURCE = {
    "critical": FindingLevel.CRITICAL,
    "high": FindingLevel.HIGH,
    "medium": FindingLevel.MEDIUM,
    "low": FindingLevel.LOW,
    "info": FindingLevel.INFO,
}
# SkillSpector exits 0 (SAFE/CAUTION) or 1 (DO_NOT_INSTALL); both mean a valid scan.
_SUCCESS_EXIT_CODES = frozenset({0, 1})
_INSTALL_GUIDE = (
    "Install NVIDIA SkillSpector with: "
    "uv tool install git+https://github.com/NVIDIA/skillspector.git "
    "(requires Python 3.12+; runs in its own isolated environment)."
)


class SkillSpectorScanner:
    """Normalize NVIDIA SkillSpector JSON into shared evaluation models.

    By default only local static analysis runs (``--no-llm``): no API key, no
    NVIDIA NIM endpoint, and no Skill file content egress. The only network use
    is an outbound OSV.dev CVE lookup (keyless, with an offline fallback).
    """

    name = "skillspector"

    def __init__(self) -> None:
        self._version: str | None = None

    def is_available(self) -> bool:
        """Return whether the ``skillspector`` CLI can be resolved."""
        return executable_path(_default_executable()) is not None

    def get_version(self) -> str | None:
        """Return the SkillSpector version, cached after the first call."""
        if self._version is None:
            self._version = _query_version() or ""
        return self._version or None

    def normalize_result(self, raw_result: object) -> tuple[SecurityFinding, ...]:
        """Normalize a parsed SkillSpector payload into security findings."""
        return _normalize_findings(raw_result)

    def scan(self, skill_path: Path, options: dict[str, object]) -> ScanOutcome:
        option_error = _validate_options(options)
        if option_error is not None:
            return _failed("SKILLSPECTOR_OPTIONS_INVALID", option_error)

        executable = str(options.get("executable") or _default_executable())
        if executable_path(executable) is None:
            return _failed(
                "SKILLSPECTOR_EXECUTABLE_MISSING",
                f"NVIDIA SkillSpector executable was not found: {executable!r}.",
                hint=_INSTALL_GUIDE,
            )

        use_llm = options.get("useLlm") is True
        version = self.get_version()
        start = time.monotonic()
        try:
            with staged_scan_input(skill_path) as scan_path:
                args = [
                    resolve_executable(executable),
                    "scan",
                    str(scan_path),
                    "--format",
                    "json",
                ]
                if not use_llm:
                    args.append("--no-llm")
                return_code, stdout, stderr = run_subprocess(
                    args, timeout=_SCANNER_TIMEOUT_SECONDS
                )
        except subprocess.TimeoutExpired as error:
            return _failed(
                "SKILLSPECTOR_PROCESS_TIMEOUT",
                f"NVIDIA SkillSpector exceeded the {error.timeout:g}-second execution limit.",
                stdout=_output_text(error.stdout),
                stderr=_output_text(error.stderr),
            )
        except FileNotFoundError:
            return _failed(
                "SKILLSPECTOR_EXECUTABLE_MISSING",
                "NVIDIA SkillSpector executable was not found.",
                hint=_INSTALL_GUIDE,
            )
        except OSError as error:
            return _failed(
                "SKILLSPECTOR_PROCESS_ERROR",
                "NVIDIA SkillSpector could not be started.",
                error=str(error),
            )
        duration_ms = int((time.monotonic() - start) * 1000)

        if return_code not in _SUCCESS_EXIT_CODES:
            return _failed(
                "SKILLSPECTOR_PROCESS_FAILED",
                f"NVIDIA SkillSpector exited with status {return_code}.",
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                version=version,
            )

        if not stdout.strip():
            return _failed(
                "SKILLSPECTOR_OUTPUT_UNREADABLE",
                "NVIDIA SkillSpector did not produce JSON output.",
                stderr=stderr,
                duration_ms=duration_ms,
                version=version,
            )

        try:
            payload = json.loads(stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            return _failed(
                "SKILLSPECTOR_OUTPUT_INVALID",
                "NVIDIA SkillSpector output is not valid JSON.",
                output=stdout,
                stderr=stderr,
                error=str(error),
                duration_ms=duration_ms,
                version=version,
            )

        try:
            findings = _normalize_findings(payload)
        except ValueError as error:
            return _failed(
                "SKILLSPECTOR_PAYLOAD_INVALID",
                f"NVIDIA SkillSpector returned an unexpected payload: {error}",
                output=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                version=version,
            )

        status = _outcome_status(findings, return_code)
        return ScanOutcome(
            status=status,
            findings=findings,
            duration_ms=duration_ms,
            version=version,
            raw_result=payload if isinstance(payload, dict) else None,
        )


def _default_executable() -> str:
    return "skillspector"


def _validate_options(options: dict[str, object]) -> str | None:
    unknown = sorted(set(options) - _SUPPORTED_OPTIONS)
    if unknown:
        return f"Unknown NVIDIA SkillSpector option: {unknown[0]!r}."
    use_llm = options.get("useLlm", False)
    if not isinstance(use_llm, bool):
        return "NVIDIA SkillSpector option 'useLlm' must be a boolean."
    executable = options.get("executable")
    if executable is not None and not isinstance(executable, str):
        return "NVIDIA SkillSpector option 'executable' must be a string."
    return None


def _query_version() -> str | None:
    try:
        return_code, stdout, _stderr = run_subprocess(
            [resolve_executable(_default_executable()), "--version"],
            timeout=_VERSION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if return_code != 0:
        return None
    match = re.search(r"v?(\d+(?:\.\d+){1,3})", stdout)
    return match.group(1) if match else None


def _normalize_findings(payload: Any) -> tuple[SecurityFinding, ...]:
    if not isinstance(payload, dict):
        raise ValueError("top-level value must be an object")
    raw_issues = payload.get("issues")
    if not isinstance(raw_issues, list):
        raise ValueError("'issues' must be an array")

    findings: list[SecurityFinding] = []
    for index, raw_issue in enumerate(raw_issues):
        if not isinstance(raw_issue, dict):
            raise ValueError(f"issue {index} must be an object")

        rule_id = _nonempty_string(raw_issue.get("id")) or f"SKILLSPECTOR-{index}"
        raw_severity = _nonempty_string(raw_issue.get("severity"))
        source_severity = raw_severity.lower() if raw_severity else "info"
        level = _LEVEL_BY_SOURCE.get(source_severity, FindingLevel.INFO)

        pattern = _nonempty_string(raw_issue.get("pattern"))
        category = _nonempty_string(raw_issue.get("category"))
        explanation = _nonempty_string(raw_issue.get("explanation"))
        remediation = _nonempty_string(raw_issue.get("remediation"))
        matched = _nonempty_string(raw_issue.get("finding"))
        snippet = _nonempty_string(raw_issue.get("code_snippet"))

        title = pattern or category or rule_id
        message = title
        detail = explanation
        evidence = matched or snippet

        location = raw_issue.get("location")
        file_path = _location_file(location)
        line = _location_line(location)

        findings.append(
            SecurityFinding(
                severity=level_to_severity(level),
                code=rule_id,
                message=message,
                path=Path(file_path) if file_path else None,
                source="skillspector",
                rule_id=rule_id,
                line=line,
                detail=detail,
                remediation=remediation,
                evidence=evidence,
                source_severity=raw_severity,
                level=level,
                title=title,
                raw=dict(raw_issue),
            )
        )
    return tuple(findings)


def _location_file(location: object) -> str | None:
    if not isinstance(location, dict):
        return None
    value = location.get("file")
    return _nonempty_string(value)


def _location_line(location: object) -> int | None:
    if not isinstance(location, dict):
        return None
    value = location.get("start_line")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def _outcome_status(findings: tuple[SecurityFinding, ...], return_code: int) -> ScanStatus:
    if any(finding.severity is Severity.FAIL for finding in findings):
        return ScanStatus.FAIL
    if findings:
        return ScanStatus.WARN
    # Exit code 1 (DO_NOT_INSTALL) without parseable issues still signals risk.
    if return_code == 1:
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


def _nonempty_string(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _bounded(value: str) -> str:
    if len(value) <= _DETAIL_LIMIT:
        return value
    return f"{value[:_DETAIL_LIMIT]}… [truncated]"


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
