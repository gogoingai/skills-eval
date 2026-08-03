"""Snyk Agent Scan adapter (optional, networked skill-content scanning).

Uses ``snyk-agent-scan`` (invoked via ``uvx``) to scan SKILL.md instruction
content for prompt injection, malicious payloads, credential handling issues,
tool poisoning, and other AI-agent threats. This is the official Snyk tool for
local skill scanning - it is NOT the dependency-scanning ``snyk test``.

Skill content is sent to Snyk's verification server; enable this provider only
when sending Skill content off-host is acceptable. The ``SNYK_TOKEN`` is read
from the configured environment variable and never placed on the command line
or in reports.

The JSON output of ``snyk-agent-scan`` is experimental and its structure may
change between releases. This adapter uses a tolerant recursive parser that
collects any dict resembling a finding (has severity + title) and preserves the
raw output for reference.
"""

from __future__ import annotations

import json
import os
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
_VERSION_TIMEOUT_SECONDS = 30.0
# snyk-agent-scan emits full MCP server metadata (tools/resources/prompts) even
# for clean skills, which can run into hundreds of KB. The shared 64 KiB capture
# limit would truncate that and break JSON parsing, so allow a larger bound.
_SCANNER_OUTPUT_LIMIT = 8 * 1024 * 1024
_DETAIL_LIMIT = 2_000
_SUPPORTED_OPTIONS = frozenset({"tokenEnv", "executable", "baseUrl"})
_LEVEL_BY_SOURCE = {
    "critical": FindingLevel.CRITICAL,
    "high": FindingLevel.HIGH,
    "medium": FindingLevel.MEDIUM,
    "moderate": FindingLevel.MEDIUM,
    "low": FindingLevel.LOW,
    "info": FindingLevel.INFO,
}
_SUCCESS_EXIT_CODES = frozenset({0, 1})
_REDACTED = "***REDACTED***"
_INSTALL_GUIDE = (
    "Snyk Agent Scan runs via uvx (part of uv). Install uv: "
    "curl -LsSf https://astral.sh/uv/install.sh | sh. "
    "Then set SNYK_TOKEN and enable the snyk provider."
)


class SnykScanner:
    """Scan SKILL.md instruction content via ``snyk-agent-scan``."""

    name = "snyk"

    def __init__(self) -> None:
        self._version: str | None = None

    def is_available(self) -> bool:
        """Return whether ``uvx`` (or ``uv``) is available to run the scanner."""
        return executable_path("uvx") is not None or executable_path("uv") is not None

    def get_version(self) -> str | None:
        """Return the snyk-agent-scan version, cached after the first call."""
        if self._version is None:
            self._version = _query_version() or ""
        return self._version or None

    def normalize_result(self, raw_result: object) -> tuple[SecurityFinding, ...]:
        """Normalize a parsed snyk-agent-scan payload into security findings."""
        return _normalize_findings(raw_result)

    def scan(self, skill_path: Path, options: dict[str, object]) -> ScanOutcome:
        option_error = _validate_options(options)
        if option_error is not None:
            return _failed("SNYK_OPTIONS_INVALID", option_error)

        runner = str(options.get("executable") or "uvx")
        if executable_path(runner) is None and executable_path("uv") is None:
            return _failed(
                "SNYK_EXECUTABLE_MISSING",
                f"Neither {runner!r} nor 'uv' was found on PATH.",
                hint=_INSTALL_GUIDE,
            )

        token_env = str(options.get("tokenEnv") or "SNYK_TOKEN")
        token = os.environ.get(token_env, "")
        version = self.get_version()
        if not token:
            return ScanOutcome(
                status=ScanStatus.SKIPPED,
                skip_reason=f"missing Snyk token; set the {token_env} environment variable",
                version=version,
            )

        env = dict(os.environ)
        env["SNYK_TOKEN"] = token
        start = time.monotonic()
        try:
            with staged_scan_input(skill_path) as scan_path:
                args = [resolve_executable(runner), "snyk-agent-scan@latest", "--json", str(scan_path)]
                base_url = options.get("baseUrl")
                if isinstance(base_url, str) and base_url:
                    args.extend(["--base-url", base_url])
                return_code, stdout, stderr = run_subprocess(
                    args, timeout=_SCANNER_TIMEOUT_SECONDS, env=env,
                    stdout_limit=_SCANNER_OUTPUT_LIMIT,
                )
        except subprocess.TimeoutExpired as error:
            return _failed(
                "SNYK_PROCESS_TIMEOUT",
                f"snyk-agent-scan exceeded the {error.timeout:g}-second execution limit.",
                stdout=_redact(_output_text(error.stdout), token),
                stderr=_redact(_output_text(error.stderr), token),
            )
        except FileNotFoundError:
            return _failed(
                "SNYK_EXECUTABLE_MISSING",
                f"{runner!r} was not found.",
                hint=_INSTALL_GUIDE,
            )
        except OSError as error:
            return _failed(
                "SNYK_PROCESS_ERROR",
                "snyk-agent-scan could not be started.",
                error=str(error),
            )
        duration_ms = int((time.monotonic() - start) * 1000)

        if return_code not in _SUCCESS_EXIT_CODES:
            return _failed(
                "SNYK_PROCESS_FAILED",
                f"snyk-agent-scan exited with status {return_code}.",
                stdout=_redact(stdout, token),
                stderr=_redact(stderr, token),
                duration_ms=duration_ms,
                version=version,
            )

        if not stdout.strip():
            return ScanOutcome(
                status=ScanStatus.PASS,
                duration_ms=duration_ms,
                version=version,
            )

        try:
            payload = json.loads(stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            return _failed(
                "SNYK_OUTPUT_INVALID",
                "snyk-agent-scan output is not valid JSON.",
                output=_redact(stdout, token),
                stderr=_redact(stderr, token),
                error=str(error),
                duration_ms=duration_ms,
                version=version,
            )

        findings = _normalize_findings(payload)
        status = _outcome_status(findings)
        return ScanOutcome(
            status=status,
            findings=findings,
            duration_ms=duration_ms,
            version=version,
            raw_result=payload if isinstance(payload, (dict, list)) else None,
        )


def _validate_options(options: dict[str, object]) -> str | None:
    unknown = sorted(set(options) - _SUPPORTED_OPTIONS)
    if unknown:
        return f"Unknown Snyk option: {unknown[0]!r}."
    for key in ("tokenEnv", "executable", "baseUrl"):
        value = options.get(key)
        if value is not None and not isinstance(value, str):
            return f"Snyk option {key!r} must be a string."
    return None


def _query_version() -> str | None:
    try:
        runner = resolve_executable("uvx") if executable_path("uvx") else resolve_executable("uv")
        if runner == "uv":
            args = ["uv", "tool", "run", "snyk-agent-scan@latest", "--version"]
        else:
            args = [runner, "snyk-agent-scan@latest", "--version"]
        return_code, stdout, _stderr = run_subprocess(args, timeout=_VERSION_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError):
        return None
    if return_code != 0:
        return None
    match = re.search(r"(\d+(?:\.\d+){1,3})", stdout)
    return match.group(1) if match else None


# --- tolerant parser (output format is experimental/undocumented) -----------


def _normalize_findings(payload: Any) -> tuple[SecurityFinding, ...]:
    if payload is None:
        return ()
    findings: list[SecurityFinding] = []
    _collect_findings(payload, findings)
    return tuple(findings)


def _collect_findings(obj: Any, findings: list[SecurityFinding]) -> None:
    """Recursively walk the JSON tree collecting dicts that look like findings."""
    if isinstance(obj, dict):
        if _looks_like_finding(obj):
            findings.append(_finding_from_raw(obj))
            return  # don't recurse into a finding's children (avoid duplicates)
        for value in obj.values():
            _collect_findings(value, findings)
    elif isinstance(obj, list):
        for item in obj:
            _collect_findings(item, findings)


def _looks_like_finding(obj: dict[str, object]) -> bool:
    # snyk-agent-scan issue: has "code" + "extra_data" (or "message")
    if "code" in obj and ("extra_data" in obj or "message" in obj):
        return True
    # generic: has severity + title
    has_severity = any(k in obj for k in ("severity", "level", "risk"))
    has_title = any(k in obj for k in ("title", "message", "description", "name", "rule"))
    return has_severity and has_title


def _finding_from_raw(raw: dict[str, object]) -> SecurityFinding:
    extra = raw.get("extra_data")
    extra = extra if isinstance(extra, dict) else {}

    raw_severity = _str(
        extra.get("severity") or raw.get("severity")
        or extra.get("level") or raw.get("level")
        or extra.get("risk") or raw.get("risk")
    )
    source_severity = raw_severity or "info"
    level = _LEVEL_BY_SOURCE.get(source_severity.lower(), FindingLevel.INFO)

    rule_id = _str(
        raw.get("code") or extra.get("code")
        or raw.get("id") or extra.get("id")
        or raw.get("rule") or raw.get("type")
    ) or "SNYK"

    title = _str(
        extra.get("title") or raw.get("title")
        or raw.get("message") or extra.get("message")
        or raw.get("name")
    ) or "Snyk finding"

    description = _str(
        extra.get("description") or raw.get("description")
        or extra.get("detail") or extra.get("explanation")
    )

    # file/line: snyk-agent-scan nests them in extra_data.extra_metadata.affected_files
    file_path = None
    line: int | None = None
    meta = extra.get("extra_metadata")
    if isinstance(meta, dict):
        affected = meta.get("affected_files")
        if isinstance(affected, list) and affected:
            first = affected[0]
            if isinstance(first, dict):
                start = first.get("start")
                if isinstance(start, dict):
                    file_path = _str(start.get("path"))
                    line = start.get("line")
    # fallback to direct fields
    if not file_path:
        file_path = _str(
            raw.get("file") or extra.get("file")
            or raw.get("path") or extra.get("path")
            or raw.get("filePath")
        )
    if line is None:
        line = raw.get("line") or extra.get("line") or raw.get("startLine")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        line = None

    evidence = _str(extra.get("evidence") or extra.get("reason"))
    remediation = _str(extra.get("fix") or extra.get("suggestion") or raw.get("remediation"))

    return SecurityFinding(
        severity=level_to_severity(level),
        code=rule_id,
        message=title,
        path=Path(file_path) if file_path else None,
        source="snyk",
        rule_id=rule_id,
        line=line,
        detail=description,
        remediation=remediation,
        evidence=evidence,
        source_severity=raw_severity,
        level=level,
        title=title,
        raw=dict(raw),
    )


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


def _redact(text: str, token: str) -> str:
    if token:
        text = text.replace(token, _REDACTED)
    return text


def _str(value: object) -> str | None:
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
