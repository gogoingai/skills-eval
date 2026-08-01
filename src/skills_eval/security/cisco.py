"""Isolated command-line adapter for Cisco's AI Skill Scanner."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from threading import Lock, Thread
from typing import Any

from skills_eval.models import Severity, parse_frontmatter
from skills_eval.security.base import (
    ExecutionDiagnostic,
    ScanOutcome,
    SecurityFinding,
)


_POLICIES = frozenset({"balanced", "strict", "permissive"})
_FAIL_SEVERITIES = frozenset({"critical", "high"})
_REVIEW_SEVERITIES = frozenset({"medium", "low", "info"})
_DETAIL_LIMIT = 2_000
_PROCESS_OUTPUT_LIMIT = 64 * 1024
_JSON_OUTPUT_LIMIT = 16 * 1024 * 1024
_SCANNER_TIMEOUT_SECONDS = 300.0
_CAPTURE_JOIN_TIMEOUT_SECONDS = 0.25
_PROCESS_TERMINATION_TIMEOUT_SECONDS = 1.0
_READ_CHUNK_SIZE = 8 * 1024
_SUPPORTED_OPTIONS = frozenset({"policy", "useBehavioral"})


def run_scanner(args: list[str]) -> tuple[int, str, str]:
    """Run the external scanner with bounded execution and captured output."""
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **_process_group_options(),
    )
    assert process.stdout is not None
    assert process.stderr is not None

    stdout_capture = _BoundedStreamCapture()
    stderr_capture = _BoundedStreamCapture()
    stdout_thread = Thread(
        target=stdout_capture.drain,
        args=(process.stdout,),
        daemon=True,
    )
    stderr_thread = Thread(
        target=stderr_capture.drain,
        args=(process.stderr,),
        daemon=True,
    )
    try:
        stdout_thread.start()
        stderr_thread.start()

        timed_out = False
        try:
            return_code = process.wait(timeout=_SCANNER_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_group(process)
            return_code = _wait_for_process(process)

        captures_complete = _join_capture_threads(stdout_thread, stderr_thread)
        if not captures_complete:
            timed_out = True
            _terminate_process_group(process)
            return_code = _wait_for_process(process)
            _join_capture_threads(stdout_thread, stderr_thread)

        stdout = stdout_capture.text()
        stderr = stderr_capture.text()
        if timed_out:
            raise subprocess.TimeoutExpired(
                cmd=args,
                timeout=_SCANNER_TIMEOUT_SECONDS,
                output=stdout,
                stderr=stderr,
            )
        return return_code, stdout, stderr
    except subprocess.TimeoutExpired:
        raise
    except BaseException:
        _terminate_process_group(process)
        _wait_for_process(process)
        _join_capture_threads(stdout_thread, stderr_thread)
        raise


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

            if return_code != 0:
                return _failed(
                    "CISCO_PROCESS_FAILED",
                    f"Cisco scanner exited with status {return_code}.",
                    stdout=stdout,
                    stderr=stderr,
                )

            try:
                output_text = _read_json_output(output_path)
            except _OutputTooLarge:
                return _failed(
                    "CISCO_OUTPUT_TOO_LARGE",
                    f"Cisco scanner JSON output exceeds the {_JSON_OUTPUT_LIMIT}-byte limit.",
                    stdout=stdout,
                    stderr=stderr,
                )
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
            if len(output_text) > _JSON_OUTPUT_LIMIT:
                return _failed(
                    "CISCO_OUTPUT_TOO_LARGE",
                    f"Cisco scanner JSON output exceeds the {_JSON_OUTPUT_LIMIT}-character limit.",
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

            findings = _filter_markdown_magic_mismatches(findings, skill_path)
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


class _OutputTooLarge(ValueError):
    """Raised before loading an oversized scanner artifact."""


def _read_json_output(path: Path) -> str:
    with path.open("rb") as output:
        contents = output.read(_JSON_OUTPUT_LIMIT + 1)
    if len(contents) > _JSON_OUTPUT_LIMIT:
        raise _OutputTooLarge
    return contents.decode("utf-8")


class _BoundedStreamCapture:
    def __init__(self) -> None:
        self._contents = bytearray()
        self._truncated = False
        self._lock = Lock()

    def drain(self, stream: Any) -> None:
        try:
            while chunk := stream.read(_READ_CHUNK_SIZE):
                with self._lock:
                    remaining = _PROCESS_OUTPUT_LIMIT - len(self._contents)
                    if remaining > 0:
                        self._contents.extend(chunk[:remaining])
                    if len(chunk) > max(remaining, 0):
                        self._truncated = True
        finally:
            stream.close()

    def text(self) -> str:
        with self._lock:
            contents = bytes(self._contents)
            truncated = self._truncated
        text = contents.decode("utf-8", errors="replace")
        if truncated:
            return f"{text}\n[truncated]"
        return text


def _process_group_options() -> dict[str, object]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_PROCESS_TERMINATION_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass


def _wait_for_process(process: subprocess.Popen[bytes]) -> int:
    try:
        return process.wait(timeout=_PROCESS_TERMINATION_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            return process.wait(timeout=_PROCESS_TERMINATION_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return process.returncode if process.returncode is not None else -1


def _join_capture_threads(*threads: Thread) -> bool:
    for thread in threads:
        if thread.ident is not None:
            thread.join(timeout=_CAPTURE_JOIN_TIMEOUT_SECONDS)
    return all(thread.ident is None or not thread.is_alive() for thread in threads)


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
