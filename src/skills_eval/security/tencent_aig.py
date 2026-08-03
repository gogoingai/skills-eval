"""Tencent AI-Infra-Guard ``aig-skill-scan`` adapter (OpenAI-compatible LLM scan)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from importlib import metadata
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

_SCANNER_TIMEOUT_SECONDS = 600.0
_DETAIL_LIMIT = 2_000
_JSON_OUTPUT_LIMIT = 32 * 1024 * 1024
_SUPPORTED_OPTIONS = frozenset({"apiKeyEnv", "baseUrlEnv", "modelEnv", "language", "executable", "disableThinking"})
# SARIF level -> unified finding level. SARIF defaults to "warning" when omitted.
_LEVEL_BY_SARIF = {
    "error": FindingLevel.HIGH,
    "warning": FindingLevel.MEDIUM,
    "note": FindingLevel.LOW,
    "none": FindingLevel.INFO,
}
_REDACTED = "***REDACTED***"
# DeepSeek V4 models enable "thinking" by default, which is slow. This patch is
# written to a temp dir and placed on PYTHONPATH so Python auto-loads it as
# sitecustomize; it monkey-patches the OpenAI SDK to pass
# extra_body={"thinking":{"type":"disabled"}} unless AIG_THINKING=enabled.
# No installed package is modified; controlled via the disableThinking option.
_NO_THINK_PATCH = '''"""Disable DeepSeek V4 thinking for faster aig-skill-scan runs."""
import os
if os.environ.get("AIG_THINKING", "disabled").lower() != "enabled":
    try:
        import openai.resources.chat.completions as _c
        _orig = _c.Completions.create
        def _patched(self, *a, **k):
            eb = k.get("extra_body")
            if not isinstance(eb, dict):
                eb = {}
            eb.setdefault("thinking", {"type": "disabled"})
            k["extra_body"] = eb
            return _orig(self, *a, **k)
        _c.Completions.create = _patched
    except Exception:
        pass
'''


class TencentAigScanner:
    """Normalize Tencent ``aig-skill-scan`` SARIF output into shared models.

    The scanner runs standalone (no web platform) against a local Skill
    directory. LLM credentials (API key, base URL, model) are injected only via
    subprocess environment variables and never appear on the command line or in
    reports. It is OpenAI-compatible and not bound to a single vendor.
    """

    name = "tencent-aig"

    def __init__(self) -> None:
        self._version: str | None = None

    def is_available(self) -> bool:
        """Return whether the ``aig-skill-scan`` CLI can be resolved."""
        return executable_path(_default_executable()) is not None

    def get_version(self) -> str | None:
        """Return the installed ``aig-skill-scan`` version, cached after the first call."""
        if self._version is None:
            try:
                self._version = metadata.version("aig-skill-scan")
            except metadata.PackageNotFoundError:
                self._version = ""
        return self._version or None

    def normalize_result(self, raw_result: object) -> tuple[SecurityFinding, ...]:
        """Normalize a parsed SARIF 2.1.0 payload into security findings."""
        return _normalize_sarif(raw_result)

    def scan(self, skill_path: Path, options: dict[str, object]) -> ScanOutcome:
        option_error = _validate_options(options)
        if option_error is not None:
            return _failed("TENCENT_AIG_OPTIONS_INVALID", option_error)

        executable = str(options.get("executable") or _default_executable())
        if executable_path(executable) is None:
            return _failed(
                "TENCENT_AIG_EXECUTABLE_MISSING",
                f"Tencent aig-skill-scan executable was not found: {executable!r}.",
                hint=_INSTALL_GUIDE,
            )

        api_key_env = str(options.get("apiKeyEnv") or "LLM_API_KEY")
        model_env = str(options.get("modelEnv") or "LLM_MODEL")
        base_url_env = str(options.get("baseUrlEnv") or "LLM_BASE_URL")
        api_key = os.environ.get(api_key_env, "")
        model = os.environ.get(model_env, "")
        if not api_key or not model:
            return ScanOutcome(
                status=ScanStatus.SKIPPED,
                skip_reason=(
                    "missing LLM API key or model; set the configured environment "
                    f"variables ({api_key_env}, {model_env})"
                ),
                version=self.get_version(),
            )

        # The API key stays in the subprocess environment (never on the command
        # line). Model and base URL are not secret and MUST be passed explicitly:
        # aig-skill-scan's --model/--base_url argparse defaults are truthy, so its
        # LLM_MODEL/LLM_BASE_URL env-var fallbacks are never applied.
        language = str(options.get("language") or "en")
        version = self.get_version()
        base_url = os.environ.get(base_url_env, "")
        secrets = {api_key}
        env = dict(os.environ)
        env["LLM_API_KEY"] = api_key

        patch_dir: Path | None = None
        if options.get("disableThinking") is True:
            patch_dir = Path(tempfile.mkdtemp(prefix="skills-eval-aig-nothink-"))
            (patch_dir / "sitecustomize.py").write_text(_NO_THINK_PATCH, encoding="utf-8")
            env["PYTHONPATH"] = (
                str(patch_dir) + os.pathsep + env.get("PYTHONPATH", "")
            ).rstrip(os.pathsep)

        output_path: Path | None = None
        start = time.monotonic()
        try:
            with staged_scan_input(skill_path) as scan_path:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    prefix="skills-eval-tencent-aig-",
                    suffix=".sarif.json",
                    delete=False,
                ) as output:
                    output_path = Path(output.name)
                args = [
                    resolve_executable(executable),
                    "--repo",
                    str(scan_path),
                    "--language",
                    language,
                    "-m",
                    model,
                ]
                if base_url:
                    args.extend(["-u", base_url])
                args.extend(["-o", str(output_path)])
                try:
                    return_code, stdout, stderr = run_subprocess(
                        args, timeout=_SCANNER_TIMEOUT_SECONDS, env=env
                    )
                except subprocess.TimeoutExpired as error:
                    return _failed(
                        "TENCENT_AIG_PROCESS_TIMEOUT",
                        f"Tencent aig-skill-scan exceeded the {error.timeout:g}-second limit.",
                        stdout=_redact(_output_text(error.stdout), secrets),
                        stderr=_redact(_output_text(error.stderr), secrets),
                    )
                except FileNotFoundError:
                    return _failed(
                        "TENCENT_AIG_EXECUTABLE_MISSING",
                        "Tencent aig-skill-scan executable was not found.",
                        hint=_INSTALL_GUIDE,
                    )
                except OSError as error:
                    return _failed(
                        "TENCENT_AIG_PROCESS_ERROR",
                        "Tencent aig-skill-scan could not be started.",
                        error=str(error),
                    )
            duration_ms = int((time.monotonic() - start) * 1000)

            if return_code != 0:
                return _failed(
                    "TENCENT_AIG_PROCESS_FAILED",
                    f"Tencent aig-skill-scan exited with status {return_code}.",
                    stdout=_redact(stdout, secrets),
                    stderr=_redact(stderr, secrets),
                    duration_ms=duration_ms,
                    version=version,
                )

            try:
                output_text = _read_json_output(output_path)
            except _OutputTooLarge:
                return _failed(
                    "TENCENT_AIG_OUTPUT_TOO_LARGE",
                    f"Tencent aig-skill-scan SARIF output exceeds the {_JSON_OUTPUT_LIMIT}-byte limit.",
                    stderr=_redact(stderr, secrets),
                    duration_ms=duration_ms,
                    version=version,
                )
            except (OSError, UnicodeDecodeError) as error:
                return _failed(
                    "TENCENT_AIG_OUTPUT_UNREADABLE",
                    "Tencent aig-skill-scan SARIF output could not be read.",
                    stderr=_redact(stderr, secrets),
                    error=str(error),
                    duration_ms=duration_ms,
                    version=version,
                )
            if not output_text.strip():
                return _failed(
                    "TENCENT_AIG_OUTPUT_UNREADABLE",
                    "Tencent aig-skill-scan did not produce SARIF output.",
                    stderr=_redact(stderr, secrets),
                    duration_ms=duration_ms,
                    version=version,
                )

            try:
                payload = json.loads(output_text)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                return _failed(
                    "TENCENT_AIG_OUTPUT_INVALID",
                    "Tencent aig-skill-scan output is not valid JSON.",
                    output=_redact(output_text, secrets),
                    stderr=_redact(stderr, secrets),
                    error=str(error),
                    duration_ms=duration_ms,
                    version=version,
                )

            try:
                findings = _normalize_sarif(payload)
            except ValueError as error:
                return _failed(
                    "TENCENT_AIG_PAYLOAD_INVALID",
                    f"Tencent aig-skill-scan returned an unexpected payload: {error}",
                    output=_redact(output_text, secrets),
                    stderr=_redact(stderr, secrets),
                    duration_ms=duration_ms,
                    version=version,
                )

            status = _outcome_status(findings)
            return ScanOutcome(
                status=status,
                findings=findings,
                duration_ms=duration_ms,
                version=version,
                raw_result=payload if isinstance(payload, dict) else None,
            )
        finally:
            if output_path is not None:
                try:
                    output_path.unlink(missing_ok=True)
                except OSError:
                    pass
            if patch_dir is not None:
                shutil.rmtree(patch_dir, ignore_errors=True)


def _default_executable() -> str:
    return "aig-skill-scan"


_INSTALL_GUIDE = (
    "Install Tencent aig-skill-scan with: pip install aig-skill-scan "
    "(or pip install \"skills-eval[tencent-aig]\")."
)


def _validate_options(options: dict[str, object]) -> str | None:
    unknown = sorted(set(options) - _SUPPORTED_OPTIONS)
    if unknown:
        return f"Unknown Tencent aig-skill-scan option: {unknown[0]!r}."
    for key in ("apiKeyEnv", "baseUrlEnv", "modelEnv", "executable"):
        value = options.get(key)
        if value is not None and not isinstance(value, str):
            return f"Tencent aig-skill-scan option {key!r} must be a string."
    language = options.get("language", "en")
    if not isinstance(language, str) or language not in {"zh", "en"}:
        return "Tencent aig-skill-scan option 'language' must be 'zh' or 'en'."
    disable_thinking = options.get("disableThinking", False)
    if not isinstance(disable_thinking, bool):
        return "Tencent aig-skill-scan option 'disableThinking' must be a boolean."
    return None


def _normalize_sarif(payload: Any) -> tuple[SecurityFinding, ...]:
    if not isinstance(payload, dict):
        raise ValueError("top-level value must be an object")
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ValueError("'runs' must be an array")

    findings: list[SecurityFinding] = []
    index = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            if _is_placeholder_result(result):
                continue
            findings.append(_finding_from_result(result, index))
            index += 1
    return tuple(findings)


def _is_placeholder_result(result: dict[str, object]) -> bool:
    """Detect SARIF results that are unfilled template placeholders.

    The LLM-backed ``aig-skill-scan`` occasionally emits results whose fields
    are still the SARIF template's documentation text (e.g. message ``"title"``,
    file ``"File path relative to the project root, e.g. scripts/setup.sh"``).
    These are scanner output bugs, not real findings, so they are dropped.
    """
    message_text = _message_text(result.get("message"))
    if message_text and message_text.strip().lower() == "title":
        return True
    location = _first_location(result.get("locations"))
    file_path = _location_file(location)
    if file_path and any(
        marker in file_path
        for marker in ("File path relative to", "e.g.", "<path>", "<")
    ):
        return True
    return False


def _finding_from_result(result: dict[str, object], index: int) -> SecurityFinding:
    rule_id = _nonempty_string(result.get("ruleId")) or f"TENCENT-AIG-{index}"
    raw_level = _nonempty_string(result.get("level")) or "warning"
    source_severity = raw_level.lower()
    level = _LEVEL_BY_SARIF.get(source_severity, FindingLevel.MEDIUM)

    message_text = _message_text(result.get("message"))
    title = message_text or rule_id

    location = _first_location(result.get("locations"))
    file_path = _location_file(location)
    line = _location_line(location)
    fix = _first_fix_text(result.get("fixes"))

    return SecurityFinding(
        severity=level_to_severity(level),
        code=rule_id,
        message=title,
        path=Path(file_path) if file_path else None,
        source="tencent-aig",
        rule_id=rule_id,
        line=line,
        detail=message_text,
        remediation=fix,
        evidence=None,
        source_severity=raw_level,
        level=level,
        title=title,
        raw=dict(result),
    )


def _message_text(message: object) -> str | None:
    if isinstance(message, str):
        return _nonempty_string(message)
    if isinstance(message, dict):
        return _nonempty_string(message.get("text"))
    return None


def _first_location(locations: object) -> dict[str, object] | None:
    if isinstance(locations, list) and locations:
        first = locations[0]
        if isinstance(first, dict):
            return first
    return None


def _location_file(location: dict[str, object] | None) -> str | None:
    if not location:
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        return None
    return _nonempty_string(artifact.get("uri"))


def _location_line(location: dict[str, object] | None) -> int | None:
    if not location:
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    region = physical.get("region")
    if not isinstance(region, dict):
        return None
    value = region.get("startLine")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def _first_fix_text(fixes: object) -> str | None:
    if not isinstance(fixes, list) or not fixes:
        return None
    first = fixes[0]
    if not isinstance(first, dict):
        return None
    description = first.get("description")
    if isinstance(description, dict):
        return _nonempty_string(description.get("text"))
    if isinstance(description, str):
        return _nonempty_string(description)
    return None


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


def _redact(text: str, secrets: set[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, _REDACTED)
    return text


class _OutputTooLarge(ValueError):
    """Raised before loading an oversized scanner artifact."""


def _read_json_output(path: Path) -> str:
    with path.open("rb") as output:
        contents = output.read(_JSON_OUTPUT_LIMIT + 1)
    if len(contents) > _JSON_OUTPUT_LIMIT:
        raise _OutputTooLarge
    return contents.decode("utf-8")


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
