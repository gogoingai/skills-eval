import json
from pathlib import Path
import subprocess

import pytest

from skills_eval.models import Severity
from skills_eval.security import ScannerRegistry
from skills_eval.security.base import FindingLevel, ScanStatus
from skills_eval.security.snyk import SnykScanner

FIXTURES = Path(__file__).parent / "fixtures" / "snyk"
TOKEN = "snyk-test-token-abcdef-12345"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _set_token(monkeypatch, token=TOKEN) -> None:
    if token is None:
        monkeypatch.delenv("SNYK_TOKEN", raising=False)
    else:
        monkeypatch.setenv("SNYK_TOKEN", token)


def _patch_available(monkeypatch, available: bool = True) -> None:
    monkeypatch.setattr(
        "skills_eval.security.snyk.executable_path",
        lambda name: Path("/fake/uvx") if available and name == "uvx" else None,
    )


def _patch_run(monkeypatch, returns, capture=None):
    def fake_run(args, *, timeout=None, env=None, **kwargs):
        if capture is not None:
            capture["args"] = list(args)
            capture["env"] = dict(env) if env else {}
        return returns

    monkeypatch.setattr("skills_eval.security.snyk.run_subprocess", fake_run)


def _scanner_with_version() -> SnykScanner:
    scanner = SnykScanner()
    scanner._version = "0.5.15"
    return scanner


def test_is_available_reflects_uvx_resolution(monkeypatch) -> None:
    _patch_available(monkeypatch, available=True)
    assert SnykScanner().is_available() is True

    _patch_available(monkeypatch, available=False)
    assert SnykScanner().is_available() is False


def test_missing_token_is_skipped(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch, token=None)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("skills_eval.security.snyk.run_subprocess", fail_if_called)

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.SKIPPED
    assert "SNYK_TOKEN" in (outcome.skip_reason or "")
    assert called is False


def test_token_injected_via_env_not_command_line(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    captured: dict = {}
    _patch_run(monkeypatch, (0, _fixture("clean.json"), ""), capture=captured)

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.PASS
    args = captured["args"]
    assert args[0] == "uvx"
    assert "snyk-agent-scan@latest" in args
    assert "--json" in args
    assert TOKEN not in args
    assert captured["env"]["SNYK_TOKEN"] == TOKEN


def test_base_url_passed_when_configured(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    captured: dict = {}
    _patch_run(monkeypatch, (0, _fixture("clean.json"), ""), capture=captured)

    _scanner_with_version().scan(tmp_path, {"baseUrl": "https://custom.snyk.example"})

    assert "--base-url" in captured["args"]
    assert "https://custom.snyk.example" in captured["args"]


def test_clean_result_is_pass(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    _patch_run(monkeypatch, (0, _fixture("clean.json"), ""))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.PASS
    assert outcome.findings == ()
    assert outcome.diagnostic is None


def test_high_findings_map_to_fail(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    _patch_run(monkeypatch, (1, _fixture("high_risk.json"), ""))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.FAIL
    assert len(outcome.findings) == 2
    f0 = outcome.findings[0]
    assert f0.rule_id == "E005"
    assert f0.level is FindingLevel.HIGH
    assert f0.source_severity == "high"
    assert f0.severity is Severity.FAIL
    assert f0.title == "Suspicious download URL detected"
    assert f0.detail == "This issue occurs when an AI agent is directed to download from untrusted URLs."
    assert f0.path == Path("SKILL.md")
    assert f0.line == 9
    assert f0.evidence == "This is high-risk: it uses curl | bash to fetch and execute a .sh from an untrusted domain."
    assert f0.source == "snyk"
    assert outcome.findings[1].rule_id == "E006"
    assert outcome.findings[1].level is FindingLevel.HIGH


def test_medium_finding_is_warn(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    _patch_run(monkeypatch, (1, _fixture("medium.json"), ""))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.WARN
    assert outcome.findings[0].level is FindingLevel.MEDIUM
    assert outcome.findings[0].severity is Severity.REVIEW


def test_missing_fields_are_handled(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    _patch_run(monkeypatch, (1, _fixture("missing_fields.json"), ""))

    outcome = _scanner_with_version().scan(tmp_path, {})

    # Tolerant parser: dicts with code+extra_data/message, or severity+title.
    assert len(outcome.findings) == 2
    assert outcome.findings[0].rule_id == "X001"
    assert outcome.findings[0].level is FindingLevel.INFO
    assert outcome.findings[1].rule_id == "X002"
    assert outcome.findings[1].level is FindingLevel.HIGH


def test_version_variant_is_tolerated(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    _patch_run(monkeypatch, (1, _fixture("version_variant.json"), ""))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.FAIL
    assert outcome.findings[0].rule_id == "FUT-001"
    assert outcome.findings[0].level is FindingLevel.HIGH
    assert outcome.findings[0].path == Path("SKILL.md")
    assert outcome.findings[0].line == 2
    assert outcome.findings[0].raw["extra_data"]["extraFutureField"] == "ignored"


def test_empty_output_is_pass(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    _patch_run(monkeypatch, (0, "", ""))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.PASS


def test_invalid_json_is_execution_error(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    _patch_run(monkeypatch, (1, _fixture("invalid.txt"), ""))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.ERROR
    assert outcome.diagnostic.code == "SNYK_OUTPUT_INVALID"


def test_failure_exit_is_execution_error(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    _patch_run(monkeypatch, (2, "", "internal error"))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.ERROR
    assert outcome.diagnostic.code == "SNYK_PROCESS_FAILED"


def test_timeout_is_execution_error(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)

    def raise_timeout(args, *, timeout=None, env=None, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout, output="", stderr="")

    monkeypatch.setattr("skills_eval.security.snyk.run_subprocess", raise_timeout)

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.ERROR
    assert outcome.diagnostic.code == "SNYK_PROCESS_TIMEOUT"


def test_token_is_redacted_from_failure_diagnostics(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    _patch_run(monkeypatch, (2, "", f"auth failed for {TOKEN}"))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.ERROR
    assert TOKEN not in outcome.diagnostic.detail
    assert "***REDACTED***" in outcome.diagnostic.detail


def test_missing_executable_is_error_with_install_guidance(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch, available=False)
    _set_token(monkeypatch)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("skills_eval.security.snyk.run_subprocess", fail_if_called)

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.ERROR
    assert outcome.diagnostic.code == "SNYK_EXECUTABLE_MISSING"
    assert "uv" in outcome.diagnostic.detail
    assert called is False


def test_unknown_option_is_rejected(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_token(monkeypatch)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("skills_eval.security.snyk.run_subprocess", fail_if_called)

    outcome = _scanner_with_version().scan(tmp_path, {"bogus": True})

    assert outcome.status is ScanStatus.ERROR
    assert outcome.diagnostic.code == "SNYK_OPTIONS_INVALID"
    assert called is False


def test_get_version_parses_version_output(monkeypatch) -> None:
    _patch_run(monkeypatch, (0, "0.5.15\n", ""))

    assert SnykScanner().get_version() == "0.5.15"


@pytest.mark.parametrize(
    ("source", "level"),
    [
        ("critical", FindingLevel.CRITICAL),
        ("high", FindingLevel.HIGH),
        ("medium", FindingLevel.MEDIUM),
        ("moderate", FindingLevel.MEDIUM),
        ("low", FindingLevel.LOW),
        ("info", FindingLevel.INFO),
        ("unknown", FindingLevel.INFO),
    ],
)
def test_severity_mapping(source, level) -> None:
    payload = {"issues": [{"severity": source, "title": "test"}]}
    findings = SnykScanner().normalize_result(payload)
    assert findings[0].level is level
    assert findings[0].source_severity == source


def test_registry_creates_snyk_scanner() -> None:
    scanner = ScannerRegistry.create("snyk")
    assert isinstance(scanner, SnykScanner)
