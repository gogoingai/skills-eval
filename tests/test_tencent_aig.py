import json
import os
from pathlib import Path
import subprocess

import pytest

from skills_eval.models import Severity
from skills_eval.security import ScannerRegistry
from skills_eval.security.base import FindingLevel, ScanStatus
from skills_eval.security.tencent_aig import TencentAigScanner

FIXTURES = Path(__file__).parent / "fixtures" / "tencent_aig"
API_KEY = "sk-test-secret-key-12345"
MODEL = "test-scan-model"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _set_creds(monkeypatch, *, key=API_KEY, model=MODEL) -> None:
    if key is None:
        monkeypatch.delenv("LLM_API_KEY", raising=False)
    else:
        monkeypatch.setenv("LLM_API_KEY", key)
    if model is None:
        monkeypatch.delenv("LLM_MODEL", raising=False)
    else:
        monkeypatch.setenv("LLM_MODEL", model)
    monkeypatch.setenv("LLM_BASE_URL", "https://example.test/v1")


def _patch_available(monkeypatch, available: bool = True) -> None:
    monkeypatch.setattr(
        "skills_eval.security.tencent_aig.executable_path",
        lambda name: Path("/fake/aig-skill-scan") if available else None,
    )


def _patch_run_writes_sarif(monkeypatch, sarif_text, returns=(0, "", ""), capture=None):
    def fake_run(args, *, timeout=None, env=None, **kwargs):
        output_path = Path(args[args.index("-o") + 1])
        output_path.write_text(sarif_text, encoding="utf-8")
        if capture is not None:
            capture["args"] = list(args)
            capture["env"] = dict(env) if env else {}
        return returns

    monkeypatch.setattr("skills_eval.security.tencent_aig.run_subprocess", fake_run)


def _scanner_with_version() -> TencentAigScanner:
    scanner = TencentAigScanner()
    scanner._version = "0.2.1"
    return scanner


def test_is_available_reflects_executable_resolution(monkeypatch) -> None:
    _patch_available(monkeypatch, available=True)
    assert TencentAigScanner().is_available() is True

    _patch_available(monkeypatch, available=False)
    assert TencentAigScanner().is_available() is False


def test_missing_credentials_is_skipped(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch, key=None, model=None)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("skills_eval.security.tencent_aig.run_subprocess", fail_if_called)

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.SKIPPED
    assert "LLM_API_KEY" in (outcome.skip_reason or "")
    assert outcome.diagnostic is None
    assert called is False


def test_missing_model_is_skipped(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch, model=None)

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.SKIPPED


def test_credentials_injected_via_env_not_command_line(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    captured: dict = {}
    _patch_run_writes_sarif(monkeypatch, _fixture("clean.sarif.json"), capture=captured)

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.PASS
    args = captured["args"]
    assert "--repo" in args and "-o" in args and "--language" in args
    # Model and base URL are passed explicitly (non-secret); the API key is not.
    assert "-m" in args and MODEL in args
    assert "-u" in args and "https://example.test/v1" in args
    assert API_KEY not in args
    assert "-k" not in args
    env = captured["env"]
    assert env["LLM_API_KEY"] == API_KEY
    # Model/base URL are passed on the command line (their env fallback is broken
    # in aig-skill-scan), so the adapter does not rely on env for them.


def test_clean_sarif_is_pass(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    _patch_run_writes_sarif(monkeypatch, _fixture("clean.sarif.json"))


def test_disable_thinking_sets_pythonpath_patch(monkeypatch, tmp_path) -> None:
    """disableThinking=true puts a sitecustomize patch dir on PYTHONPATH so the
    DeepSeek thinking mode is disabled in the aig-skill-scan subprocess; without
    the option, PYTHONPATH is left untouched."""
    from skills_eval.security.tencent_aig import _NO_THINK_PATCH

    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    captured: dict = {}
    _patch_run_writes_sarif(monkeypatch, _fixture("clean.sarif.json"), capture=captured)

    outcome = _scanner_with_version().scan(tmp_path, {"disableThinking": True})

    assert outcome.status is ScanStatus.PASS
    env = captured["env"]
    assert "PYTHONPATH" in env
    assert "skills-eval-aig-nothink" in env["PYTHONPATH"]
    # The patch content disables thinking via the OpenAI extra_body.
    assert "thinking" in _NO_THINK_PATCH
    assert "disabled" in _NO_THINK_PATCH

    # Without the option, PYTHONPATH is not modified by the adapter.
    captured2: dict = {}
    _patch_run_writes_sarif(monkeypatch, _fixture("clean.sarif.json"), capture=captured2)
    _scanner_with_version().scan(tmp_path, {})
    assert "skills-eval-aig-nothink" not in captured2["env"].get("PYTHONPATH", "")


    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.PASS
    assert outcome.findings == ()
    assert outcome.diagnostic is None


def test_placeholder_sarif_results_are_dropped(monkeypatch, tmp_path) -> None:
    """Unfilled SARIF template placeholders (message 'title', template file
    paths) are scanner output bugs, not real findings - they must be filtered."""
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    sarif = json.dumps({
        "runs": [{
            "results": [
                {
                    "ruleId": "T08",
                    "level": "warning",
                    "message": {"text": "Real finding"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "SKILL.md"}, "region": {"startLine": 1}}}],
                },
                {
                    "ruleId": "other",
                    "level": "note",
                    "message": {"text": "title"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "File path relative to the project root, e.g. scripts/setup.sh"}, "region": {}}}],
                },
                {
                    "ruleId": "other",
                    "level": "note",
                    "message": {"text": "<path> placeholder"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "<path>"}}}],
                },
            ]
        }]
    })
    _patch_run_writes_sarif(monkeypatch, sarif)

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert [f.rule_id for f in outcome.findings] == ["T08"]
    assert outcome.findings[0].title == "Real finding"


def test_high_risk_sarif_maps_to_fail(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    _patch_run_writes_sarif(monkeypatch, _fixture("high_risk.sarif.json"))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.FAIL
    assert [f.rule_id for f in outcome.findings] == ["T04", "T02"]
    assert outcome.findings[0].level is FindingLevel.HIGH
    assert outcome.findings[0].source_severity == "error"
    assert outcome.findings[0].severity is Severity.FAIL
    assert outcome.findings[0].path == Path("scripts/setup.sh")
    assert outcome.findings[0].line == 12
    assert outcome.findings[0].title == "Dangerous remote script execution"
    assert outcome.findings[0].remediation == "Remove the curl|sh pipeline."
    assert outcome.findings[0].source == "tencent-aig"


def test_medium_sarif_is_warn(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    _patch_run_writes_sarif(monkeypatch, _fixture("medium.sarif.json"))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.WARN
    assert outcome.findings[0].level is FindingLevel.MEDIUM
    assert outcome.findings[0].severity is Severity.REVIEW


def test_missing_fields_are_handled(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    _patch_run_writes_sarif(monkeypatch, _fixture("missing_fields.sarif.json"))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.WARN
    assert len(outcome.findings) == 3
    assert outcome.findings[0].rule_id == "T01"
    assert outcome.findings[0].line is None
    assert outcome.findings[0].path is None
    # Default SARIF level is "warning" -> MEDIUM.
    assert outcome.findings[0].level is FindingLevel.MEDIUM
    # A "note" level with no ruleId gets a generated id and LOW level.
    note = outcome.findings[1]
    assert note.level is FindingLevel.LOW
    assert note.rule_id.startswith("TENCENT-AIG-")


def test_version_variant_and_multiple_runs_are_aggregated(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    _patch_run_writes_sarif(monkeypatch, _fixture("version_variant.sarif.json"))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.FAIL
    assert [f.rule_id for f in outcome.findings] == ["T05", "T06"]
    assert outcome.findings[0].raw["extraField"] == "ignored-by-parser"


def test_invalid_json_is_execution_error(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    _patch_run_writes_sarif(monkeypatch, _fixture("invalid.txt"))

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.ERROR
    assert outcome.diagnostic.code == "TENCENT_AIG_OUTPUT_INVALID"


def test_non_zero_exit_is_execution_error(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    _patch_run_writes_sarif(
        monkeypatch, _fixture("clean.sarif.json"), returns=(2, "", "boom")
    )

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.ERROR
    assert outcome.diagnostic.code == "TENCENT_AIG_PROCESS_FAILED"


def test_timeout_is_execution_error(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)

    def raise_timeout(args, *, timeout=None, env=None, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout, output="", stderr="")

    monkeypatch.setattr("skills_eval.security.tencent_aig.run_subprocess", raise_timeout)

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.ERROR
    assert outcome.diagnostic.code == "TENCENT_AIG_PROCESS_TIMEOUT"


def test_api_key_is_redacted_from_failure_diagnostics(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    _patch_run_writes_sarif(
        monkeypatch,
        _fixture("clean.sarif.json"),
        returns=(2, "", f"error: auth failed for {API_KEY}"),
    )

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.ERROR
    detail = outcome.diagnostic.detail
    assert API_KEY not in detail
    assert "***REDACTED***" in detail


def test_missing_executable_is_error_with_install_guidance(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch, available=False)
    _set_creds(monkeypatch)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("skills_eval.security.tencent_aig.run_subprocess", fail_if_called)

    outcome = _scanner_with_version().scan(tmp_path, {})

    assert outcome.status is ScanStatus.ERROR
    assert outcome.diagnostic.code == "TENCENT_AIG_EXECUTABLE_MISSING"
    assert "pip install" in outcome.diagnostic.detail
    assert called is False


def test_unknown_option_is_rejected(monkeypatch, tmp_path) -> None:
    _patch_available(monkeypatch)
    _set_creds(monkeypatch)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("skills_eval.security.tencent_aig.run_subprocess", fail_if_called)

    outcome = _scanner_with_version().scan(tmp_path, {"bogus": True})

    assert outcome.status is ScanStatus.ERROR
    assert outcome.diagnostic.code == "TENCENT_AIG_OPTIONS_INVALID"
    assert called is False


@pytest.mark.parametrize(
    ("sarif_level", "level"),
    [
        ("error", FindingLevel.HIGH),
        ("warning", FindingLevel.MEDIUM),
        ("note", FindingLevel.LOW),
        ("none", FindingLevel.INFO),
    ],
)
def test_sarif_level_mapping(sarif_level, level) -> None:
    payload = {
        "runs": [{"results": [{"ruleId": "X", "level": sarif_level, "message": {"text": "t"}}]}]
    }
    findings = TencentAigScanner().normalize_result(payload)
    assert findings[0].level is level
    assert findings[0].source_severity == sarif_level


def test_normalize_result_rejects_non_object() -> None:
    with pytest.raises(ValueError):
        TencentAigScanner().normalize_result([])


def test_registry_creates_tencent_aig_scanner() -> None:
    scanner = ScannerRegistry.create("tencent-aig")
    assert isinstance(scanner, TencentAigScanner)
