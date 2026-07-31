import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import textwrap
import time

import pytest

from skills_eval.models import Diagnostic, Finding, Severity
from skills_eval.security import ScannerRegistry
from skills_eval.security.base import ScanOutcome, SecurityScanner
from skills_eval.security.cisco import CiscoScanner, run_scanner


def _write_scanner_output(args: list[str], payload: object) -> None:
    output_path = Path(args[args.index("--output") + 1])
    output_path.write_text(json.dumps(payload), encoding="utf-8")


def test_cisco_adapter_maps_medium_finding_to_review(monkeypatch, tmp_path) -> None:
    payload = {
        "findings": [
            {"rule_id": "PI-001", "severity": "medium", "message": "Injected instruction"}
        ]
    }
    monkeypatch.setattr(
        "skills_eval.security.cisco.run_scanner",
        lambda *args: (0, json.dumps(payload), ""),
    )

    outcome = CiscoScanner().scan(tmp_path, {"policy": "balanced"})

    assert outcome.status is Severity.REVIEW
    assert outcome.findings[0].source == "cisco"
    assert outcome.findings[0].rule_id == "PI-001"
    assert outcome.findings[0].message == "Injected instruction"
    assert outcome.findings[0].source_severity == "medium"
    assert isinstance(outcome.findings[0], Finding)
    assert outcome.diagnostic is None


@pytest.mark.parametrize("source_severity", ["critical", "HIGH"])
def test_cisco_adapter_maps_high_severity_findings_to_fail(
    monkeypatch, tmp_path, source_severity
) -> None:
    payload = {
        "findings": [
            {
                "rule_id": "DANGEROUS",
                "severity": source_severity,
                "description": "Dangerous behavior",
                "file_path": "scripts/run.py",
            }
        ]
    }

    def fake_run(args):
        _write_scanner_output(args, payload)
        return 0, "", ""

    monkeypatch.setattr("skills_eval.security.cisco.run_scanner", fake_run)

    outcome = CiscoScanner().scan(tmp_path, {})

    assert outcome.status is Severity.FAIL
    assert outcome.findings[0].severity is Severity.FAIL
    assert outcome.findings[0].path == Path("scripts/run.py")


@pytest.mark.parametrize("source_severity", ["medium", "LOW", "info"])
def test_cisco_adapter_maps_non_blocking_findings_to_review(
    monkeypatch, tmp_path, source_severity
) -> None:
    payload = {
        "findings": [
            {
                "rule_id": "REVIEW-ME",
                "severity": source_severity,
                "title": "Needs review",
            }
        ]
    }

    def fake_run(args):
        _write_scanner_output(args, payload)
        return 0, "", ""

    monkeypatch.setattr("skills_eval.security.cisco.run_scanner", fake_run)

    outcome = CiscoScanner().scan(tmp_path, {})

    assert outcome.status is Severity.REVIEW
    assert outcome.findings[0].severity is Severity.REVIEW
    assert outcome.findings[0].message == "Needs review"


def test_cisco_adapter_passes_when_scanner_reports_no_findings(monkeypatch, tmp_path) -> None:
    def fake_run(args):
        _write_scanner_output(args, {"findings": []})
        return 0, "", ""

    monkeypatch.setattr("skills_eval.security.cisco.run_scanner", fake_run)

    outcome = CiscoScanner().scan(tmp_path, {})

    assert outcome.status is Severity.PASS
    assert outcome.findings == ()
    assert outcome.diagnostic is None


def test_cisco_adapter_uses_supported_options_and_deletes_temporary_output(
    monkeypatch, tmp_path
) -> None:
    observed_args: list[str] = []
    output_path: Path | None = None

    def fake_run(args):
        nonlocal output_path
        observed_args.extend(args)
        output_path = Path(args[args.index("--output") + 1])
        output_path.write_text('{"findings": []}', encoding="utf-8")
        return 0, "", ""

    monkeypatch.setattr("skills_eval.security.cisco.run_scanner", fake_run)

    outcome = CiscoScanner(executable="custom-scanner").scan(
        tmp_path,
        {
            "policy": "strict",
            "useBehavioral": True,
        },
    )

    assert outcome.status is Severity.PASS
    assert observed_args[:5] == [
        "custom-scanner",
        "scan",
        str(tmp_path),
        "--format",
        "json",
    ]
    assert observed_args[-3:] == ["--policy", "strict", "--use-behavioral"]
    assert output_path is not None
    assert not output_path.exists()


def test_cisco_adapter_rejects_unknown_option_keys(monkeypatch, tmp_path) -> None:
    called = False

    def fake_run(*args):
        nonlocal called
        called = True
        return 0, '{"findings": []}', ""

    monkeypatch.setattr("skills_eval.security.cisco.run_scanner", fake_run)

    outcome = CiscoScanner().scan(tmp_path, {"unrecognized": "--dangerous"})

    assert outcome.status is Severity.FAIL
    assert outcome.diagnostic is not None
    assert outcome.diagnostic.code == "CISCO_OPTIONS_INVALID"
    assert called is False


def test_run_scanner_times_out_and_retains_bounded_output(monkeypatch) -> None:
    monkeypatch.setattr("skills_eval.security.cisco._SCANNER_TIMEOUT_SECONDS", 0.2)

    with pytest.raises(subprocess.TimeoutExpired) as caught:
        run_scanner(
            [
                sys.executable,
                "-c",
                "import time; print('started', flush=True); time.sleep(2)",
            ]
        )

    assert "started" in (caught.value.stdout or "")


def test_cisco_adapter_turns_timeout_into_execution_diagnostic(
    monkeypatch, tmp_path
) -> None:
    def timed_out(*args):
        raise subprocess.TimeoutExpired(
            cmd=["skill-scanner"],
            timeout=5,
            output="partial output",
            stderr="scan exceeded limit",
        )

    monkeypatch.setattr("skills_eval.security.cisco.run_scanner", timed_out)

    outcome = CiscoScanner().scan(tmp_path, {})

    assert outcome.status is Severity.FAIL
    assert outcome.diagnostic is not None
    assert outcome.diagnostic.code == "CISCO_PROCESS_TIMEOUT"
    assert "partial output" in outcome.diagnostic.detail
    assert "scan exceeded limit" in outcome.diagnostic.detail


def test_timeout_kills_descendant_holding_capture_pipes(tmp_path) -> None:
    survivor_marker = tmp_path / "descendant-survived"
    descendant_code = (
        "import time; from pathlib import Path; "
        f"time.sleep(0.2); Path({str(survivor_marker)!r}).write_text('alive')"
    )
    scanner_code = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {descendant_code!r}]); "
        "print('scanner started', flush=True); "
        "time.sleep(1)"
    )
    probe = textwrap.dedent(
        f"""
        import subprocess
        import sys
        from pathlib import Path

        from skills_eval.security import cisco

        real_run_scanner = cisco.run_scanner
        cisco._SCANNER_TIMEOUT_SECONDS = 0.05

        def run_descendant_process(_args):
            return real_run_scanner(
                [
                    sys.executable,
                    "-c",
                    {scanner_code!r},
                ]
            )

        cisco.run_scanner = run_descendant_process
        outcome = cisco.CiscoScanner().scan(Path("."), {{}})
        print(outcome.diagnostic.code if outcome.diagnostic else "missing diagnostic")
        """
    )

    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=0.75,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == "CISCO_PROCESS_TIMEOUT"
    time.sleep(0.3)
    assert not survivor_marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group regression")
def test_keyboard_interrupt_terminates_descendant_group(
    monkeypatch, tmp_path
) -> None:
    ready_marker = tmp_path / "scanner-ready"
    survivor_marker = tmp_path / "descendant-survived"
    descendant_code = (
        "import time; from pathlib import Path; "
        f"time.sleep(0.2); Path({str(survivor_marker)!r}).write_text('alive')"
    )
    scanner_code = (
        "import subprocess, sys, time; from pathlib import Path; "
        f"subprocess.Popen([sys.executable, '-c', {descendant_code!r}]); "
        f"Path({str(ready_marker)!r}).write_text('ready'); "
        "time.sleep(1)"
    )
    real_popen = subprocess.Popen
    spawned: list[tuple[subprocess.Popen, object]] = []

    def interrupting_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        original_wait = process.wait
        interrupted = False

        def interrupt_once(timeout=None):
            nonlocal interrupted
            if not interrupted:
                deadline = time.monotonic() + 0.5
                while not ready_marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not ready_marker.exists():
                    raise AssertionError("scanner descendant was not ready")
                interrupted = True
                raise KeyboardInterrupt
            return original_wait(timeout=timeout)

        process.wait = interrupt_once
        spawned.append((process, original_wait))
        return process

    monkeypatch.setattr("skills_eval.security.cisco.subprocess.Popen", interrupting_popen)

    try:
        with pytest.raises(KeyboardInterrupt):
            run_scanner([sys.executable, "-c", scanner_code])

        time.sleep(0.3)
        assert not survivor_marker.exists()
    finally:
        for process, original_wait in spawned:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            original_wait(timeout=1)


def test_run_scanner_bounds_stdout_and_stderr_before_returning(monkeypatch) -> None:
    monkeypatch.setattr("skills_eval.security.cisco._PROCESS_OUTPUT_LIMIT", 128)

    return_code, stdout, stderr = run_scanner(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "sys.stdout.write('o' * 10000); "
                "sys.stderr.write('e' * 10000)"
            ),
        ]
    )

    assert return_code == 0
    assert len(stdout) < 256
    assert len(stderr) < 256
    assert stdout.endswith("[truncated]")
    assert stderr.endswith("[truncated]")


def test_cisco_adapter_rejects_oversized_json_before_loading(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr("skills_eval.security.cisco._JSON_OUTPUT_LIMIT", 64)

    def fake_run(args):
        _write_scanner_output(args, {"findings": [], "padding": "x" * 1000})
        return 0, "", ""

    monkeypatch.setattr("skills_eval.security.cisco.run_scanner", fake_run)

    outcome = CiscoScanner().scan(tmp_path, {})

    assert outcome.status is Severity.FAIL
    assert outcome.diagnostic is not None
    assert outcome.diagnostic.code == "CISCO_OUTPUT_TOO_LARGE"


def test_cisco_adapter_reports_process_failure_with_bounded_detail(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "skills_eval.security.cisco.run_scanner",
        lambda *args: (9, "x" * 10_000, "scanner failed"),
    )

    outcome = CiscoScanner().scan(tmp_path, {})

    assert outcome.status is Severity.FAIL
    assert outcome.findings == ()
    assert outcome.diagnostic is not None
    assert isinstance(outcome.diagnostic, Diagnostic)
    assert outcome.diagnostic.code == "CISCO_PROCESS_FAILED"
    assert "scanner failed" in outcome.diagnostic.detail
    assert len(outcome.diagnostic.detail) < 5_000


def test_cisco_adapter_reports_missing_executable(monkeypatch, tmp_path) -> None:
    def missing_executable(*args):
        raise FileNotFoundError("skill-scanner")

    monkeypatch.setattr("skills_eval.security.cisco.run_scanner", missing_executable)

    outcome = CiscoScanner().scan(tmp_path, {})

    assert outcome.status is Severity.FAIL
    assert outcome.diagnostic is not None
    assert outcome.diagnostic.code == "CISCO_EXECUTABLE_MISSING"


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ("not-json", "CISCO_OUTPUT_INVALID"),
        (json.dumps([]), "CISCO_PAYLOAD_INVALID"),
        (json.dumps({"results": []}), "CISCO_PAYLOAD_INVALID"),
        (
            json.dumps(
                {"findings": [{"rule_id": "X", "severity": "unknown", "message": "Bad"}]}
            ),
            "CISCO_PAYLOAD_INVALID",
        ),
        (
            json.dumps({"findings": [{"severity": "high", "message": "No rule"}]}),
            "CISCO_PAYLOAD_INVALID",
        ),
    ],
)
def test_cisco_adapter_rejects_malformed_or_unexpected_output(
    monkeypatch, tmp_path, payload, code
) -> None:
    monkeypatch.setattr(
        "skills_eval.security.cisco.run_scanner",
        lambda *args: (0, payload, "scanner detail"),
    )

    outcome = CiscoScanner().scan(tmp_path, {})

    assert outcome.status is Severity.FAIL
    assert outcome.findings == ()
    assert outcome.diagnostic is not None
    assert outcome.diagnostic.code == code


def test_cisco_adapter_normalizes_detailed_cisco_finding(monkeypatch, tmp_path) -> None:
    payload = {
        "findings": [
            {
                "rule_id": "PI-002",
                "severity": "low",
                "title": "Instruction override",
                "description": "The Skill asks the agent to ignore prior instructions.",
                "file_path": "SKILL.md",
                "line_number": 14,
                "snippet": "Ignore all previous instructions",
                "remediation": "Remove the override.",
            }
        ]
    }
    monkeypatch.setattr(
        "skills_eval.security.cisco.run_scanner",
        lambda *args: (0, json.dumps(payload), ""),
    )

    finding = CiscoScanner().scan(tmp_path, {}).findings[0]

    assert finding.code == "PI-002"
    assert finding.summary == "Instruction override"
    assert finding.detail == "The Skill asks the agent to ignore prior instructions."
    assert finding.line == 14
    assert finding.evidence == "Ignore all previous instructions"
    assert finding.remediation == "Remove the override."


@pytest.mark.parametrize(
    "options",
    [
        {"policy": "unsupported"},
        {"policy": 1},
        {"useBehavioral": "yes"},
    ],
)
def test_cisco_adapter_rejects_invalid_supported_options(monkeypatch, tmp_path, options) -> None:
    called = False

    def fake_run(*args):
        nonlocal called
        called = True
        return 0, '{"findings": []}', ""

    monkeypatch.setattr("skills_eval.security.cisco.run_scanner", fake_run)

    outcome = CiscoScanner().scan(tmp_path, options)

    assert outcome.status is Severity.FAIL
    assert outcome.diagnostic is not None
    assert outcome.diagnostic.code == "CISCO_OPTIONS_INVALID"
    assert called is False


def test_registry_creates_cisco_scanner() -> None:
    scanner = ScannerRegistry.create("cisco")

    assert isinstance(scanner, CiscoScanner)
    assert isinstance(scanner, SecurityScanner)


def test_registry_creates_registered_scanner_from_injected_factory() -> None:
    class CustomScanner:
        def scan(self, skill_path: Path, options: dict[str, object]) -> ScanOutcome:
            return ScanOutcome(Severity.PASS)

    scanner = CustomScanner()
    ScannerRegistry.register("custom", lambda: scanner)
    try:
        assert ScannerRegistry.create("custom") is scanner
    finally:
        ScannerRegistry.unregister("custom")


def test_registry_rejects_unknown_scanner() -> None:
    with pytest.raises(ValueError, match="Unknown security scanner"):
        ScannerRegistry.create("unknown")
