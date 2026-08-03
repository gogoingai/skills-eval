from __future__ import annotations

from pathlib import Path

import pytest

from skills_eval.models import Severity, Skill
from skills_eval.security.base import (
    FindingLevel,
    ScanOutcome,
    ScanStatus,
    SecurityFinding,
)
from skills_eval.security.summary import (
    effective_status,
    overall_status,
    run_security_scan,
    worst_status,
)


def _finding(level: FindingLevel, *, code: str = "X") -> SecurityFinding:
    return SecurityFinding(
        severity=Severity.REVIEW,
        code=code,
        message=code,
        source="test",
        rule_id=code,
        level=level,
    )


def _skill(tmp_path, name="write") -> Skill:
    path = tmp_path / name
    path.mkdir(parents=True, exist_ok=True)
    return Skill(name=name, path=path)


class MockProvider:
    def __init__(self, name, *, available=True, outcome=None, outcomes=None, raise_on_scan=False):
        self.name = name
        self._available = available
        self._outcome = outcome
        self._outcomes = outcomes or {}
        self._raise = raise_on_scan

    def is_available(self) -> bool:
        return self._available

    def get_version(self) -> str | None:
        return "1.0"

    def normalize_result(self, raw_result: object) -> tuple:
        return ()

    def scan(self, skill_path: Path, options: dict) -> ScanOutcome:
        if self._raise:
            raise RuntimeError("boom")
        if self._outcome is not None:
            return self._outcome
        return self._outcomes.get(skill_path.name, ScanOutcome(status=ScanStatus.PASS))


def _patch_provider(monkeypatch, name, provider):
    monkeypatch.setattr(
        "skills_eval.security.summary.ScannerRegistry.create",
        lambda n: provider if n == name else (_ for _ in ()).throw(ValueError(n)),
    )


# --- pure function tests -----------------------------------------------------


def test_effective_status_passes_error_and_skipped_unchanged() -> None:
    for status in (ScanStatus.ERROR, ScanStatus.SKIPPED):
        outcome = ScanOutcome(status=status)
        assert effective_status(outcome, "high") is status


def test_effective_status_blocks_at_failon_threshold() -> None:
    high = ScanOutcome(status=ScanStatus.PASS, findings=(_finding(FindingLevel.HIGH),))
    medium = ScanOutcome(status=ScanStatus.PASS, findings=(_finding(FindingLevel.MEDIUM),))

    assert effective_status(high, "high") is ScanStatus.FAIL
    assert effective_status(medium, "high") is ScanStatus.WARN
    assert effective_status(medium, "medium") is ScanStatus.FAIL
    assert effective_status(high, "critical") is ScanStatus.WARN


def test_effective_status_warns_on_below_threshold_findings() -> None:
    outcome = ScanOutcome(status=ScanStatus.PASS, findings=(_finding(FindingLevel.LOW),))
    assert effective_status(outcome, "high") is ScanStatus.WARN


def test_worst_status_orders_by_severity() -> None:
    assert worst_status([ScanStatus.PASS, ScanStatus.WARN]) is ScanStatus.WARN
    assert worst_status([ScanStatus.SKIPPED, ScanStatus.FAIL]) is ScanStatus.FAIL
    assert worst_status([]) is ScanStatus.PASS


def test_overall_status_required_error_is_error() -> None:
    from skills_eval.security.base import ProviderResult

    results = (
        ProviderResult(provider="cisco", status=ScanStatus.ERROR, required=True),
        ProviderResult(provider="skillspector", status=ScanStatus.PASS, required=False),
    )
    assert overall_status(results) is ScanStatus.ERROR


def test_overall_status_fail_then_warn_then_pass() -> None:
    from skills_eval.security.base import ProviderResult

    assert overall_status([ProviderResult(provider="x", status=ScanStatus.FAIL)]) is ScanStatus.FAIL
    assert overall_status([ProviderResult(provider="x", status=ScanStatus.WARN)]) is ScanStatus.WARN
    assert overall_status([ProviderResult(provider="x", status=ScanStatus.PASS)]) is ScanStatus.PASS


def test_overall_status_optional_error_does_not_override_pass() -> None:
    from skills_eval.security.base import ProviderResult

    results = (
        ProviderResult(provider="cisco", status=ScanStatus.PASS, required=True),
        ProviderResult(provider="snyk", status=ScanStatus.ERROR, required=False),
    )
    assert overall_status(results) is ScanStatus.PASS


# --- run_security_scan integration tests -------------------------------------


def test_dry_run_returns_empty_report(monkeypatch, tmp_path) -> None:
    called = False

    def fail_if_called(name):
        nonlocal called
        called = True
        raise AssertionError("must not create scanners in dry run")

    monkeypatch.setattr("skills_eval.security.summary.ScannerRegistry.create", fail_if_called)

    report = run_security_scan([_skill(tmp_path)], ({"name": "cisco", "enabled": True},), "high", dry_run=True)

    assert called is False
    assert report.provider_results == ()
    assert report.overall is ScanStatus.PASS
    assert report.execution_error is False


def test_passing_provider_yields_pass(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    _patch_provider(monkeypatch, "mock", MockProvider("mock", outcome=ScanOutcome(status=ScanStatus.PASS)))

    report = run_security_scan([skill], ({"name": "mock", "enabled": True},), "high")

    assert report.overall is ScanStatus.PASS
    assert report.provider_results[0].status is ScanStatus.PASS
    assert report.per_skill[skill.path].security_status is Severity.PASS


def test_high_finding_is_fail(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    outcome = ScanOutcome(status=ScanStatus.FAIL, findings=(_finding(FindingLevel.HIGH, code="H"),))
    _patch_provider(monkeypatch, "mock", MockProvider("mock", outcome=outcome))

    report = run_security_scan([skill], ({"name": "mock", "enabled": True},), "high")

    assert report.overall is ScanStatus.FAIL
    assert report.per_skill[skill.path].security_status is Severity.FAIL
    assert report.provider_results[0].finding_count == 1


def test_medium_finding_is_warn(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    outcome = ScanOutcome(status=ScanStatus.WARN, findings=(_finding(FindingLevel.MEDIUM, code="M"),))
    _patch_provider(monkeypatch, "mock", MockProvider("mock", outcome=outcome))

    report = run_security_scan([skill], ({"name": "mock", "enabled": True},), "high")

    assert report.overall is ScanStatus.WARN
    assert report.per_skill[skill.path].security_status is Severity.REVIEW


def test_suppressed_rule_id_does_not_fail(monkeypatch, tmp_path) -> None:
    """A high finding whose rule_id is suppressed must not cause FAIL."""
    skill = _skill(tmp_path)
    outcome = ScanOutcome(
        status=ScanStatus.FAIL,
        findings=(_finding(FindingLevel.HIGH, code="YR4"),),
    )
    _patch_provider(monkeypatch, "mock", MockProvider("mock", outcome=outcome))

    source = {
        "name": "mock",
        "enabled": True,
        "suppress": [{"ruleId": "YR4", "reason": "false positive on frontmatter"}],
    }
    report = run_security_scan([skill], (source,), "high")

    # suppressed -> no active findings -> PASS, not FAIL
    assert report.overall is ScanStatus.PASS
    provider = report.provider_results[0]
    assert provider.finding_count == 0
    assert provider.suppressed_count == 1
    assert provider.findings == ()
    assert provider.suppressed[0].rule_id == "YR4"
    assert report.per_skill[skill.path].security_status is Severity.PASS


def test_suppress_isolates_only_named_rule(monkeypatch, tmp_path) -> None:
    """Suppressing one rule leaves other high findings blocking."""
    skill = _skill(tmp_path)
    outcome = ScanOutcome(
        status=ScanStatus.FAIL,
        findings=(
            _finding(FindingLevel.HIGH, code="YR4"),
            _finding(FindingLevel.HIGH, code="REAL"),
        ),
    )
    _patch_provider(monkeypatch, "mock", MockProvider("mock", outcome=outcome))

    source = {"name": "mock", "enabled": True, "suppress": ["YR4"]}
    report = run_security_scan([skill], (source,), "high")

    assert report.overall is ScanStatus.FAIL
    provider = report.provider_results[0]
    assert provider.finding_count == 1
    assert provider.suppressed_count == 1
    assert provider.findings[0].rule_id == "REAL"


def test_effective_status_ignores_suppressed_findings() -> None:
    outcome = ScanOutcome(
        status=ScanStatus.FAIL,
        findings=(_finding(FindingLevel.HIGH, code="YR4"),),
    )
    assert effective_status(outcome, "high", suppressed_rule_ids=frozenset({"YR4"})) is ScanStatus.PASS
    assert effective_status(outcome, "high", suppressed_rule_ids=frozenset()) is ScanStatus.FAIL


def test_required_provider_not_available_is_error(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    _patch_provider(monkeypatch, "mock", MockProvider("mock", available=False))

    report = run_security_scan([skill], ({"name": "mock", "enabled": True, "required": True},), "high")

    assert report.overall is ScanStatus.ERROR
    assert report.execution_error is True
    assert len(report.execution_diagnostics) == 1
    assert report.per_skill[skill.path].security_status is Severity.FAIL


def test_optional_provider_not_available_is_skipped(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    _patch_provider(monkeypatch, "mock", MockProvider("mock", available=False))

    report = run_security_scan([skill], ({"name": "mock", "enabled": True, "required": False},), "high")

    assert report.overall is ScanStatus.PASS
    assert report.execution_error is False
    assert report.provider_results[0].status is ScanStatus.SKIPPED
    assert report.per_skill[skill.path].security_status is Severity.PASS


def test_required_provider_missing_credentials_is_error(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    _patch_provider(
        monkeypatch,
        "mock",
        MockProvider("mock", outcome=ScanOutcome(status=ScanStatus.SKIPPED, skip_reason="missing creds")),
    )

    report = run_security_scan([skill], ({"name": "mock", "enabled": True, "required": True},), "high")

    assert report.overall is ScanStatus.ERROR
    assert report.execution_error is True
    assert report.execution_diagnostics[0].code == "SECURITY_PROVIDER_ERROR"


def test_optional_provider_missing_credentials_is_skipped(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    _patch_provider(
        monkeypatch,
        "mock",
        MockProvider("mock", outcome=ScanOutcome(status=ScanStatus.SKIPPED, skip_reason="missing creds")),
    )

    report = run_security_scan([skill], ({"name": "mock", "enabled": True, "required": False},), "high")

    assert report.overall is ScanStatus.PASS
    assert report.provider_results[0].status is ScanStatus.SKIPPED


def test_optional_provider_scan_error_does_not_fail_overall(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    providers = {
        "ok": MockProvider("ok", outcome=ScanOutcome(status=ScanStatus.PASS)),
        "flaky": MockProvider(
            "flaky",
            outcome=ScanOutcome(
                status=ScanStatus.ERROR,
                error="timeout",
                diagnostic=__import__(
                    "skills_eval.security.base", fromlist=["ExecutionDiagnostic"]
                ).ExecutionDiagnostic(
                    severity=Severity.FAIL, code="FLAKY", message="timeout"
                ),
            ),
        ),
    }
    monkeypatch.setattr(
        "skills_eval.security.summary.ScannerRegistry.create",
        lambda n: providers[n],
    )

    report = run_security_scan(
        [skill],
        (
            {"name": "ok", "enabled": True, "required": True},
            {"name": "flaky", "enabled": True, "required": False},
        ),
        "high",
    )

    assert report.overall is ScanStatus.PASS
    assert report.execution_error is False
    flaky = next(r for r in report.provider_results if r.provider == "flaky")
    assert flaky.status is ScanStatus.ERROR
    # Optional error produces no per-skill execution diagnostic.
    assert report.per_skill[skill.path].diagnostics == ()


def test_required_provider_scan_error_adds_per_skill_diagnostic(monkeypatch, tmp_path) -> None:
    from skills_eval.security.base import ExecutionDiagnostic

    skill = _skill(tmp_path)
    _patch_provider(
        monkeypatch,
        "mock",
        MockProvider(
            "mock",
            outcome=ScanOutcome(
                status=ScanStatus.ERROR,
                diagnostic=ExecutionDiagnostic(severity=Severity.FAIL, code="BOOM", message="failed"),
            ),
        ),
    )

    report = run_security_scan([skill], ({"name": "mock", "enabled": True, "required": True},), "high")

    assert report.overall is ScanStatus.ERROR
    assert report.per_skill[skill.path].diagnostics[0].code == "BOOM"


def test_provider_exception_is_isolated(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    providers = {
        "raise": MockProvider("raise", raise_on_scan=True),
        "ok": MockProvider("ok", outcome=ScanOutcome(status=ScanStatus.PASS)),
    }
    monkeypatch.setattr(
        "skills_eval.security.summary.ScannerRegistry.create",
        lambda n: providers[n],
    )

    report = run_security_scan(
        [skill],
        (
            {"name": "raise", "enabled": True, "required": True},
            {"name": "ok", "enabled": True, "required": False},
        ),
        "high",
    )

    # The raising required provider becomes ERROR; the ok provider still ran.
    statuses = {r.provider: r.status for r in report.provider_results}
    assert statuses["raise"] is ScanStatus.ERROR
    assert statuses["ok"] is ScanStatus.PASS


def test_failon_medium_promotes_medium_to_fail(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    outcome = ScanOutcome(status=ScanStatus.WARN, findings=(_finding(FindingLevel.MEDIUM, code="M"),))
    _patch_provider(monkeypatch, "mock", MockProvider("mock", outcome=outcome))

    report = run_security_scan([skill], ({"name": "mock", "enabled": True},), "medium")

    assert report.overall is ScanStatus.FAIL
    assert report.provider_results[0].status is ScanStatus.FAIL


def test_multiple_providers_worst_takes_precedence(monkeypatch, tmp_path) -> None:
    skill = _skill(tmp_path)
    providers = {
        "a": MockProvider("a", outcome=ScanOutcome(status=ScanStatus.WARN, findings=(_finding(FindingLevel.MEDIUM, code="A"),))),
        "b": MockProvider("b", outcome=ScanOutcome(status=ScanStatus.FAIL, findings=(_finding(FindingLevel.HIGH, code="B"),))),
    }
    monkeypatch.setattr("skills_eval.security.summary.ScannerRegistry.create", lambda n: providers[n])

    report = run_security_scan(
        [skill],
        ({"name": "a", "enabled": True}, {"name": "b", "enabled": True}),
        "high",
    )

    assert report.overall is ScanStatus.FAIL
    assert report.per_skill[skill.path].security_status is Severity.FAIL
