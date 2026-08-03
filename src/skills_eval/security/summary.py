"""Unified multi-provider security scan orchestration and summary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skills_eval.models import Severity, Skill, highest_status
from skills_eval.security.base import (
    ExecutionDiagnostic,
    FindingLevel,
    ProviderResult,
    ScannerRegistry,
    ScanOutcome,
    ScanStatus,
    SecurityFinding,
    scan_status_to_severity,
)

# Providers that block the release by default when they cannot run.
_DEFAULT_REQUIRED = {"cisco": True}
_STATUS_RANK = {
    ScanStatus.SKIPPED: 0,
    ScanStatus.PASS: 1,
    ScanStatus.WARN: 2,
    ScanStatus.FAIL: 3,
    ScanStatus.ERROR: 4,
}


@dataclass(frozen=True)
class SkillSecurityResult:
    """Per-skill security outcome across all providers."""

    security_status: Severity
    findings: tuple[SecurityFinding, ...] = ()
    diagnostics: tuple[ExecutionDiagnostic, ...] = ()
    provider_results: tuple[ProviderResult, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "provider_results", tuple(self.provider_results))


@dataclass(frozen=True)
class SecurityScanReport:
    """Aggregate security report across providers and skills."""

    provider_results: tuple[ProviderResult, ...] = ()
    per_skill: Mapping[Path, SkillSecurityResult] = field(default_factory=dict)
    overall: ScanStatus = ScanStatus.PASS
    overall_severity: Severity = Severity.PASS
    execution_error: bool = False
    execution_diagnostics: tuple[ExecutionDiagnostic, ...] = ()
    fail_on: str = "high"

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_results", tuple(self.provider_results))
        object.__setattr__(self, "execution_diagnostics", tuple(self.execution_diagnostics))


def run_security_scan(
    skills: list[Skill],
    enabled_sources: tuple[Mapping[str, object], ...],
    fail_on: str,
    *,
    dry_run: bool = False,
) -> SecurityScanReport:
    """Run every enabled provider across every skill and summarize."""
    if dry_run:
        return SecurityScanReport(fail_on=fail_on)

    fail_on_rank = FindingLevel.rank(fail_on)
    per_skill: dict[Path, list[tuple[ProviderResult, ExecutionDiagnostic | None]]] = {
        skill.path: [] for skill in skills
    }
    provider_aggregates: list[ProviderResult] = []
    execution_diagnostics: list[ExecutionDiagnostic] = []

    for source in enabled_sources:
        name = _source_name(source)
        required = _source_required(source, name)
        options = _source_options(source)
        suppressed_ids = _source_suppress(source)
        source_fail_on = _source_fail_on(source, fail_on)
        source_fail_on_rank = (
            fail_on_rank
            if source_fail_on == fail_on
            else FindingLevel.rank(source_fail_on)
        )

        provider, create_error = _create_provider(name)
        if create_error is not None:
            reason = f"scanner {name!r} could not be created: {create_error}"
            status = ScanStatus.ERROR if required else ScanStatus.SKIPPED
            provider_aggregates.append(
                ProviderResult(
                    provider=name,
                    status=status,
                    enabled=True,
                    available=False,
                    required=required,
                    error=reason if status is ScanStatus.ERROR else None,
                    skip_reason=reason if status is ScanStatus.SKIPPED else None,
                )
            )
            if required:
                execution_diagnostics.append(_global_error(name, reason))
                for skill in skills:
                    per_skill[skill.path].append(
                        (ProviderResult(provider=name, status=ScanStatus.ERROR, required=True, available=False), None)
                    )
            else:
                for skill in skills:
                    per_skill[skill.path].append(
                        (ProviderResult(provider=name, status=ScanStatus.SKIPPED, required=False, available=False, skip_reason=reason), None)
                    )
            continue

        available = provider.is_available()
        version = _safe_version(provider)
        if not available:
            reason = f"scanner {name!r} is not installed or not on PATH"
            status = ScanStatus.ERROR if required else ScanStatus.SKIPPED
            provider_aggregates.append(
                ProviderResult(
                    provider=name,
                    status=status,
                    enabled=True,
                    available=False,
                    required=required,
                    version=version,
                    error=reason if status is ScanStatus.ERROR else None,
                    skip_reason=reason if status is ScanStatus.SKIPPED else None,
                )
            )
            if required:
                execution_diagnostics.append(_global_error(name, reason))
                for skill in skills:
                    per_skill[skill.path].append(
                        (ProviderResult(provider=name, status=ScanStatus.ERROR, required=True, available=False, version=version), None)
                    )
            else:
                for skill in skills:
                    per_skill[skill.path].append(
                        (ProviderResult(provider=name, status=ScanStatus.SKIPPED, required=False, available=False, version=version, skip_reason=reason), None)
                    )
            continue

        skill_outcomes: list[tuple[Skill, ScanOutcome]] = []
        for skill in skills:
            skill_outcomes.append((skill, _safe_scan(provider, skill.path, options, name)))

        all_skipped = all(outcome.status is ScanStatus.SKIPPED for _, outcome in skill_outcomes)
        creds_missing_required = all_skipped and required
        if creds_missing_required:
            execution_diagnostics.append(_global_error(name, "missing credentials"))
            agg_status = ScanStatus.ERROR
        else:
            agg_status = worst_status(
                effective_status(outcome, source_fail_on_rank, suppressed_rule_ids=suppressed_ids)
                for _, outcome in skill_outcomes
            )

        all_findings: list[SecurityFinding] = []
        all_suppressed: list[SecurityFinding] = []
        total_duration = 0
        error_text: str | None = None
        skip_reason: str | None = None
        for skill, outcome in skill_outcomes:
            active_findings, suppressed_findings = _split_findings(outcome.findings, suppressed_ids)
            # When a per-source failOn demotes findings (e.g. failOn:"critical"
            # on a "high" finding), demote the individual severity from FAIL
            # to REVIEW so the overall CheckResult.severity is correct.
            active_findings = _demote_findings(active_findings, source_fail_on_rank)
            eff = ScanStatus.ERROR if creds_missing_required else effective_status(
                outcome, source_fail_on_rank, suppressed_rule_ids=suppressed_ids
            )
            per_skill[skill.path].append(
                (
                    ProviderResult(
                        provider=name,
                        status=eff,
                        enabled=True,
                        available=True,
                        required=required,
                        version=version,
                        duration_ms=outcome.duration_ms,
                        findings=active_findings,
                        suppressed=suppressed_findings,
                        error=outcome.error if eff is ScanStatus.ERROR else None,
                        skip_reason=outcome.skip_reason if eff is ScanStatus.SKIPPED else None,
                    ),
                    outcome.diagnostic,
                )
            )
            all_findings.extend(active_findings)
            all_suppressed.extend(suppressed_findings)
            total_duration += outcome.duration_ms or 0
            if eff is ScanStatus.ERROR and error_text is None:
                error_text = outcome.error or (
                    outcome.diagnostic.message if outcome.diagnostic else "scan failed"
                )
            if outcome.status is ScanStatus.SKIPPED and skip_reason is None:
                skip_reason = outcome.skip_reason
        if creds_missing_required:
            skip_reason = "missing credentials"
        provider_aggregates.append(
            ProviderResult(
                provider=name,
                status=agg_status,
                enabled=True,
                available=True,
                required=required,
                version=version,
                duration_ms=total_duration or None,
                findings=tuple(all_findings),
                suppressed=tuple(all_suppressed),
                error=error_text if agg_status is ScanStatus.ERROR else None,
                skip_reason=skip_reason if agg_status is ScanStatus.SKIPPED else None,
            )
        )

    per_skill_results: dict[Path, SkillSecurityResult] = {}
    for skill in skills:
        entries = per_skill[skill.path]
        contributions: list[Severity] = []
        diagnostics: list[ExecutionDiagnostic] = []
        findings: list[SecurityFinding] = []
        results: list[ProviderResult] = []
        for provider_result, diagnostic in entries:
            results.append(provider_result)
            findings.extend(provider_result.findings)
            status = provider_result.status
            if status is ScanStatus.FAIL:
                contributions.append(Severity.FAIL)
            elif status is ScanStatus.WARN:
                contributions.append(Severity.REVIEW)
            elif status is ScanStatus.PASS:
                contributions.append(Severity.PASS)
            elif status is ScanStatus.ERROR and provider_result.required:
                contributions.append(Severity.FAIL)
                if diagnostic is not None:
                    diagnostics.append(diagnostic)
            # SKIPPED and optional ERROR contribute nothing.
        security_status = highest_status(contributions) if contributions else Severity.PASS
        per_skill_results[skill.path] = SkillSecurityResult(
            security_status=security_status,
            findings=tuple(findings),
            diagnostics=tuple(diagnostics),
            provider_results=tuple(results),
        )

    execution_error = any(
        result.required and result.status is ScanStatus.ERROR for result in provider_aggregates
    )
    overall = overall_status(provider_aggregates)
    return SecurityScanReport(
        provider_results=tuple(provider_aggregates),
        per_skill=per_skill_results,
        overall=overall,
        overall_severity=scan_status_to_severity(overall),
        execution_error=execution_error,
        execution_diagnostics=tuple(execution_diagnostics),
        fail_on=fail_on,
    )


def effective_status(
    outcome: ScanOutcome,
    fail_on: str | int,
    *,
    suppressed_rule_ids: frozenset[str] = frozenset(),
) -> ScanStatus:
    """Re-derive PASS/WARN/FAIL from an outcome's findings and the failOn threshold.

    ``ERROR`` and ``SKIPPED`` outcomes are returned unchanged; finding-based
    outcomes honor the configured ``failOn`` threshold so a provider's status
    stays consistent regardless of the default threshold it was built with.
    Findings whose ``rule_id`` is in *suppressed_rule_ids* are ignored - a
    suppressed finding never causes FAIL/WARN on its own.
    """
    if outcome.status in (ScanStatus.ERROR, ScanStatus.SKIPPED):
        return outcome.status
    threshold = fail_on if isinstance(fail_on, int) else FindingLevel.rank(fail_on)
    active = [
        finding
        for finding in outcome.findings
        if not (finding.rule_id and finding.rule_id in suppressed_rule_ids)
    ]
    if any(FindingLevel.rank(finding.level) >= threshold for finding in active):
        return ScanStatus.FAIL
    if active:
        return ScanStatus.WARN
    return ScanStatus.PASS


def worst_status(statuses: Any) -> ScanStatus:
    """Return the most severe status among *statuses*."""
    return max(statuses, key=lambda status: _STATUS_RANK.get(status, 0), default=ScanStatus.PASS)


def overall_status(provider_results: Any) -> ScanStatus:
    """Compute the overall security status from per-provider aggregate results.

    A required provider ``ERROR`` makes the overall ``ERROR``. Otherwise the
    worst of ``FAIL``/``WARN``/``PASS`` wins. Optional provider errors are shown
    but do not override valid results.
    """
    results = list(provider_results)
    if any(result.required and result.status is ScanStatus.ERROR for result in results):
        return ScanStatus.ERROR
    if any(result.status is ScanStatus.FAIL for result in results):
        return ScanStatus.FAIL
    if any(result.status is ScanStatus.WARN for result in results):
        return ScanStatus.WARN
    return ScanStatus.PASS


def _create_provider(name: str) -> tuple[Any, str | None]:
    try:
        return ScannerRegistry.create(name), None
    except Exception as error:  # noqa: BLE001 - surface any creation failure as a diagnostic
        return None, str(error)


def _safe_scan(provider: Any, skill_path: Path, options: dict[str, object], name: str) -> ScanOutcome:
    try:
        return provider.scan(skill_path, options)
    except Exception as error:  # noqa: BLE001 - isolate one provider's failure from the rest
        return ScanOutcome(
            status=ScanStatus.ERROR,
            diagnostic=ExecutionDiagnostic(
                severity=Severity.FAIL,
                code="SCANNER_EXECUTION_ERROR",
                message=f"Security scanner {name!r} failed: {error}",
            ),
            error=str(error),
        )


def _safe_version(provider: Any) -> str | None:
    try:
        return provider.get_version()
    except Exception:  # noqa: BLE001
        return None


def _global_error(name: str, reason: str) -> ExecutionDiagnostic:
    return ExecutionDiagnostic(
        severity=Severity.FAIL,
        code="SECURITY_PROVIDER_ERROR",
        message=f"Required security provider {name!r} could not complete: {reason}",
    )


def _source_name(source: Mapping[str, object]) -> str:
    name = source.get("name")
    assert isinstance(name, str)
    return name


def _source_required(source: Mapping[str, object], name: str) -> bool:
    value = source.get("required")
    return bool(value) if isinstance(value, bool) else _DEFAULT_REQUIRED.get(name, False)


_KNOWN_FAIL_ON = frozenset({"info", "low", "medium", "high", "critical"})


def _source_fail_on(source: Mapping[str, object], global_fail_on: str) -> str:
    """Return the effective ``failOn`` threshold for a source.

    When a source declares ``failOn`` it overrides the global threshold, e.g.
    ``"failOn": "critical"`` means only critical findings from that provider
    cause a FAIL (useful for non-deterministic LLM scanners).
    """
    value = source.get("failOn")
    if isinstance(value, str) and value in _KNOWN_FAIL_ON:
        return value
    return global_fail_on


def _source_options(source: Mapping[str, object]) -> dict[str, object]:
    options = source.get("options", {})
    assert isinstance(options, Mapping)
    return dict(options)


def _source_suppress(source: Mapping[str, object]) -> frozenset[str]:
    """Return the set of suppressed rule IDs declared for a source.

    Each entry of the ``suppress`` array may be a plain string rule ID or an
    object ``{"ruleId": "...", "reason": "..."}``; only the rule ID is used
    here (the reason is preserved for the report via the raw config).
    """
    raw = source.get("suppress", ())
    if not isinstance(raw, (list, tuple)):
        return frozenset()
    ids: list[str] = []
    for entry in raw:
        if isinstance(entry, str):
            ids.append(entry)
        elif isinstance(entry, Mapping):
            rule_id = entry.get("ruleId")
            if isinstance(rule_id, str):
                ids.append(rule_id)
    return frozenset(ids)


def _split_findings(
    findings: tuple[SecurityFinding, ...],
    suppressed_ids: frozenset[str],
) -> tuple[tuple[SecurityFinding, ...], tuple[SecurityFinding, ...]]:
    """Partition findings into (active, suppressed) by rule ID."""
    if not suppressed_ids:
        return findings, ()
    active: list[SecurityFinding] = []
    suppressed: list[SecurityFinding] = []
    for finding in findings:
        if finding.rule_id and finding.rule_id in suppressed_ids:
            suppressed.append(finding)
        else:
            active.append(finding)
    return tuple(active), tuple(suppressed)


def _demote_findings(
    findings: tuple[SecurityFinding, ...],
    fail_on_rank: int,
) -> tuple[SecurityFinding, ...]:
    """Demote individual finding severities that are below *fail_on_rank*.

    When a per-source failOn threshold is higher (stricter) than the global
    default, a finding that was originally ``FAIL`` at its raw level should
    be demoted to ``REVIEW`` so it doesn't cause ``NOT_READY`` through the
    per-item severity aggregation.
    """
    from dataclasses import replace

    from skills_eval.models import Severity

    adjusted: list[SecurityFinding] = []
    for finding in findings:
        if (
            finding.severity is Severity.FAIL
            and FindingLevel.rank(finding.level) < fail_on_rank
        ):
            adjusted.append(replace(finding, severity=Severity.REVIEW))
        else:
            adjusted.append(finding)
    return tuple(adjusted)
