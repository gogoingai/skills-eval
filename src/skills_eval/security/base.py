"""Shared contracts and normalized results for external security scanners."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Protocol, runtime_checkable

from skills_eval.models import Diagnostic, Finding, Severity


class ScanStatus(str, Enum):
    """Unified security-scan status for one provider invocation.

    ``PASS`` no findings reached the warning threshold.
    ``WARN`` findings exist but none reached the blocking threshold.
    ``FAIL`` blocking findings exist (at/above ``security.failOn``).
    ``ERROR`` the scanner failed to run, timed out, or produced unparseable output.
    ``SKIPPED`` the provider is disabled, not installed, or missing optional credentials.
    """

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


# Ordered low -> high so threshold comparisons use ``FindingLevel.rank``.
_LEVEL_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class FindingLevel(str, Enum):
    """Unified five-level finding severity, preserving original scanner levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def rank(cls, level: object) -> int:
        """Return the ordering rank of a level string (unknown levels rank lowest)."""
        text = level.value if isinstance(level, FindingLevel) else str(level)
        return _LEVEL_RANK.get(text.lower(), -1)


def level_to_severity(level: object) -> Severity:
    """Map a unified finding level to the coarse release-gate severity."""
    if FindingLevel.rank(level) >= FindingLevel.rank(FindingLevel.HIGH):
        return Severity.FAIL
    return Severity.REVIEW


def scan_status_to_severity(status: object) -> Severity:
    """Map a provider scan status to the coarse severity used by the release gate.

    ``SKIPPED`` and ``PASS`` do not block; ``WARN`` becomes ``REVIEW``; ``FAIL``
    and ``ERROR`` become ``FAIL`` (errors additionally surface as execution
    diagnostics so they drive the exit code).
    """
    if status in (ScanStatus.FAIL, ScanStatus.ERROR):
        return Severity.FAIL
    if status == ScanStatus.WARN:
        return Severity.REVIEW
    return Severity.PASS


@dataclass(frozen=True)
class SecurityFinding(Finding):
    """A scanner-independent security finding."""

    source: str = ""
    rule_id: str = ""
    line: int | None = None
    detail: str | None = None
    remediation: str | None = None
    evidence: str | None = None
    source_severity: str | None = None
    level: FindingLevel = FindingLevel.INFO
    title: str | None = None
    raw: Mapping[str, object] | None = None

    @property
    def provider(self) -> str:
        """Provider name that produced this finding (alias for :attr:`source`)."""
        return self.source

    @property
    def summary(self) -> str:
        """Return the shared finding summary."""
        return self.message


@dataclass(frozen=True)
class ExecutionDiagnostic(Diagnostic):
    """A bounded diagnostic produced when a scanner cannot return valid results."""

    detail: str = ""

    @property
    def is_execution_error(self) -> bool:
        return True


@dataclass(frozen=True)
class ScanOutcome:
    """Normalized findings and status from one scanner invocation."""

    status: ScanStatus
    findings: tuple[SecurityFinding, ...] = ()
    diagnostic: ExecutionDiagnostic | None = None
    duration_ms: int | None = None
    version: str | None = None
    raw_result: Any = None
    skip_reason: str | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))

    @property
    def execution_diagnostic(self) -> ExecutionDiagnostic | None:
        """Expose the diagnostic under an explicit compatibility name."""
        return self.diagnostic


@dataclass(frozen=True)
class ProviderResult:
    """Aggregate outcome for one provider, used by reports and JSON output."""

    provider: str
    status: ScanStatus
    enabled: bool = True
    available: bool = True
    required: bool = False
    version: str | None = None
    duration_ms: int | None = None
    findings: tuple[SecurityFinding, ...] = ()
    suppressed: tuple[SecurityFinding, ...] = ()
    error: str | None = None
    skip_reason: str | None = None
    raw_result: Any = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "suppressed", tuple(self.suppressed))

    @property
    def finding_count(self) -> int:
        """Number of active (non-suppressed) findings this provider produced."""
        return len(self.findings)

    @property
    def suppressed_count(self) -> int:
        """Number of findings suppressed by configured ``suppress`` rules."""
        return len(self.suppressed)


@runtime_checkable
class SecurityProvider(Protocol):
    """Contract implemented by every external security scanner adapter."""

    name: str

    def is_available(self) -> bool:
        """Return whether the scanner CLI/package can be invoked."""

    def get_version(self) -> str | None:
        """Return the scanner version, cached after the first call."""

    def scan(self, skill_path: Path, options: dict[str, object]) -> ScanOutcome:
        """Scan one Skill directory and return normalized results."""

    def normalize_result(self, raw_result: object) -> tuple[SecurityFinding, ...]:
        """Normalize a scanner's raw result into security findings."""


# Backwards-compatible alias for the scanner contract.
SecurityScanner = SecurityProvider


class ScannerRegistry:
    """Create supported scanner adapters by their configuration name."""

    _factories: ClassVar[dict[str, Callable[[], SecurityProvider]]] = {}

    @classmethod
    def register(
        cls,
        name: str,
        factory: Callable[[], SecurityProvider],
        *,
        replace: bool = False,
    ) -> None:
        """Register a scanner factory without changing registry dispatch code."""
        if not name:
            raise ValueError("Security scanner name must not be empty.")
        if name in cls._factories and not replace:
            raise ValueError(f"Security scanner is already registered: {name!r}")
        cls._factories[name] = factory

    @classmethod
    def unregister(cls, name: str) -> None:
        """Remove a scanner registration."""
        cls._factories.pop(name, None)

    @classmethod
    def create(cls, name: str) -> SecurityProvider:
        try:
            factory = cls._factories[name]
        except KeyError:
            raise ValueError(f"Unknown security scanner: {name!r}") from None
        scanner = factory()
        if not isinstance(scanner, SecurityProvider):
            raise TypeError(f"Security scanner factory returned an invalid adapter: {name!r}")
        return scanner
