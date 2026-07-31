"""Shared contracts and normalized results for external security scanners."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from skills_eval.models import Diagnostic, Finding, Severity


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

    @property
    def summary(self) -> str:
        """Return the shared finding summary."""
        return self.message


@dataclass(frozen=True)
class ExecutionDiagnostic(Diagnostic):
    """A bounded diagnostic produced when a scanner cannot return valid results."""

    detail: str = ""


@dataclass(frozen=True)
class ScanOutcome:
    """Normalized findings and status from one scanner invocation."""

    status: Severity
    findings: tuple[SecurityFinding, ...] = ()
    diagnostic: ExecutionDiagnostic | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))

    @property
    def execution_diagnostic(self) -> ExecutionDiagnostic | None:
        """Expose the diagnostic under an explicit compatibility name."""
        return self.diagnostic


@runtime_checkable
class SecurityScanner(Protocol):
    """Contract implemented by every external security scanner adapter."""

    def scan(self, skill_path: Path, options: dict[str, object]) -> ScanOutcome:
        """Scan one Skill directory and return normalized results."""


class ScannerRegistry:
    """Create supported scanner adapters by their configuration name."""

    @staticmethod
    def create(name: str) -> SecurityScanner:
        if name == "cisco":
            from skills_eval.security.cisco import CiscoScanner

            return CiscoScanner()
        raise ValueError(f"Unknown security scanner: {name!r}")
