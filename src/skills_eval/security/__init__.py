"""Extensible security scanner adapters."""

from skills_eval.security.base import (
    ExecutionDiagnostic,
    FindingLevel,
    ProviderResult,
    ScannerRegistry,
    ScanOutcome,
    ScanStatus,
    SecurityFinding,
    SecurityProvider,
    SecurityScanner,
    level_to_severity,
    scan_status_to_severity,
)
from skills_eval.security.cisco import CiscoScanner
from skills_eval.security.skillspector import SkillSpectorScanner
from skills_eval.security.snyk import SnykScanner
from skills_eval.security.tencent_aig import TencentAigScanner

ScannerRegistry.register("cisco", CiscoScanner, replace=True)
ScannerRegistry.register("skillspector", SkillSpectorScanner, replace=True)
ScannerRegistry.register("tencent-aig", TencentAigScanner, replace=True)
ScannerRegistry.register("snyk", SnykScanner, replace=True)

__all__ = [
    "CiscoScanner",
    "ExecutionDiagnostic",
    "FindingLevel",
    "ProviderResult",
    "ScanOutcome",
    "ScanStatus",
    "ScannerRegistry",
    "SecurityFinding",
    "SecurityProvider",
    "SecurityScanner",
    "SkillSpectorScanner",
    "SnykScanner",
    "TencentAigScanner",
    "level_to_severity",
    "scan_status_to_severity",
]
