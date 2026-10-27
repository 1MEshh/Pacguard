"""
Pacguard: Arch Linux Security Auditor for PKGBUILDs and systemd Service Units.

Provides AST and token-based heuristics for Arch User Repository (AUR) packages,
version-diff hijack detection, and weighted systemd security exposure scoring.
"""

from pacguard.pkgbuild_parser import PKGBUILDParser, PKGBUILDData, SourceEntry, ShellFunction
from pacguard.shell_heuristics import ShellHeuristicsEngine, Finding, Severity
from pacguard.pkgbuild_diff import PKGBUILDDiffer, DiffFinding
from pacguard.systemd_scorer import SystemdScorer, UnitAuditResult, DirectiveAssessment
from pacguard.sarif import SarifExporter, ScorecardRenderer

__version__ = "1.0.0"
__all__ = [
    "PKGBUILDParser",
    "PKGBUILDData",
    "SourceEntry",
    "ShellFunction",
    "ShellHeuristicsEngine",
    "Finding",
    "Severity",
    "PKGBUILDDiffer",
    "DiffFinding",
    "SystemdScorer",
    "UnitAuditResult",
    "DirectiveAssessment",
    "SarifExporter",
    "ScorecardRenderer",
]
