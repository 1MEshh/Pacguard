"""
PKGBUILD version-to-version diffing and supply chain anomaly detector.

Analyzes delta between two PKGBUILD versions (e.g. v1 upstream vs v2 AUR update)
to detect domain hijacks, URL typosquatting, checksum downgrades to SKIP,
malicious dependency poisoning, and stealth lifecycle hook injections.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from pacguard.pkgbuild_parser import PKGBUILDData
from pacguard.shell_heuristics import Severity


@dataclass
class DiffFinding:
    """Represents a delta-based anomaly detected between two PKGBUILD revisions."""
    rule_id: str
    severity: Severity
    title: str
    description: str
    old_value: str
    new_value: str
    file_path: str


class PKGBUILDDiffer:
    """Compares two PKGBUILD instances to identify security-relevant regressions."""

    def __init__(self, v1: PKGBUILDData, v2: PKGBUILDData) -> None:
        self.v1 = v1
        self.v2 = v2
        self.findings: List[DiffFinding] = []

    def compare(self) -> List[DiffFinding]:
        """Perform comprehensive differential security analysis."""
        self.findings = []
        target_path = self.v2.file_path or "PKGBUILD (v2)"

        self._check_url_and_source_hijacks(target_path)
        self._check_checksum_downgrades(target_path)
        self._check_dependency_injections(target_path)
        self._check_lifecycle_hook_changes(target_path)
        self._check_install_script_changes(target_path)

        return self.findings

    def _check_url_and_source_hijacks(self, file_path: str) -> None:
        """Detect remote source domain swaps or project website redirection."""
        # 1. Project URL comparison
        if self.v1.url and self.v2.url and self.v1.url != self.v2.url:
            self.findings.append(
                DiffFinding(
                    rule_id="PG_DIFF_PROJECT_URL_CHANGED",
                    severity=Severity.HIGH,
                    title="Upstream Project URL Redirected",
                    description=(
                        f"PKGBUILD upstream project URL changed from '{self.v1.url}' to '{self.v2.url}'. "
                        "Verify whether this reflects an official domain migration or an attacker redirect."
                    ),
                    old_value=self.v1.url,
                    new_value=self.v2.url,
                    file_path=file_path,
                )
            )

        # 2. Source URLs comparison
        v1_sources = {s.filename or s.url: s for s in self.v1.source}
        v2_sources = {s.filename or s.url: s for s in self.v2.source}

        for idx, s2 in enumerate(self.v2.source):
            if idx < len(self.v1.source):
                s1 = self.v1.source[idx]
                # Compare domains
                if s1.is_remote and s2.is_remote:
                    if s1.domain and s2.domain and s1.domain != s2.domain:
                        self.findings.append(
                            DiffFinding(
                                rule_id="PG_DIFF_URL_HIJACK",
                                severity=Severity.CRITICAL,
                                title="Source Download Domain Swapped / Hijacked",
                                description=(
                                    f"Source download domain for entry #{idx + 1} changed from '{s1.domain}' "
                                    f"to '{s2.domain}'. This strongly indicates upstream source hijack or typosquatting."
                                ),
                                old_value=s1.url,
                                new_value=s2.url,
                                file_path=file_path,
                            )
                        )
            else:
                # Completely new remote source added in v2
                if s2.is_remote:
                    self.findings.append(
                        DiffFinding(
                            rule_id="PG_DIFF_NEW_REMOTE_SOURCE",
                            severity=Severity.HIGH,
                            title="New Remote Download Source Added",
                            description=(
                                f"PKGBUILD v2 introduces a new remote source entry: '{s2.url}'."
                            ),
                            old_value="",
                            new_value=s2.raw,
                            file_path=file_path,
                        )
                    )

    def _check_checksum_downgrades(self, file_path: str) -> None:
        """Detect checksum downgrade attacks (e.g. valid sha256 replaced with SKIP)."""
        for sum_type in ("sha256sums", "sha512sums", "b2sums"):
            v1_sums = self.v1.checksums.get(sum_type, [])
            v2_sums = self.v2.checksums.get(sum_type, [])

            for idx, sum_val_2 in enumerate(v2_sums):
                val2_clean = sum_val_2.strip().upper()
                if val2_clean in ("SKIP", "'SKIP'", '"SKIP"', "NONE"):
                    # Check what v1 had at this index
                    if idx < len(v1_sums):
                        val1_clean = v1_sums[idx].strip().upper()
                        if val1_clean not in ("SKIP", "'SKIP'", '"SKIP"', "NONE", ""):
                            self.findings.append(
                                DiffFinding(
                                    rule_id="PG_DIFF_CHECKSUM_DOWNGRADE",
                                    severity=Severity.CRITICAL,
                                    title="Checksum Verification Downgraded to SKIP",
                                    description=(
                                        f"In {sum_type}, entry #{idx + 1} was previously protected with a cryptographic "
                                        f"hash ('{val1_clean[:16]}...'), but was downgraded to 'SKIP' in the new revision. "
                                        "This completely disables archive integrity verification."
                                    ),
                                    old_value=val1_clean,
                                    new_value=val2_clean,
                                    file_path=file_path,
                                )
                            )

    def _check_dependency_injections(self, file_path: str) -> None:
        """Detect newly added runtime or build-time dependencies."""
        v1_deps = set(self.v1.depends)
        v2_deps = set(self.v2.depends)
        new_deps = v2_deps - v1_deps

        if new_deps:
            self.findings.append(
                DiffFinding(
                    rule_id="PG_DIFF_DEPENDS_INJECTION",
                    severity=Severity.HIGH,
                    title="New Runtime Dependencies Injected",
                    description=(
                        f"New runtime packages added to depends: {sorted(list(new_deps))}. "
                        "Validate that new dependencies are legitimate and not malicious lookalikes."
                    ),
                    old_value=", ".join(sorted(list(v1_deps))),
                    new_value=", ".join(sorted(list(v2_deps))),
                    file_path=file_path,
                )
            )

        v1_make = set(self.v1.makedepends)
        v2_make = set(self.v2.makedepends)
        new_make = v2_make - v1_make

        if new_make:
            self.findings.append(
                DiffFinding(
                    rule_id="PG_DIFF_MAKEDEPENDS_INJECTION",
                    severity=Severity.MEDIUM,
                    title="New Build-time Dependencies Injected",
                    description=(
                        f"New build packages added to makedepends: {sorted(list(new_make))}."
                    ),
                    old_value=", ".join(sorted(list(v1_make))),
                    new_value=", ".join(sorted(list(v2_make))),
                    file_path=file_path,
                )
            )

    def _check_lifecycle_hook_changes(self, file_path: str) -> None:
        """Detect injected lifecycle functions or significant code body expansions."""
        v1_funcs = set(self.v1.functions.keys())
        v2_funcs = set(self.v2.functions.keys())

        # Functions newly introduced
        injected_funcs = v2_funcs - v1_funcs
        for func_name in injected_funcs:
            f2 = self.v2.functions[func_name]
            self.findings.append(
                DiffFinding(
                    rule_id="PG_DIFF_HOOK_INJECTION",
                    severity=Severity.HIGH,
                    title=f"New Lifecycle Function Injected: '{func_name}'",
                    description=(
                        f"Function '{func_name}()' did not exist in the prior version. "
                        f"Inspect lines {f2.start_line}-{f2.end_line} to verify purpose."
                    ),
                    old_value="[None]",
                    new_value=f2.raw_code[:120] + ("..." if len(f2.raw_code) > 120 else ""),
                    file_path=file_path,
                )
            )

    def _check_install_script_changes(self, file_path: str) -> None:
        """Detect introduction of pacman .install script."""
        if not self.v1.install_script and self.v2.install_script:
            self.findings.append(
                DiffFinding(
                    rule_id="PG_DIFF_INSTALL_SCRIPT_ADDED",
                    severity=Severity.HIGH,
                    title="Pacman Install Script Attached",
                    description=(
                        f"The package previously had no install script, but now references '{self.v2.install_script}'. "
                        "Install scripts execute post-install hooks as root outside makepkg sandbox."
                    ),
                    old_value="None",
                    new_value=self.v2.install_script,
                    file_path=file_path,
                )
            )
