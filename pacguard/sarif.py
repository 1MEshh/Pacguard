"""
OASIS SARIF v2.1.0 JSON exporter and terminal risk scorecard generator.

Transforms Pacguard security findings, version diffs, and systemd exposure audits
into compliant SARIF v2.1.0 documents for DevSecOps CI/CD pipelines, and produces
high-contrast ANSI terminal security scorecards.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

from pacguard.pkgbuild_diff import DiffFinding
from pacguard.shell_heuristics import Finding, Severity
from pacguard.systemd_scorer import UnitAuditResult


class SarifExporter:
    """Exports Pacguard security findings to OASIS SARIF v2.1.0 JSON standard."""

    SCHEMA_URI = (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    )
    SARIF_VERSION = "2.1.0"
    TOOL_NAME = "Pacguard"
    TOOL_VERSION = "1.0.0"
    TOOL_URI = "https://github.com/1MEshh/Pacguard"

    @classmethod
    def export(
        cls,
        findings: Optional[List[Finding]] = None,
        diff_findings: Optional[List[DiffFinding]] = None,
        systemd_results: Optional[List[UnitAuditResult]] = None,
        indent: int = 2,
    ) -> str:
        """Convert findings into a complete SARIF v2.1.0 JSON string."""
        findings = findings or []
        diff_findings = diff_findings or []
        systemd_results = systemd_results or []

        rules_dict: Dict[str, Dict[str, Any]] = {}
        results_list: List[Dict[str, Any]] = []

        # 1. Process PKGBUILD heuristic findings
        for f in findings:
            if f.rule_id not in rules_dict:
                rules_dict[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {"level": f.severity.sarif_level},
                    "properties": {
                        "mitreTechnique": f.mitre_technique,
                        "securitySeverity": str(f.severity.rank * 2.0),
                    },
                }

            file_uri = f.file_path if not os.path.isabs(f.file_path) else os.path.basename(f.file_path)
            results_list.append(
                {
                    "ruleId": f.rule_id,
                    "level": f.severity.sarif_level,
                    "message": {
                        "text": f"{f.title}: {f.description} (Snippet: {f.snippet})"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": file_uri,
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": f.line_number,
                                    "startColumn": 1,
                                    "snippet": {"text": f.snippet},
                                },
                            }
                        }
                    ],
                    "properties": {
                        "mitreTechnique": f.mitre_technique,
                        "severity": f.severity.value,
                        "function": f.function_name or "global",
                    },
                }
            )

        # 2. Process Diff findings
        for df in diff_findings:
            if df.rule_id not in rules_dict:
                rules_dict[df.rule_id] = {
                    "id": df.rule_id,
                    "name": df.title,
                    "shortDescription": {"text": df.title},
                    "fullDescription": {"text": df.description},
                    "defaultConfiguration": {"level": df.severity.sarif_level},
                    "properties": {
                        "mitreTechnique": "T1195.002",
                        "securitySeverity": str(df.severity.rank * 2.0),
                    },
                }

            file_uri = df.file_path if not os.path.isabs(df.file_path) else os.path.basename(df.file_path)
            results_list.append(
                {
                    "ruleId": df.rule_id,
                    "level": df.severity.sarif_level,
                    "message": {
                        "text": f"{df.title}: {df.description} [Old: '{df.old_value}' -> New: '{df.new_value}']"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": file_uri,
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": 1,
                                    "startColumn": 1,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "severity": df.severity.value,
                        "oldValue": df.old_value,
                        "newValue": df.new_value,
                    },
                }
            )

        # 3. Process systemd unit audit results (if exposed or medium)
        for res in systemd_results:
            rule_id = "SD_EXPOSURE_RISK"
            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": "systemd Service Exposure Vulnerability",
                    "shortDescription": {"text": "systemd unit lacks sandbox capabilities or namespace isolation"},
                    "fullDescription": {"text": "Audits 24 systemd security directives modeled after systemd-analyze security."},
                    "defaultConfiguration": {"level": "error" if res.exposure_score > 6.6 else "warning"},
                    "properties": {
                        "mitreTechnique": "T1543.002",
                        "securitySeverity": str(round(res.exposure_score, 1)),
                    },
                }

            if res.exposure_score > 3.3:
                file_uri = res.unit_name
                results_list.append(
                    {
                        "ruleId": rule_id,
                        "level": "error" if res.exposure_score > 6.6 else "warning",
                        "message": {
                            "text": (
                                f"systemd unit '{res.unit_name}' evaluated to Exposure Score {res.exposure_score}/10.0 ({res.rating}). "
                                f"{res.hardened_count}/{res.total_directives} directives hardened."
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": file_uri,
                                        "uriBaseId": "%SRCROOT%",
                                    },
                                    "region": {"startLine": 1, "startColumn": 1},
                                }
                            }
                        ],
                        "properties": {
                            "exposureScore": res.exposure_score,
                            "rating": res.rating,
                        },
                    }
                )

        sarif_doc = {
            "$schema": cls.SCHEMA_URI,
            "version": cls.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": cls.TOOL_NAME,
                            "version": cls.TOOL_VERSION,
                            "informationUri": cls.TOOL_URI,
                            "rules": list(rules_dict.values()),
                        }
                    },
                    "results": results_list,
                }
            ],
        }

        return json.dumps(sarif_doc, indent=indent)


class ScorecardRenderer:
    """Renders high-contrast, terminal-friendly security scorecards and tables."""

    def __init__(self, no_color: bool = False) -> None:
        self.no_color = no_color or (not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"))

    def _c(self, text: str, code: str) -> str:
        if self.no_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def red(self, text: str) -> str:
        return self._c(text, "1;31")

    def green(self, text: str) -> str:
        return self._c(text, "1;32")

    def yellow(self, text: str) -> str:
        return self._c(text, "1;33")

    def cyan(self, text: str) -> str:
        return self._c(text, "1;36")

    def bold(self, text: str) -> str:
        return self._c(text, "1")

    def dim(self, text: str) -> str:
        return self._c(text, "2")

    def render_pkgbuild_scorecard(self, target: str, findings: List[Finding]) -> str:
        """Render PKGBUILD static audit findings summary."""
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)

        lines: List[str] = []
        lines.append(self.cyan("=" * 80))
        lines.append(self.bold(f" PACGUARD SECURITY SCORECARD :: {target}"))
        lines.append(self.cyan("=" * 80))
        lines.append(
            f" Findings Summary: "
            f"{self.red(f'{crit} CRITICAL')} | "
            f"{self.yellow(f'{high} HIGH')} | "
            f"{self.cyan(f'{med} MEDIUM')} | "
            f"{self.dim(f'{low} LOW')}"
        )
        lines.append(self.dim("-" * 80))

        if not findings:
            lines.append(self.green(" [PASS] No malicious heuristics or supply chain anomalies detected."))
            lines.append(self.cyan("=" * 80))
            return "\n".join(lines)

        lines.append(f" {'LINE':<6} {'SEVERITY':<10} {'RULE ID':<30} {'TITLE'}")
        lines.append(self.dim("-" * 80))

        for f in findings:
            sev_str = f.severity.value
            if f.severity == Severity.CRITICAL:
                sev_fmt = self.red(f"{sev_str:<10}")
            elif f.severity == Severity.HIGH:
                sev_fmt = self.yellow(f"{sev_str:<10}")
            elif f.severity == Severity.MEDIUM:
                sev_fmt = self.cyan(f"{sev_str:<10}")
            else:
                sev_fmt = self.dim(f"{sev_str:<10}")

            lines.append(f" {f.line_number:<6} {sev_fmt} {f.rule_id:<30} {f.title}")
            lines.append(f"        {self.dim('MITRE:')} {f.mitre_technique} | {self.dim('Snippet:')} {f.snippet[:56]}")

        lines.append(self.cyan("=" * 80))
        return "\n".join(lines)

    def render_diff_scorecard(self, v1_name: str, v2_name: str, findings: List[DiffFinding]) -> str:
        """Render version-to-version differential comparison table."""
        lines: List[str] = []
        lines.append(self.cyan("=" * 80))
        lines.append(self.bold(f" PACGUARD VERSION-DIFF AUDIT :: {v1_name} -> {v2_name}"))
        lines.append(self.cyan("=" * 80))

        if not findings:
            lines.append(self.green(" [PASS] No regression anomalies or source hijacks detected between versions."))
            lines.append(self.cyan("=" * 80))
            return "\n".join(lines)

        lines.append(f" {'SEVERITY':<10} {'RULE ID':<30} {'ANOMALY TITLE'}")
        lines.append(self.dim("-" * 80))

        for df in findings:
            sev_str = df.severity.value
            if df.severity == Severity.CRITICAL:
                sev_fmt = self.red(f"{sev_str:<10}")
            elif df.severity == Severity.HIGH:
                sev_fmt = self.yellow(f"{sev_str:<10}")
            else:
                sev_fmt = self.cyan(f"{sev_str:<10}")

            lines.append(f" {sev_fmt} {df.rule_id:<30} {df.title}")
            lines.append(f"        {self.dim('Old:')} {df.old_value[:65]}")
            lines.append(f"        {self.dim('New:')} {df.new_value[:65]}")

        lines.append(self.cyan("=" * 80))
        return "\n".join(lines)

    def render_systemd_scorecard(self, result: UnitAuditResult) -> str:
        """Render systemd security exposure rating and 24-directive scorecard."""
        lines: List[str] = []
        lines.append(self.cyan("=" * 80))
        lines.append(self.bold(f" SYSTEMD SECURITY AUDIT :: {result.unit_name}"))
        lines.append(self.cyan("=" * 80))

        # Color rating and exposure progress bar
        score_val = result.exposure_score
        bar_len = 20
        filled = int((score_val / 10.0) * bar_len)
        bar = "[" + "=" * filled + " " * (bar_len - filled) + "]"

        if result.rating == "SAFE":
            rating_fmt = self.green(f"{result.rating} ({score_val}/10.0)")
            bar_fmt = self.green(bar)
        elif result.rating == "MEDIUM":
            rating_fmt = self.yellow(f"{result.rating} ({score_val}/10.0)")
            bar_fmt = self.yellow(bar)
        else:
            rating_fmt = self.red(f"{result.rating} ({score_val}/10.0)")
            bar_fmt = self.red(bar)

        lines.append(f" Exposure Score: {bar_fmt} {rating_fmt}")
        lines.append(f" Hardened Directives: {result.hardened_count}/{result.total_directives}")
        lines.append(self.dim("-" * 80))
        lines.append(f" {'STATUS':<8} {'DIRECTIVE':<26} {'CURRENT VALUE':<24} {'WEIGHT'}")
        lines.append(self.dim("-" * 80))

        for d in result.assessments:
            if d.is_hardened:
                st = self.green("[SAFE]  ")
            elif d.exposure_factor <= 0.5:
                st = self.yellow("[PART]  ")
            else:
                st = self.red("[UNSET] ")

            val_trunc = (d.current_value or "[Unset]")[:24]
            lines.append(f" {st} {d.directive:<26} {val_trunc:<24} {d.weight}")

        lines.append(self.cyan("=" * 80))
        return "\n".join(lines)
