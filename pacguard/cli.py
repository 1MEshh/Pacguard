"""
Pacguard Command-Line Interface.

Provides subcommands:
  - scan-pkgbuild: Analyzes PKGBUILD and .install files for malicious patterns.
  - diff-pkgbuild: Compares two revisions of a PKGBUILD to detect supply chain hijacks.
  - audit-systemd: Evaluates systemd service units against 24 security directives.
  - export-sarif: Generates OASIS SARIF v2.1.0 JSON reports for CI/CD pipelines.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from pacguard.pkgbuild_diff import PKGBUILDDiffer
from pacguard.pkgbuild_parser import PKGBUILDParser
from pacguard.sarif import SarifExporter, ScorecardRenderer
from pacguard.shell_heuristics import Finding, Severity, ShellHeuristicsEngine
from pacguard.systemd_scorer import SystemdScorer, UnitAuditResult


def _parse_severity(sev_str: str) -> Optional[Severity]:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(sev_str.lower())


def cmd_scan_pkgbuild(args: argparse.Namespace) -> int:
    """Execute scan-pkgbuild subcommand."""
    target_path = args.path
    if os.path.isdir(target_path):
        target_path = os.path.join(target_path, "PKGBUILD")

    if not os.path.isfile(target_path):
        sys.stderr.write(f"Error: Target PKGBUILD file not found: {target_path}\n")
        return 2

    parser = PKGBUILDParser.from_file(target_path)
    data = parser.parse()

    # Optional manual install script attachment
    if args.install_script and os.path.isfile(args.install_script):
        data.install_functions = PKGBUILDParser.parse_install_script_file(args.install_script)

    engine = ShellHeuristicsEngine()
    findings = engine.analyze(data)

    fail_severity = _parse_severity(args.fail_on) if args.fail_on else None
    has_failure = False
    if fail_severity:
        has_failure = any(f.severity.rank >= fail_severity.rank for f in findings)

    # Format output
    output_format = args.format.lower()
    if output_format == "sarif":
        sarif_json = SarifExporter.export(findings=findings)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(sarif_json)
        else:
            sys.stdout.write(sarif_json + "\n")
    elif output_format == "json":
        json_data = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "mitre_technique": f.mitre_technique,
                "line_number": f.line_number,
                "file_path": f.file_path,
                "snippet": f.snippet,
                "function_name": f.function_name,
            }
            for f in findings
        ]
        out_str = json.dumps(json_data, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(out_str)
        else:
            sys.stdout.write(out_str + "\n")
    else:
        renderer = ScorecardRenderer(no_color=args.no_color)
        card = renderer.render_pkgbuild_scorecard(target_path, findings)
        sys.stdout.write(card + "\n")

    return 1 if has_failure else 0


def cmd_diff_pkgbuild(args: argparse.Namespace) -> int:
    """Execute diff-pkgbuild subcommand."""
    v1_path = args.v1
    v2_path = args.v2

    if not os.path.isfile(v1_path):
        sys.stderr.write(f"Error: Version 1 PKGBUILD not found: {v1_path}\n")
        return 2
    if not os.path.isfile(v2_path):
        sys.stderr.write(f"Error: Version 2 PKGBUILD not found: {v2_path}\n")
        return 2

    p1 = PKGBUILDParser.from_file(v1_path).parse()
    p2 = PKGBUILDParser.from_file(v2_path).parse()

    differ = PKGBUILDDiffer(p1, p2)
    diff_findings = differ.compare()

    fail_severity = _parse_severity(args.fail_on) if args.fail_on else None
    has_failure = False
    if fail_severity:
        has_failure = any(df.severity.rank >= fail_severity.rank for df in diff_findings)

    output_format = args.format.lower()
    if output_format == "sarif":
        sarif_json = SarifExporter.export(diff_findings=diff_findings)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(sarif_json)
        else:
            sys.stdout.write(sarif_json + "\n")
    elif output_format == "json":
        json_data = [
            {
                "rule_id": df.rule_id,
                "severity": df.severity.value,
                "title": df.title,
                "description": df.description,
                "old_value": df.old_value,
                "new_value": df.new_value,
                "file_path": df.file_path,
            }
            for df in diff_findings
        ]
        out_str = json.dumps(json_data, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(out_str)
        else:
            sys.stdout.write(out_str + "\n")
    else:
        renderer = ScorecardRenderer(no_color=args.no_color)
        card = renderer.render_diff_scorecard(v1_path, v2_path, diff_findings)
        sys.stdout.write(card + "\n")

    return 1 if has_failure else 0


def cmd_audit_systemd(args: argparse.Namespace) -> int:
    """Execute audit-systemd subcommand."""
    path = args.path
    if not os.path.isfile(path):
        sys.stderr.write(f"Error: systemd service file not found: {path}\n")
        return 2

    result = SystemdScorer.audit_file(path)

    has_failure = False
    if args.fail_on_score is not None:
        if result.exposure_score > args.fail_on_score:
            has_failure = True

    output_format = args.format.lower()
    if output_format == "sarif":
        sarif_json = SarifExporter.export(systemd_results=[result])
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(sarif_json)
        else:
            sys.stdout.write(sarif_json + "\n")
    elif output_format == "json":
        json_data = {
            "unit_name": result.unit_name,
            "exposure_score": result.exposure_score,
            "rating": result.rating,
            "total_directives": result.total_directives,
            "hardened_count": result.hardened_count,
            "assessments": [
                {
                    "directive": a.directive,
                    "current_value": a.current_value,
                    "is_hardened": a.is_hardened,
                    "exposure_factor": a.exposure_factor,
                    "weight": a.weight,
                    "recommendation": a.recommendation,
                }
                for a in result.assessments
            ],
        }
        out_str = json.dumps(json_data, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(out_str)
        else:
            sys.stdout.write(out_str + "\n")
    else:
        renderer = ScorecardRenderer(no_color=args.no_color)
        card = renderer.render_systemd_scorecard(result)
        sys.stdout.write(card + "\n")

    return 1 if has_failure else 0


def cmd_export_sarif(args: argparse.Namespace) -> int:
    """Execute export-sarif subcommand."""
    findings: List[Finding] = []
    diff_findings: List[Any] = []
    systemd_results: List[UnitAuditResult] = []

    if args.pkgbuild:
        if os.path.isfile(args.pkgbuild):
            parser = PKGBUILDParser.from_file(args.pkgbuild)
            data = parser.parse()
            engine = ShellHeuristicsEngine()
            findings = engine.analyze(data)
        else:
            sys.stderr.write(f"Warning: PKGBUILD not found: {args.pkgbuild}\n")

    if args.systemd:
        if os.path.isfile(args.systemd):
            systemd_results.append(SystemdScorer.audit_file(args.systemd))
        else:
            sys.stderr.write(f"Warning: systemd unit not found: {args.systemd}\n")

    sarif_str = SarifExporter.export(
        findings=findings,
        diff_findings=diff_findings,
        systemd_results=systemd_results,
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            out.write(sarif_str)
        sys.stdout.write(f"Exported SARIF report to {args.output}\n")
    else:
        sys.stdout.write(sarif_str + "\n")

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI command and argument hierarchy."""
    parser = argparse.ArgumentParser(
        prog="pacguard",
        description="Arch Linux Security Auditor for PKGBUILDs and systemd Service Units.",
    )
    parser.add_argument("--version", action="version", version="Pacguard 1.0.0")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. scan-pkgbuild
    p_scan = subparsers.add_parser("scan-pkgbuild", help="Scan a PKGBUILD for malicious heuristics.")
    p_scan.add_argument("path", help="Path to PKGBUILD or directory containing PKGBUILD.")
    p_scan.add_argument("--install-script", help="Path to associated pacman .install script.")
    p_scan.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Report output format (default: table).",
    )
    p_scan.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit with non-zero code if findings equal or exceed severity.",
    )
    p_scan.add_argument("--output", "-o", help="File path to save output.")
    p_scan.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")

    # 2. diff-pkgbuild
    p_diff = subparsers.add_parser("diff-pkgbuild", help="Compare two PKGBUILDs to detect supply-chain anomalies.")
    p_diff.add_argument("v1", help="Path to baseline PKGBUILD (v1).")
    p_diff.add_argument("v2", help="Path to target PKGBUILD (v2).")
    p_diff.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Report output format (default: table).",
    )
    p_diff.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit with non-zero code if diff anomalies equal or exceed severity.",
    )
    p_diff.add_argument("--output", "-o", help="File path to save output.")
    p_diff.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")

    # 3. audit-systemd
    p_sys = subparsers.add_parser("audit-systemd", help="Audit systemd .service unit against 24 security directives.")
    p_sys.add_argument("path", help="Path to systemd .service unit file.")
    p_sys.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Report output format (default: table).",
    )
    p_sys.add_argument(
        "--fail-on-score",
        type=float,
        default=None,
        help="Exit with non-zero code if Exposure Score E exceeds threshold (0.0 - 10.0).",
    )
    p_sys.add_argument("--output", "-o", help="File path to save output.")
    p_sys.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")

    # 4. export-sarif
    p_sarif = subparsers.add_parser("export-sarif", help="Export findings to OASIS SARIF v2.1.0 JSON format.")
    p_sarif.add_argument("--pkgbuild", help="Path to PKGBUILD file to audit.")
    p_sarif.add_argument("--systemd", help="Path to systemd service unit to audit.")
    p_sarif.add_argument("--output", "-o", required=False, help="Target SARIF JSON file path.")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan-pkgbuild":
        return cmd_scan_pkgbuild(args)
    elif args.command == "diff-pkgbuild":
        return cmd_diff_pkgbuild(args)
    elif args.command == "audit-systemd":
        return cmd_audit_systemd(args)
    elif args.command == "export-sarif":
        return cmd_export_sarif(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
