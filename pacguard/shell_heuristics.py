"""
Shell and PKGBUILD security heuristics engine.

Scans Arch Linux PKGBUILD recipes and pacman .install scripts for supply chain
attacks, dynamic linker tampering (LD_PRELOAD), credential harvesting (~/.ssh),
obfuscated payloads (base64 eval), checksum bypasses (SKIP), reverse shells,
and unauthorized persistence mechanisms.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from pacguard.pkgbuild_parser import PKGBUILDData, ShellFunction, SourceEntry


class Severity(enum.Enum):
    """Vulnerability severity levels matching CVSS and SARIF levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def sarif_level(self) -> str:
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks.get(self, 0)


@dataclass
class Finding:
    """Security finding detected during static heuristic analysis."""
    rule_id: str
    severity: Severity
    title: str
    description: str
    mitre_technique: str
    line_number: int
    file_path: str
    snippet: str
    function_name: Optional[str] = None


class ShellHeuristicsEngine:
    """Static heuristic analysis engine for shell commands and PKGBUILD structures."""

    # Heuristic regex patterns
    CURL_SH_PATTERN = re.compile(
        r"(?:curl|wget|fetch|lynx|links|nc|socat)\b[^|\n;]+(?:\||\|&)\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python\d?|perl|ruby)\b|"
        r"(?:eval|bash|sh|zsh)\s*<\s*\(\s*(?:curl|wget|fetch)\b|"
        r"(?:eval|source|\.)\s+[\"']?\$\(\s*(?:curl|wget|fetch)\b",
        re.IGNORECASE,
    )

    BASE64_EVAL_PATTERN = re.compile(
        r"(?:base64\s+(?:-d|--decode)|openssl\s+enc\s+-d|xxd\s+-r)\s*(?:\||\|&)\s*(?:sh|bash|zsh|dash|python\d?|perl|eval\b)|"
        r"(?:eval|exec)\s+[\"']?\$\([^)]*base64\s+(?:-d|--decode)[^)]*\)|"
        r"python\d?\s+-c\s+[\"'].*import\s+base64.*(?:exec|eval)\s*\(.*[\"']",
        re.IGNORECASE,
    )

    LD_PRELOAD_PATTERN = re.compile(
        r"(?:export\s+)?LD_PRELOAD\s*=|"
        r"/etc/ld\.so\.preload|"
        r"/etc/ld\.so\.conf(?:\.d)?",
        re.IGNORECASE,
    )

    SSH_KEY_PATTERN = re.compile(
        r"(?:~|\$HOME|/root)/\.ssh(?:/(?:id_[a-zA-Z0-9_-]+|authorized_keys|known_hosts))?|"
        r"\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)|"
        r"/etc/shadow|"
        r"(?:~|\$HOME)/\.aws/credentials|"
        r"(?:~|\$HOME)/\.gnupg",
        re.IGNORECASE,
    )

    PERSISTENCE_PATTERN = re.compile(
        r"/etc/cron\.(?:d|daily|hourly|monthly|weekly)/|"
        r"/var/spool/cron(?:/crontabs)?|"
        r"/etc/sudoers(?:\.d)?|"
        r"\.config/autostart|"
        r"/etc/systemd/system/(?!.*\.service\.d)",
        re.IGNORECASE,
    )

    REVERSE_SHELL_PATTERN = re.compile(
        r"/dev/(?:tcp|udp)/[a-zA-Z0-9_.-]+/\d+|"
        r"nc\s+(?:-[a-zA-Z]*e\s+|[a-zA-Z0-9_.-]+\s+\d+\s+-e)|"
        r"mkfifo\s+[^;]+;\s*(?:cat|nc|sh|bash)|"
        r"socket\.(?:AF_INET|SOCK_STREAM).*connect\(",
        re.IGNORECASE,
    )

    SUSPICIOUS_NETWORK_HOOK = re.compile(
        r"\b(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|rsync|ftp|tftp)\b",
        re.IGNORECASE,
    )

    ARCHIVE_EXTENSIONS = (
        ".tar.gz",
        ".tar.xz",
        ".tar.zst",
        ".tar.bz2",
        ".tgz",
        ".txz",
        ".zip",
        ".7z",
    )

    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def analyze(self, data: PKGBUILDData) -> List[Finding]:
        """Perform comprehensive heuristic inspection across PKGBUILD data."""
        self.findings = []
        file_path = data.file_path or "PKGBUILD"

        # 1. Inspect Source and Checksum integrity
        self._audit_sources_and_checksums(data, file_path)

        # 2. Inspect raw file line-by-line for global code / stray commands
        self._audit_raw_lines(data.raw_lines, file_path)

        # 3. Inspect PKGBUILD lifecycle functions
        for name, func in data.functions.items():
            self._audit_function(func, file_path, is_install_hook=False)

        # 4. Inspect pacman .install script hooks
        for name, func in data.install_functions.items():
            self._audit_function(func, file_path, is_install_hook=True)

        return self.findings

    def _audit_sources_and_checksums(self, data: PKGBUILDData, file_path: str) -> None:
        """Verify checksum algorithms, SKIP downgrades, and unencrypted protocols."""
        # Find primary checksum array
        checksum_list: List[str] = []
        chk_type = ""
        for name in ("sha256sums", "sha512sums", "b2sums", "sha384sums", "sha1sums", "md5sums"):
            if name in data.checksums:
                checksum_list = data.checksums[name]
                chk_type = name
                break

        # Check for weak or deprecated hash algorithms
        if ("md5sums" in data.checksums or "sha1sums" in data.checksums) and not (
            "sha256sums" in data.checksums or "sha512sums" in data.checksums or "b2sums" in data.checksums
        ):
            self.findings.append(
                Finding(
                    rule_id="PG010_DEPRECATED_HASH_ALGORITHM",
                    severity=Severity.LOW,
                    title="Deprecated Hash Algorithm",
                    description=(
                        "PKGBUILD relies exclusively on deprecated hash functions (MD5 or SHA1). "
                        "Modern Arch Linux security standards mandate SHA256, SHA512, or BLAKE2 (b2sums)."
                    ),
                    mitre_technique="T1195.002",
                    line_number=1,
                    file_path=file_path,
                    snippet=f"Checksum type: {chk_type}",
                )
            )

        for idx, src in enumerate(data.source):
            # Check for unencrypted HTTP / FTP
            if src.url.startswith("http://") or src.url.startswith("ftp://"):
                self.findings.append(
                    Finding(
                        rule_id="PG009_INSECURE_HTTP_FETCH",
                        severity=Severity.MEDIUM,
                        title="Insecure Plaintext Source Protocol",
                        description=(
                            f"Source URL '{src.url}' uses unencrypted HTTP/FTP, leaving downloads "
                            "vulnerable to man-in-the-middle (MITM) tampering and transit poisoning."
                        ),
                        mitre_technique="T1195.002",
                        line_number=1,
                        file_path=file_path,
                        snippet=src.raw,
                    )
                )

            # Check for SKIP on non-VCS tarball archives
            is_static_archive = any(src.filename.endswith(ext) or src.url.endswith(ext) for ext in self.ARCHIVE_EXTENSIONS)
            is_remote_http = src.url.startswith("https://") or src.url.startswith("http://")

            has_skip = False
            if idx < len(checksum_list):
                sum_val = checksum_list[idx].strip().upper()
                if sum_val in ("SKIP", "'SKIP'", '"SKIP"', "NONE"):
                    has_skip = True

            if has_skip:
                if not src.is_vcs and (is_static_archive or is_remote_http):
                    self.findings.append(
                        Finding(
                            rule_id="PG005_SKIP_CHECKSUM_NON_VCS",
                            severity=Severity.HIGH,
                            title="Checksum Integrity Verification Bypassed (SKIP)",
                            description=(
                                f"Source '{src.filename or src.url}' is a remote non-VCS archive or file, "
                                f"but its integrity verification is explicitly disabled with 'SKIP'. "
                                "This creates critical supply chain exposure to remote domain hijacking or poisoning."
                            ),
                            mitre_technique="T1195.002",
                            line_number=1,
                            file_path=file_path,
                            snippet=f"source: {src.raw} | {chk_type}: SKIP",
                        )
                    )

    def _audit_raw_lines(self, lines: List[str], file_path: str) -> None:
        """Scan top-level lines for dangerous global patterns."""
        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check LD_PRELOAD manipulation
            if self.LD_PRELOAD_PATTERN.search(stripped):
                self.findings.append(
                    Finding(
                        rule_id="PG003_LD_PRELOAD_TAMPERING",
                        severity=Severity.CRITICAL,
                        title="Dynamic Linker Preload Tampering",
                        description=(
                            "Detected explicit manipulation of LD_PRELOAD or /etc/ld.so.preload. "
                            "This technique is heavily utilized in userland rootkits and credential interception."
                        ),
                        mitre_technique="T1574.006",
                        line_number=line_no,
                        file_path=file_path,
                        snippet=stripped,
                    )
                )

            # Check SSH key or shadow harvesting
            if self.SSH_KEY_PATTERN.search(stripped):
                self.findings.append(
                    Finding(
                        rule_id="PG004_CREDENTIAL_EXFILTRATION",
                        severity=Severity.CRITICAL,
                        title="Sensitive Credential & SSH Key Access",
                        description=(
                            "Detected reference to private keys, ~/.ssh, /etc/shadow, or cloud credential stores. "
                            "Packaging recipes should never touch user or host credential directories."
                        ),
                        mitre_technique="T1552.004",
                        line_number=line_no,
                        file_path=file_path,
                        snippet=stripped,
                    )
                )

            # Check Reverse shell or raw socket
            if self.REVERSE_SHELL_PATTERN.search(stripped):
                self.findings.append(
                    Finding(
                        rule_id="PG008_REVERSE_SHELL_SOCKET",
                        severity=Severity.CRITICAL,
                        title="Interactive Reverse Shell or Direct Socket Callback",
                        description=(
                            "Detected direct socket callback (/dev/tcp, netcat reverse shell, or socket connect). "
                            "Indicates unauthorized command-and-control connection attempts."
                        ),
                        mitre_technique="T1059",
                        line_number=line_no,
                        file_path=file_path,
                        snippet=stripped,
                    )
                )

    def _audit_function(self, func: ShellFunction, file_path: str, is_install_hook: bool) -> None:
        """Scan lifecycle function body for malicious AST and command execution patterns."""
        body_lines = func.body.splitlines()

        for idx, line in enumerate(body_lines):
            line_no = func.start_line + idx
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check curl | sh / network interpreter pipes
            if self.CURL_SH_PATTERN.search(stripped):
                self.findings.append(
                    Finding(
                        rule_id="PG001_NETWORK_EXEC_PIPE",
                        severity=Severity.CRITICAL,
                        title="Remote Code Execution via Network Interpreter Pipe",
                        description=(
                            f"Detected piping of unverified remote network payload into an interpreter shell "
                            f"(curl|sh, wget|bash, or bash <(curl)) inside function '{func.name}'. "
                            "This pattern circumvents makepkg source integrity and executes untracked remote code."
                        ),
                        mitre_technique="T1059.004",
                        line_number=line_no,
                        file_path=file_path,
                        snippet=stripped,
                        function_name=func.name,
                    )
                )

            # Check base64 obfuscated payload eval
            if self.BASE64_EVAL_PATTERN.search(stripped):
                self.findings.append(
                    Finding(
                        rule_id="PG002_OBFUSCATED_PAYLOAD_EVAL",
                        severity=Severity.CRITICAL,
                        title="Obfuscated Payload Execution via Base64/Decoder",
                        description=(
                            f"Detected decode-and-execute pattern (base64 -d | sh, eval $(echo ... | base64)) "
                            f"inside function '{func.name}'. Indicates deliberate defense evasion and payload masking."
                        ),
                        mitre_technique="T1027",
                        line_number=line_no,
                        file_path=file_path,
                        snippet=stripped,
                        function_name=func.name,
                    )
                )

            # Check LD_PRELOAD in function
            if self.LD_PRELOAD_PATTERN.search(stripped):
                self.findings.append(
                    Finding(
                        rule_id="PG003_LD_PRELOAD_TAMPERING",
                        severity=Severity.CRITICAL,
                        title="Dynamic Linker Preload Tampering",
                        description=(
                            f"Detected LD_PRELOAD or /etc/ld.so.preload manipulation in function '{func.name}'."
                        ),
                        mitre_technique="T1574.006",
                        line_number=line_no,
                        file_path=file_path,
                        snippet=stripped,
                        function_name=func.name,
                    )
                )

            # Check SSH key access in function
            if self.SSH_KEY_PATTERN.search(stripped):
                self.findings.append(
                    Finding(
                        rule_id="PG004_CREDENTIAL_EXFILTRATION",
                        severity=Severity.CRITICAL,
                        title="Sensitive Credential & SSH Key Access",
                        description=(
                            f"Detected access to SSH keys, credentials, or sensitive host identity in '{func.name}'."
                        ),
                        mitre_technique="T1552.004",
                        line_number=line_no,
                        file_path=file_path,
                        snippet=stripped,
                        function_name=func.name,
                    )
                )

            # Check Persistence mechanism modification
            if self.PERSISTENCE_PATTERN.search(stripped):
                self.findings.append(
                    Finding(
                        rule_id="PG006_PERSISTENCE_TAMPERING",
                        severity=Severity.HIGH,
                        title="Persistence Mechanism Tampering",
                        description=(
                            f"Detected tampering with system persistence directories (/etc/cron*, /etc/sudoers, "
                            f"autostart) inside function '{func.name}'."
                        ),
                        mitre_technique="T1053.003",
                        line_number=line_no,
                        file_path=file_path,
                        snippet=stripped,
                        function_name=func.name,
                    )
                )

            # Check Reverse shell in function
            if self.REVERSE_SHELL_PATTERN.search(stripped):
                self.findings.append(
                    Finding(
                        rule_id="PG008_REVERSE_SHELL_SOCKET",
                        severity=Severity.CRITICAL,
                        title="Interactive Reverse Shell or Direct Socket Callback",
                        description=(
                            f"Detected direct socket callback or reverse shell construct inside '{func.name}'."
                        ),
                        mitre_technique="T1059",
                        line_number=line_no,
                        file_path=file_path,
                        snippet=stripped,
                        function_name=func.name,
                    )
                )

            # Install hook specific checks: pacman install hooks run as root on target machines!
            if is_install_hook:
                if self.SUSPICIOUS_NETWORK_HOOK.search(stripped):
                    self.findings.append(
                        Finding(
                            rule_id="PG007_INSTALL_HOOK_NETWORK_FETCH",
                            severity=Severity.CRITICAL,
                            title="Pacman Install Script Network Operation",
                            description=(
                                f"Arch Linux .install hook '{func.name}' attempts outbound network interaction "
                                f"({stripped.split()[0]}). Pacman install hooks run with root privileges during package "
                                "installation and should never make network calls."
                            ),
                            mitre_technique="T1546",
                            line_number=line_no,
                            file_path=file_path,
                            snippet=stripped,
                            function_name=func.name,
                        )
                    )
