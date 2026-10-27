"""
systemd service unit security capability & namespace hardening scorer.

Audits systemd .service files against 24 core sandboxing and capability directives,
computing a normalized weighted Exposure Score E in [0.0, 10.0] modeled after
the systemd-analyze security specification.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


@dataclass
class DirectiveAssessment:
    """Security assessment for a single systemd directive."""
    directive: str
    current_value: Optional[str]
    is_hardened: bool
    exposure_factor: float  # 0.0 (safe) to 1.0 (exposed)
    weight: float
    description: str
    recommendation: str


@dataclass
class UnitAuditResult:
    """Consolidated security audit score and directive evaluation for a systemd unit."""
    unit_name: str
    file_path: Optional[str]
    exposure_score: float  # 0.0 (hardened) to 10.0 (exposed)
    rating: str  # SAFE, MEDIUM, EXPOSED
    total_directives: int
    hardened_count: int
    assessments: List[DirectiveAssessment] = field(default_factory=list)
    service_properties: Dict[str, str] = field(default_factory=dict)


class SystemdScorer:
    """Evaluates systemd unit hardening parameters and computes weighted exposure."""

    # Directive rule definition:
    # (Directive, Weight, Assessment Function, Description, Recommendation)
    def __init__(self) -> None:
        pass

    @classmethod
    def audit_file(cls, path: str) -> UnitAuditResult:
        """Parse and score a systemd service file from disk."""
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
        unit_name = os.path.basename(path)
        result = cls.audit_content(content, unit_name=unit_name)
        result.file_path = path
        return result

    @classmethod
    def audit_content(cls, content: str, unit_name: str = "custom.service") -> UnitAuditResult:
        """Parse systemd unit file content and evaluate all 24 directives."""
        properties = cls._parse_systemd_properties(content)
        assessments: List[DirectiveAssessment] = []

        # 24 Security Directives with systemd-analyze security weights
        rules: List[Tuple[str, float, Callable[[Dict[str, str]], Tuple[bool, float, str]], str, str]] = [
            (
                "User",
                0.8,
                cls._eval_user,
                "Service executes with root or dedicated unprivileged user.",
                "Set User= to an unprivileged dedicated service account or enable DynamicUser=yes.",
            ),
            (
                "DynamicUser",
                0.6,
                cls._eval_dynamic_user,
                "Allocates transient dynamic UID/GID from systemd range.",
                "Set DynamicUser=yes to isolate runtime identity without persistent UID allocation.",
            ),
            (
                "ProtectSystem",
                0.7,
                cls._eval_protect_system,
                "Mounts /usr, /boot, and /etc read-only.",
                "Set ProtectSystem=strict to make the entire OS root directory tree read-only.",
            ),
            (
                "ProtectHome",
                0.7,
                cls._eval_protect_home,
                "Hides or mounts /home, /root, and /run/user read-only.",
                "Set ProtectHome=yes or ProtectHome=strict to completely sandbox user home paths.",
            ),
            (
                "NoNewPrivileges",
                0.6,
                cls._eval_no_new_privileges,
                "Prevents execution of setuid/setgid binaries from elevating privileges.",
                "Set NoNewPrivileges=yes to enforce PR_SET_NO_NEW_PRIVS.",
            ),
            (
                "CapabilityBoundingSet",
                0.6,
                cls._eval_capability_bounding_set,
                "Restricts process Linux kernel capability bounding set.",
                "Set CapabilityBoundingSet= (empty) or retain only required minimal capabilities.",
            ),
            (
                "AmbientCapabilities",
                0.4,
                cls._eval_ambient_capabilities,
                "Ambient capabilities inherited across execve().",
                "Keep AmbientCapabilities= empty or unset to prevent capability inheritance.",
            ),
            (
                "MemoryDenyWriteExecute",
                0.6,
                cls._eval_memory_deny_write_execute,
                "Prohibits memory mappings that are simultaneously writable and executable (W^X).",
                "Set MemoryDenyWriteExecute=yes to block shellcode staging and JIT attacks.",
            ),
            (
                "PrivateTmp",
                0.5,
                cls._eval_private_tmp,
                "Provides isolated, per-service /tmp and /var/tmp namespace.",
                "Set PrivateTmp=yes to prevent cross-process tempfile sniffing and symlink races.",
            ),
            (
                "PrivateDevices",
                0.5,
                cls._eval_private_devices,
                "Hides raw disk partitions and physical hardware devices.",
                "Set PrivateDevices=yes to restrict access to pseudo-devices (/dev/null, /dev/urandom).",
            ),
            (
                "PrivateNetwork",
                0.5,
                cls._eval_private_network,
                "Disconnects network stack by providing private loopback namespace.",
                "Set PrivateNetwork=yes for units that do not require external network sockets.",
            ),
            (
                "ProtectKernelTunables",
                0.5,
                cls._eval_protect_kernel_tunables,
                "Mounts /proc/sys, /sys, /proc/sysrq-trigger read-only.",
                "Set ProtectKernelTunables=yes to prevent runtime kernel parameter manipulation.",
            ),
            (
                "ProtectKernelModules",
                0.5,
                cls._eval_protect_kernel_modules,
                "Prohibits explicit loading or unloading of Linux kernel modules.",
                "Set ProtectKernelModules=yes to block rootkit kernel module insertions.",
            ),
            (
                "ProtectKernelLogs",
                0.4,
                cls._eval_protect_kernel_logs,
                "Prevents read or write access to the kernel log ring buffer (dmesg).",
                "Set ProtectKernelLogs=yes to prevent kernel pointer leaks via dmesg.",
            ),
            (
                "ProtectControlGroups",
                0.5,
                cls._eval_protect_control_groups,
                "Mounts Linux cgroup hierarchy (/sys/fs/cgroup) read-only.",
                "Set ProtectControlGroups=yes to prevent cgroup escape and hierarchy restructuring.",
            ),
            (
                "ProtectClock",
                0.4,
                cls._eval_protect_clock,
                "Prohibits changes to system hardware clock and RTC settings.",
                "Set ProtectClock=yes to restrict clock-altering syscalls.",
            ),
            (
                "ProtectHostname",
                0.4,
                cls._eval_protect_hostname,
                "Isolates UTS namespace to prevent hostname or NIS domain alterations.",
                "Set ProtectHostname=yes to forbid sethostname() calls.",
            ),
            (
                "RestrictRealtime",
                0.4,
                cls._eval_restrict_realtime,
                "Prohibits selection of real-time scheduling algorithms (SCHED_FIFO/RR).",
                "Set RestrictRealtime=yes to prevent CPU starvation attacks.",
            ),
            (
                "RestrictNamespaces",
                0.5,
                cls._eval_restrict_namespaces,
                "Restricts creation of new Linux kernel namespaces.",
                "Set RestrictNamespaces=yes to prevent container-based privilege escalation exploits.",
            ),
            (
                "RestrictAddressFamilies",
                0.5,
                cls._eval_restrict_address_families,
                "Restricts accessible network socket address families.",
                "Set RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 (or none) to block obscure sockets.",
            ),
            (
                "LockPersonality",
                0.4,
                cls._eval_lock_personality,
                "Blocks personality() syscall to prevent 32-bit execution mode switches.",
                "Set LockPersonality=yes to prevent ABI emulation bypasses.",
            ),
            (
                "SystemCallFilter",
                0.6,
                cls._eval_system_call_filter,
                "Enforces seccomp BPF syscall whitelisting.",
                "Set SystemCallFilter=@system-service or define explicit allowed syscall set.",
            ),
            (
                "SystemCallArchitectures",
                0.4,
                cls._eval_system_call_architectures,
                "Restricts syscall invocation to native CPU architecture.",
                "Set SystemCallArchitectures=native to block foreign ABI syscall vulnerabilities.",
            ),
            (
                "RemoveIPC",
                0.4,
                cls._eval_remove_ipc,
                "Removes SysV and POSIX IPC message queues and shared memory on unit stop.",
                "Set RemoveIPC=yes to clean up IPC memory allocations.",
            ),
        ]

        total_weight = sum(rule[1] for rule in rules)
        weighted_exposure_sum = 0.0
        hardened_count = 0

        for directive, weight, eval_func, desc, rec in rules:
            is_hardened, factor, val = eval_func(properties)
            if is_hardened:
                hardened_count += 1
            weighted_exposure_sum += weight * factor

            assessments.append(
                DirectiveAssessment(
                    directive=directive,
                    current_value=val,
                    is_hardened=is_hardened,
                    exposure_factor=factor,
                    weight=weight,
                    description=desc,
                    recommendation=rec,
                )
            )

        # Compute normalized Exposure Score E in [0.0, 10.0]
        # 0.0 = Hardened (Safe), 10.0 = Completely unhardened (Exposed)
        exposure_score = round((weighted_exposure_sum / total_weight) * 10.0, 2)

        # Determine Danger Level rating
        if exposure_score <= 3.3:
            rating = "SAFE"
        elif exposure_score <= 6.6:
            rating = "MEDIUM"
        else:
            rating = "EXPOSED"

        return UnitAuditResult(
            unit_name=unit_name,
            file_path=None,
            exposure_score=exposure_score,
            rating=rating,
            total_directives=len(rules),
            hardened_count=hardened_count,
            assessments=assessments,
            service_properties=properties,
        )

    @staticmethod
    def _parse_systemd_properties(content: str) -> Dict[str, str]:
        """Parse systemd INI format unit into flat property mapping."""
        properties: Dict[str, str] = {}
        lines = content.splitlines()

        i = 0
        total = len(lines)
        while i < total:
            line = lines[i].strip()
            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith(";"):
                i += 1
                continue

            # Handle line continuation with backslash
            while line.endswith("\\") and i + 1 < total:
                line = line[:-1].strip() + " " + lines[i + 1].strip()
                i += 1

            if "=" in line and not line.startswith("["):
                key, val = line.split("=", 1)
                properties[key.strip()] = val.strip()

            i += 1

        return properties

    @staticmethod
    def _eval_user(props: Dict[str, str]) -> Tuple[bool, float, str]:
        dyn = props.get("DynamicUser", "").lower() in ("yes", "true", "1")
        val = props.get("User", "")
        if dyn:
            return True, 0.0, f"DynamicUser (User={val or 'transient'})"
        if val and val.lower() not in ("root", "0"):
            return True, 0.0, val
        if val.lower() in ("root", "0"):
            return False, 1.0, val
        return False, 1.0, "[Unset - Defaults to root]"

    @staticmethod
    def _eval_dynamic_user(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("DynamicUser", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_protect_system(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("ProtectSystem", "").lower()
        if val == "strict":
            return True, 0.0, val
        if val == "full":
            return True, 0.2, val
        if val in ("yes", "true", "1"):
            return True, 0.4, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_protect_home(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("ProtectHome", "").lower()
        if val in ("strict", "yes", "true", "1"):
            return True, 0.0, val
        if val == "read-only":
            return True, 0.3, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_no_new_privileges(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("NoNewPrivileges", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_capability_bounding_set(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("CapabilityBoundingSet")
        if val is not None:
            # Empty means drops all capabilities!
            if val.strip() == "" or val.strip() == "~" or "CAP_SYS_ADMIN" not in val:
                return True, 0.0, val or "[Empty - All Dropped]"
            return False, 0.7, val
        return False, 1.0, "[Unset - All Capabilities Granted]"

    @staticmethod
    def _eval_ambient_capabilities(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("AmbientCapabilities")
        if val is None or val.strip() == "" or val.strip() == "~":
            return True, 0.0, val or "[Empty/Unset]"
        return False, 1.0, val

    @staticmethod
    def _eval_memory_deny_write_execute(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("MemoryDenyWriteExecute", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_private_tmp(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("PrivateTmp", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_private_devices(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("PrivateDevices", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_private_network(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("PrivateNetwork", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_protect_kernel_tunables(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("ProtectKernelTunables", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_protect_kernel_modules(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("ProtectKernelModules", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_protect_kernel_logs(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("ProtectKernelLogs", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_protect_control_groups(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("ProtectControlGroups", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_protect_clock(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("ProtectClock", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_protect_hostname(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("ProtectHostname", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_restrict_realtime(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("RestrictRealtime", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_restrict_namespaces(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("RestrictNamespaces", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_restrict_address_families(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("RestrictAddressFamilies", "")
        if val and val.lower() != "none" and val != "~":
            return True, 0.0, val
        return False, 1.0, val or "[Unset - All Families Allowed]"

    @staticmethod
    def _eval_lock_personality(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("LockPersonality", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_system_call_filter(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("SystemCallFilter", "")
        if val:
            return True, 0.0, val
        return False, 1.0, "[Unset - Unfiltered Syscalls]"

    @staticmethod
    def _eval_system_call_architectures(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("SystemCallArchitectures", "")
        if "native" in val.lower():
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"

    @staticmethod
    def _eval_remove_ipc(props: Dict[str, str]) -> Tuple[bool, float, str]:
        val = props.get("RemoveIPC", "")
        if val.lower() in ("yes", "true", "1"):
            return True, 0.0, val
        return False, 1.0, val or "[Unset]"
