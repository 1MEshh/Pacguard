"""
PKGBUILD and Arch Linux install script parser.

Extracts metadata, scalar variables, bash arrays, source URLs with aliases,
checksum tables, and lifecycle hook functions (prepare, build, check, package,
post_install, etc.) without requiring external runtime dependencies.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class SourceEntry:
    """Represents a single entry in the PKGBUILD source array."""
    raw: str
    alias: Optional[str]
    url: str
    domain: str
    filename: str
    is_vcs: bool
    is_remote: bool


@dataclass
class ShellFunction:
    """Represents an extracted shell function definition from PKGBUILD or .install script."""
    name: str
    start_line: int
    end_line: int
    body: str
    raw_code: str


@dataclass
class PKGBUILDData:
    """Structured representation of parsed PKGBUILD metadata and code blocks."""
    file_path: Optional[str] = None
    pkgname: str = ""
    pkgver: str = ""
    pkgrel: str = ""
    epoch: Optional[str] = None
    pkgdesc: str = ""
    url: str = ""
    arch: List[str] = field(default_factory=list)
    license: List[str] = field(default_factory=list)
    depends: List[str] = field(default_factory=list)
    makedepends: List[str] = field(default_factory=list)
    checkdepends: List[str] = field(default_factory=list)
    optdepends: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    replaces: List[str] = field(default_factory=list)
    install_script: Optional[str] = None
    source: List[SourceEntry] = field(default_factory=list)
    checksums: Dict[str, List[str]] = field(default_factory=dict)
    functions: Dict[str, ShellFunction] = field(default_factory=dict)
    install_functions: Dict[str, ShellFunction] = field(default_factory=dict)
    variables: Dict[str, str] = field(default_factory=dict)
    raw_lines: List[str] = field(default_factory=list)


class PKGBUILDParser:
    """Robust parser for Arch Linux PKGBUILD syntax and .install script hooks."""

    VCS_PREFIXES = ("git+", "git://", "svn+", "svn://", "hg+", "hg://", "bzr+", "bzr://")
    KNOWN_CHECKSUM_NAMES = (
        "sha256sums",
        "sha512sums",
        "sha384sums",
        "sha224sums",
        "sha1sums",
        "md5sums",
        "b2sums",
    )

    def __init__(self, content: str, file_path: Optional[str] = None) -> None:
        self.raw_content = content
        self.file_path = file_path
        self.lines = content.splitlines()
        self.variables: Dict[str, str] = {}
        self.arrays: Dict[str, List[str]] = {}
        self.functions: Dict[str, ShellFunction] = {}

    @classmethod
    def from_file(cls, path: str) -> "PKGBUILDParser":
        """Factory method to load PKGBUILD from a filesystem path."""
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
        return cls(content, file_path=path)

    def parse(self) -> PKGBUILDData:
        """Execute full parsing pipeline and return PKGBUILDData model."""
        self._parse_variables_and_arrays()
        self._parse_functions()

        data = PKGBUILDData(
            file_path=self.file_path,
            pkgname=self.variables.get("pkgname", ""),
            pkgver=self.variables.get("pkgver", ""),
            pkgrel=self.variables.get("pkgrel", ""),
            epoch=self.variables.get("epoch"),
            pkgdesc=self.variables.get("pkgdesc", ""),
            url=self.variables.get("url", ""),
            arch=self.arrays.get("arch", [self.variables["arch"]] if "arch" in self.variables else []),
            license=self.arrays.get("license", [self.variables["license"]] if "license" in self.variables else []),
            depends=self.arrays.get("depends", []),
            makedepends=self.arrays.get("makedepends", []),
            checkdepends=self.arrays.get("checkdepends", []),
            optdepends=self.arrays.get("optdepends", []),
            provides=self.arrays.get("provides", []),
            conflicts=self.arrays.get("conflicts", []),
            replaces=self.arrays.get("replaces", []),
            install_script=self.variables.get("install"),
            source=self._parse_source_entries(),
            checksums=self._extract_checksums(),
            functions=self.functions,
            variables=self.variables,
            raw_lines=self.lines,
        )

        # If an install script is specified and can be resolved, parse its hooks
        if data.install_script and self.file_path:
            install_path = os.path.join(os.path.dirname(self.file_path), data.install_script)
            if os.path.isfile(install_path):
                data.install_functions = self.parse_install_script_file(install_path)

        return data

    @staticmethod
    def parse_install_script_file(path: str) -> Dict[str, ShellFunction]:
        """Parse functions within an Arch Linux .install script."""
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
        return PKGBUILDParser.parse_script_functions(content)

    @staticmethod
    def parse_script_functions(content: str) -> Dict[str, ShellFunction]:
        """Extract function bodies from any bash script string."""
        lines = content.splitlines()
        functions: Dict[str, ShellFunction] = {}
        # Bash function syntax: either 'function name [()] [{]' or 'name() [{]'
        func_regex = re.compile(
            r"^(?:function\s+([a-zA-Z0-9_-]+)(?:\s*\(\s*\))?|([a-zA-Z0-9_-]+)\s*\(\s*\))\s*(?:\{|$)"
        )

        i = 0
        total_lines = len(lines)
        while i < total_lines:
            line = lines[i]
            stripped = line.strip()

            # Ignore comment lines
            if stripped.startswith("#"):
                i += 1
                continue

            match = func_regex.match(stripped)
            if match:
                func_name = match.group(1) or match.group(2)
                # Ensure it's not a common control keyword
                if func_name in ("if", "for", "while", "case", "elif", "else", "then", "do", "done", "fi", "esac"):
                    i += 1
                    continue

                # Locate opening brace
                start_line = i + 1
                brace_found = False
                brace_depth = 0
                body_lines: List[str] = []
                raw_lines: List[str] = []

                # Check if opening brace is on current line
                line_after_sig = stripped[match.end():]
                if "{" in stripped:
                    brace_found = True

                j = i
                while j < total_lines:
                    cur = lines[j]
                    raw_lines.append(cur)

                    if not brace_found:
                        if "{" in cur:
                            brace_found = True
                        else:
                            j += 1
                            continue

                    # Count braces (ignoring quoted braces or comments as best effort)
                    sanitized = re.sub(r'#.*$', '', cur)
                    brace_depth += sanitized.count("{") - sanitized.count("}")

                    if j > i or (brace_found and brace_depth > 0):
                        body_lines.append(cur)

                    if brace_found and brace_depth <= 0:
                        end_line = j + 1
                        # Trim closing brace from body if present
                        if body_lines and body_lines[-1].strip().endswith("}"):
                            last = body_lines[-1].strip()
                            if last == "}":
                                body_lines.pop()
                            else:
                                body_lines[-1] = body_lines[-1].rstrip("}")
                        # Clean leading brace line
                        if body_lines and "{" in body_lines[0]:
                            body_lines[0] = body_lines[0].split("{", 1)[1]

                        functions[func_name] = ShellFunction(
                            name=func_name,
                            start_line=start_line,
                            end_line=end_line,
                            body="\n".join(body_lines),
                            raw_code="\n".join(raw_lines),
                        )
                        i = j
                        break
                    j += 1
            i += 1

        return functions

    def _parse_functions(self) -> None:
        """Parse functions declared inside the PKGBUILD."""
        self.functions = self.parse_script_functions(self.raw_content)

    def _expand_variables(self, value: str) -> str:
        """Resolve simple and braced shell variables using known scalars."""
        if not value or ("$" not in value):
            return value

        def replace_var(match: re.Match[str]) -> str:
            var_name = match.group(1) or match.group(2)
            # Handle parameter expansion syntax like ${var%/*} or ${var#prefix}
            clean_var = re.split(r"[:#%]", var_name)[0]
            return self.variables.get(clean_var, match.group(0))

        return re.sub(r"\$\{([a-zA-Z0-9_]+[^\}]*)\}|\$([a-zA-Z0-9_]+)", replace_var, value)

    def _strip_quotes(self, token: str) -> str:
        """Strip surrounding matching quotes and trim whitespace."""
        token = token.strip()
        if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
            return token[1:-1]
        return token

    def _parse_variables_and_arrays(self) -> None:
        """Iterate through lines to extract scalar assignments and array declarations."""
        i = 0
        total_lines = len(self.lines)

        var_pattern = re.compile(r"^([a-zA-Z0-9_]+)\s*=\s*(.*)$")

        while i < total_lines:
            line = self.lines[i]
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                i += 1
                continue

            # Check if this line is a function start; if so, skip function body
            func_check = re.match(r"^(?:function\s+)?([a-zA-Z0-9_-]+)\s*\(\s*\)\s*\{?", stripped)
            if func_check and func_check.group(1) not in ("if", "for", "while"):
                # Fast-forward past function definition
                brace_depth = 0
                has_brace = False
                while i < total_lines:
                    cur = self.lines[i]
                    sanitized = re.sub(r'#.*$', '', cur)
                    if "{" in sanitized:
                        has_brace = True
                    brace_depth += sanitized.count("{") - sanitized.count("}")
                    if has_brace and brace_depth <= 0:
                        break
                    i += 1
                i += 1
                continue

            match = var_pattern.match(stripped)
            if match:
                var_name = match.group(1)
                remainder = match.group(2).strip()

                # Handle bash array: name=( ... )
                if remainder.startswith("("):
                    array_elements: List[str] = []
                    acc = remainder[1:]
                    while i < total_lines:
                        # Strip comments from line segment
                        comment_idx = -1
                        in_single_q = False
                        in_double_q = False
                        for idx, ch in enumerate(acc):
                            if ch == "'" and not in_double_q:
                                in_single_q = not in_single_q
                            elif ch == '"' and not in_single_q:
                                in_double_q = not in_double_q
                            elif ch == '#' and not in_single_q and not in_double_q:
                                comment_idx = idx
                                break

                        if comment_idx != -1:
                            acc = acc[:comment_idx]

                        # Check if array closes on this line
                        closing_idx = -1
                        in_single_q = False
                        in_double_q = False
                        for idx, ch in enumerate(acc):
                            if ch == "'" and not in_double_q:
                                in_single_q = not in_single_q
                            elif ch == '"' and not in_single_q:
                                in_double_q = not in_double_q
                            elif ch == ")" and not in_single_q and not in_double_q:
                                closing_idx = idx
                                break

                        if closing_idx != -1:
                            chunk = acc[:closing_idx]
                            array_elements.extend(self._tokenize_array_elements(chunk))
                            break
                        else:
                            array_elements.extend(self._tokenize_array_elements(acc))
                            i += 1
                            if i < total_lines:
                                acc = self.lines[i].strip()
                            else:
                                break

                    resolved_elements = [
                        self._strip_quotes(self._expand_variables(elem))
                        for elem in array_elements
                        if elem.strip()
                    ]
                    self.arrays[var_name] = resolved_elements
                else:
                    # Scalar variable assignment
                    # Remove trailing inline comment if not inside quotes
                    clean_val = self._strip_inline_comment(remainder)
                    clean_val = self._strip_quotes(clean_val)
                    expanded = self._expand_variables(clean_val)
                    self.variables[var_name] = expanded

            i += 1

    def _strip_inline_comment(self, text: str) -> str:
        """Remove trailing unquoted comments from a scalar variable assignment line."""
        in_s = False
        in_d = False
        for idx, ch in enumerate(text):
            if ch == "'" and not in_d:
                in_s = not in_s
            elif ch == '"' and not in_s:
                in_d = not in_d
            elif ch == '#' and not in_s and not in_d:
                return text[:idx].strip()
        return text.strip()

    def _tokenize_array_elements(self, chunk: str) -> List[str]:
        """Tokenize bash array items respecting quotes."""
        tokens: List[str] = []
        current: List[str] = []
        in_s = False
        in_d = False

        for ch in chunk:
            if ch == "'" and not in_d:
                in_s = not in_s
                current.append(ch)
            elif ch == '"' and not in_s:
                in_d = not in_d
                current.append(ch)
            elif ch.isspace() and not in_s and not in_d:
                if current:
                    tokens.append("".join(current))
                    current.clear()
            else:
                current.append(ch)

        if current:
            tokens.append("".join(current))

        return tokens

    def _parse_source_entries(self) -> List[SourceEntry]:
        """Parse source array elements into structured SourceEntry objects."""
        raw_sources = self.arrays.get("source", [])
        # Also check architecture-specific sources, e.g. source_x86_64
        for k, v in self.arrays.items():
            if k.startswith("source_") and isinstance(v, list):
                raw_sources.extend(v)

        entries: List[SourceEntry] = []
        for raw in raw_sources:
            entry_str = raw.strip()
            alias: Optional[str] = None
            url = entry_str

            if "::" in entry_str:
                parts = entry_str.split("::", 1)
                alias = parts[0].strip()
                url = parts[1].strip()

            is_vcs = any(url.startswith(prefix) for prefix in self.VCS_PREFIXES)
            is_remote = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url)) or is_vcs

            domain = ""
            filename = ""

            if is_remote:
                clean_url = url
                # Strip VCS prefix for parsing URL domain
                for pfx in ("git+", "svn+", "hg+", "bzr+"):
                    if clean_url.startswith(pfx):
                        clean_url = clean_url[len(pfx):]
                        break
                parsed = urlparse(clean_url)
                domain = parsed.netloc.split(":")[0].lower()
                path = parsed.path
                filename = alias or (os.path.basename(path) if path else "")
            else:
                filename = alias or os.path.basename(entry_str)

            entries.append(
                SourceEntry(
                    raw=raw,
                    alias=alias,
                    url=url,
                    domain=domain,
                    filename=filename,
                    is_vcs=is_vcs,
                    is_remote=is_remote,
                )
            )

        return entries

    def _extract_checksums(self) -> Dict[str, List[str]]:
        """Collect all recognized checksum arrays (sha256sums, md5sums, etc.)."""
        checksums: Dict[str, List[str]] = {}
        for k, v in self.arrays.items():
            if any(k.startswith(chk) for chk in self.KNOWN_CHECKSUM_NAMES):
                checksums[k] = v
        return checksums
