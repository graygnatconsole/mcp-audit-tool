"""Rules for dangerous execution patterns and excessive local privileges."""

from __future__ import annotations

import re
from typing import List

from mcp_audit_tool.models import Finding, Severity

DANGEROUS_PATTERNS = [
    (re.compile(r"\brm\s+-[rf]{1,2}\b", re.I), "recursive/forced deletion (rm -rf)"),
    (re.compile(r"\bsudo\b"), "privilege escalation (sudo)"),
    (re.compile(r"\bchmod\s+777\b"), "world-writable permissions (chmod 777)"),
    (re.compile(r"\b(eval|exec)\b"), "dynamic code evaluation (eval/exec)"),
    (re.compile(r"\bmkfs\b|\bdd\s+if="), "disk-level operation"),
    (re.compile(r":\(\)\s*\{.*\};\s*:"), "fork bomb"),
]

SHELL_WRAPPERS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}

BROAD_FS_ROOTS = {"/", "~", "$HOME", "%USERPROFILE%", "C:\\", "/*"}


def _args(config: dict) -> List[str]:
    return [str(a) for a in (config.get("args") or [])]


def dangerous_command(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-005: destructive or privileged commands in the launch line."""
    findings: List[Finding] = []
    haystack = " ".join([str(config.get("command", ""))] + _args(config))
    for pattern, label in DANGEROUS_PATTERNS:
        if pattern.search(haystack):
            findings.append(
                Finding(
                    rule_id="MAT-005",
                    severity=Severity.HIGH,
                    title=f"Dangerous command in MCP server launch: {label}",
                    description=(
                        f"Server '{server}' is launched with {label}. If the server or the "
                        "model driving it is manipulated (prompt injection, tool poisoning), "
                        "this capability can destroy data or escalate privileges."
                    ),
                    server=server,
                    source_file=source_file,
                    location="command/args",
                    remediation=(
                        "Remove privileged flags, run the server as an unprivileged user, "
                        "and sandbox it (container, seatbelt, firejail)."
                    ),
                    cwe="CWE-78",
                )
            )
    return findings


def shell_interpolation(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-006: shell wrapper with -c string — command-injection surface."""
    findings: List[Finding] = []
    command = str(config.get("command", "")).split("/")[-1].lower()
    args = _args(config)
    if command in SHELL_WRAPPERS and any(a in ("-c", "/c", "-Command") for a in args):
        findings.append(
            Finding(
                rule_id="MAT-006",
                severity=Severity.MEDIUM,
                title="Shell `-c` wrapper in MCP server launch",
                description=(
                    f"Server '{server}' is started through a shell '-c' string. Interpolated "
                    "values inside that string are a classic command-injection vector and make "
                    "auditing harder."
                ),
                server=server,
                source_file=source_file,
                location="command/args",
                remediation=(
                    "Invoke the executable directly with an argument array instead of a "
                    "shell string."
                ),
                cwe="CWE-78",
            )
        )
    return findings


def overly_broad_filesystem(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-007: filesystem-style servers rooted at / or the entire home directory."""
    findings: List[Finding] = []
    name_hint = re.search(r"(filesystem|fs|files)", server, re.I) or re.search(
        r"(filesystem|fs|files)", " ".join(_args(config)), re.I
    )
    if not name_hint:
        return findings

    for a in _args(config):
        if a.strip() in BROAD_FS_ROOTS:
            findings.append(
                Finding(
                    rule_id="MAT-007",
                    severity=Severity.HIGH,
                    title="Filesystem MCP server granted root/home-wide access",
                    description=(
                        f"Server '{server}' exposes '{a}' — effectively your whole disk or "
                        "home directory — to the model. Any prompt-injection or tool-poisoning "
                        "success becomes full read/write access to SSH keys, browser cookies "
                        "and documents."
                    ),
                    server=server,
                    source_file=source_file,
                    location="args",
                    remediation=(
                        "Scope the server to a dedicated working directory, e.g. "
                        "~/mcp-workspace, and keep secrets outside it."
                    ),
                    cwe="CWE-22",
                )
            )
    return findings
