"""Rules for supply-chain risks: unpinned packages and pipe-to-shell installers."""

from __future__ import annotations

import re
from typing import List

from mcp_audit_tool.models import Finding, Severity

PACKAGE_RUNNERS = {"npx", "uvx", "pipx", "bunx", "pnpx", "yarn"}

PIPE_TO_SHELL = re.compile(
    r"(curl|wget)[^|]*\|\s*(sudo\s+)?(bash|sh|zsh|python\d*)", re.IGNORECASE
)


def _joined_args(config: dict) -> str:
    args = config.get("args") or []
    return " ".join(str(a) for a in args)


def unpinned_package(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-003: server launched via npx/uvx without a pinned version — rug-pull risk."""
    findings: List[Finding] = []
    command = str(config.get("command", "")).split("/")[-1]
    if command not in PACKAGE_RUNNERS:
        return findings

    args = [str(a) for a in (config.get("args") or [])]
    # First arg that looks like a package spec (skip flags like -y / --yes).
    pkg = next((a for a in args if not a.startswith("-")), None)
    if pkg is None:
        return findings

    pinned = ("@" in pkg[1:] and not pkg.endswith("@latest")) or "==" in pkg
    if not pinned:
        findings.append(
            Finding(
                rule_id="MAT-003",
                severity=Severity.HIGH,
                title="Unpinned MCP server package (rug-pull / supply-chain risk)",
                description=(
                    f"Server '{server}' runs '{pkg}' via {command} without a pinned "
                    "version. The package fetched at launch can change silently — a "
                    "compromised or hijacked release turns into code execution on your "
                    "machine with your credentials (classic MCP rug pull)."
                ),
                server=server,
                source_file=source_file,
                location="args",
                remediation=(
                    f"Pin an exact version, e.g. '{pkg}@1.2.3', verify the publisher, and "
                    "review the package source before upgrading. Consider vendoring the "
                    "server locally."
                ),
                cwe="CWE-1357",
                references=[
                    "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
                ],
            )
        )
    return findings


def installer_spoofing_pipe(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-004: curl/wget piped into a shell — arbitrary remote code execution."""
    findings: List[Finding] = []
    haystack = f"{config.get('command', '')} {_joined_args(config)}"
    if PIPE_TO_SHELL.search(haystack):
        findings.append(
            Finding(
                rule_id="MAT-004",
                severity=Severity.CRITICAL,
                title="Pipe-to-shell installer in MCP server launch command",
                description=(
                    f"Server '{server}' downloads and executes a remote script at launch "
                    "(curl/wget piped to a shell). The remote server can serve different "
                    "content at any time, enabling silent installer spoofing and full "
                    "remote code execution."
                ),
                server=server,
                source_file=source_file,
                location="command/args",
                remediation=(
                    "Download the script, review it, pin its checksum, and execute a local "
                    "copy — or install the server through a versioned package manager."
                ),
                cwe="CWE-494",
            )
        )
    return findings
