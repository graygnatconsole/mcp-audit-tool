"""Rules for tool metadata: poisoning indicators, auto-approve lists, wildcards."""

from __future__ import annotations

import re
from typing import List

from mcp_audit_tool.models import Finding, Severity

POISONING_PATTERNS = [
    re.compile(r"ignore (all |any )?(previous|prior|above) instructions", re.I),
    re.compile(r"do not (mention|tell|reveal|disclose)", re.I),
    re.compile(r"<(IMPORTANT|SYSTEM|HIDDEN|SECRET)>", re.I),
    re.compile(r"you (must|should|are required to) (always|never)", re.I),
    re.compile(r"exfiltrat|send (this|the|all) (data|file|content) to", re.I),
    re.compile(r"read (the )?(file|contents of) ~/|\.ssh|id_rsa|\.env", re.I),
]

RISKY_TOOL_NAMES = re.compile(
    r"(write|delete|remove|exec|execute|run|shell|bash|terminal|send|post|upload|drop|rm)",
    re.I,
)

AUTO_APPROVE_KEYS = ("alwaysAllow", "autoApprove", "auto_approve", "allowedTools")


def _text_fields(config: dict) -> str:
    parts: List[str] = []
    for key in ("description", "instructions", "systemPrompt", "prompt"):
        if isinstance(config.get(key), str):
            parts.append(config[key])
    return "\n".join(parts)


def tool_poisoning_indicators(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-010: hidden-instruction patterns in descriptions (tool poisoning)."""
    findings: List[Finding] = []
    text = _text_fields(config)
    if not text:
        return findings
    matches = [m.group(0) for p in POISONING_PATTERNS if (m := p.search(text))]
    if matches:
        quoted = ", ".join(f"'{m}'" for m in matches[:5])
        findings.append(
            Finding(
                rule_id="MAT-010",
                severity=Severity.CRITICAL,
                title="Possible tool poisoning: hidden instruction in server metadata",
                description=(
                    f"Server '{server}' metadata contains hidden-instruction patterns: "
                    f"{quoted}. Tool descriptions are injected into the model "
                    "context; malicious servers use them to smuggle instructions the "
                    "user never sees (data exfiltration, behavior overrides)."
                ),
                server=server,
                source_file=source_file,
                location="description",
                remediation=(
                    "Review the server source code, remove hidden instructions, and only "
                    "run servers whose tool metadata you have audited. Pin and hash tool "
                    "definitions to detect rug pulls."
                ),
                cwe="CWE-74",
                references=[
                    "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
                ],
            )
        )
    return findings


def auto_approve_risky_tools(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-011: destructive tools on the auto-approve list (no human confirmation)."""
    findings: List[Finding] = []
    for key in AUTO_APPROVE_KEYS:
        tools = config.get(key)
        if not isinstance(tools, list):
            continue
        for tool in tools:
            if isinstance(tool, str) and RISKY_TOOL_NAMES.search(tool):
                findings.append(
                    Finding(
                        rule_id="MAT-011",
                        severity=Severity.MEDIUM,
                        title=f"Risky tool '{tool}' auto-approved without confirmation",
                        description=(
                            f"Server '{server}' lets the model invoke '{tool}' with no "
                            "human-in-the-loop approval. A single prompt-injection success "
                            "becomes an immediate destructive action."
                        ),
                        server=server,
                        source_file=source_file,
                        location=key,
                        remediation=(
                            "Remove destructive tools from the auto-approve list and require "
                            "explicit user confirmation for write/exec operations."
                        ),
                        cwe="CWE-862",
                    )
                )
    return findings


def wildcard_permissions(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-012: '*' wildcards in permission/allow lists."""
    findings: List[Finding] = []
    for key in AUTO_APPROVE_KEYS + ("permissions", "scopes", "allow"):
        values = config.get(key)
        if isinstance(values, list) and any(str(v).strip() == "*" for v in values):
            findings.append(
                Finding(
                    rule_id="MAT-012",
                    severity=Severity.MEDIUM,
                    title=f"Wildcard '*' permission in '{key}'",
                    description=(
                        f"Server '{server}' grants every tool/permission via a wildcard. "
                        "Future tools added by the server — including malicious ones after a "
                        "rug pull — are automatically trusted."
                    ),
                    server=server,
                    source_file=source_file,
                    location=key,
                    remediation="Enumerate exactly the tools you trust instead of '*'.",
                    cwe="CWE-732",
                )
            )
    return findings
