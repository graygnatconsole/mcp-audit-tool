"""Rule registry. Each rule inspects one MCP server entry and returns findings."""

from __future__ import annotations

from typing import Callable, Dict, List

from mcp_audit_tool.models import Finding
from mcp_audit_tool.rules import execution, metadata, secrets, supply_chain, transport

RuleFunc = Callable[[str, dict, str], List[Finding]]

ALL_RULES: List[RuleFunc] = [
    # secrets
    secrets.hardcoded_secret_in_env,
    secrets.sensitive_env_passthrough,
    # supply chain
    supply_chain.unpinned_package,
    supply_chain.installer_spoofing_pipe,
    # execution
    execution.dangerous_command,
    execution.shell_interpolation,
    execution.overly_broad_filesystem,
    # transport
    transport.insecure_remote_transport,
    transport.missing_authentication,
    # metadata
    metadata.tool_poisoning_indicators,
    metadata.auto_approve_risky_tools,
    metadata.wildcard_permissions,
]

RULE_METADATA: Dict[str, dict] = {
    "MAT-001": {"name": "hardcoded-secret-in-env", "severity": "CRITICAL"},
    "MAT-002": {"name": "sensitive-env-passthrough", "severity": "HIGH"},
    "MAT-003": {"name": "unpinned-package", "severity": "HIGH"},
    "MAT-004": {"name": "installer-spoofing-pipe", "severity": "CRITICAL"},
    "MAT-005": {"name": "dangerous-command", "severity": "HIGH"},
    "MAT-006": {"name": "shell-interpolation", "severity": "MEDIUM"},
    "MAT-007": {"name": "overly-broad-filesystem", "severity": "HIGH"},
    "MAT-008": {"name": "insecure-remote-transport", "severity": "HIGH"},
    "MAT-009": {"name": "missing-authentication", "severity": "MEDIUM"},
    "MAT-010": {"name": "tool-poisoning-indicators", "severity": "CRITICAL"},
    "MAT-011": {"name": "auto-approve-risky-tools", "severity": "MEDIUM"},
    "MAT-012": {"name": "wildcard-permissions", "severity": "MEDIUM"},
}
