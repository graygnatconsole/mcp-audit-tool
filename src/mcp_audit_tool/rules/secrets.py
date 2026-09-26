"""Rules for credential hygiene in MCP server configs."""

from __future__ import annotations

import re
from typing import List

from mcp_audit_tool.models import Finding, Severity

# Known secret shapes (real-looking values, not placeholders).
SECRET_VALUE_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),                    # OpenAI / Anthropic style
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),                # Anthropic
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),                      # GitHub PAT
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),              # GitHub fine-grained PAT
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS access key
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),             # Slack
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                    # Google API key
]

SENSITIVE_KEY_NAMES = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)", re.IGNORECASE
)

PLACEHOLDER_HINTS = ("your-", "xxx", "changeme", "example", "placeholder", "<", "todo")


def _looks_real(value: str) -> bool:
    v = value.strip().lower()
    if len(v) < 8:
        return False
    return not any(h in v for h in PLACEHOLDER_HINTS)


def hardcoded_secret_in_env(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-001: real-looking secrets hardcoded in the server env block."""
    findings: List[Finding] = []
    env = config.get("env") or {}
    if not isinstance(env, dict):
        return findings

    for key, value in env.items():
        if not isinstance(value, str):
            continue
        matched_pattern = any(p.search(value) for p in SECRET_VALUE_PATTERNS)
        matched_name = bool(SENSITIVE_KEY_NAMES.search(key)) and _looks_real(value)
        if matched_pattern or matched_name:
            findings.append(
                Finding(
                    rule_id="MAT-001",
                    severity=Severity.CRITICAL,
                    title="Hardcoded secret in MCP server environment",
                    description=(
                        f"Environment variable '{key}' for server '{server}' appears to "
                        "contain a real credential stored in plaintext. Anyone with read "
                        "access to this config file (backups, dotfiles repos, screenshots) "
                        "can steal it."
                    ),
                    server=server,
                    source_file=source_file,
                    location=f"env.{key}",
                    remediation=(
                        "Move the credential to an OS keychain or a secrets manager and "
                        "reference it indirectly (e.g. ${VAR} resolved by a wrapper), or use "
                        "OAuth-based remote MCP servers instead of static keys. Rotate the "
                        "exposed secret immediately."
                    ),
                    cwe="CWE-798",
                    references=[
                        "https://modelcontextprotocol.io/specification/draft/basic/security_best_practices"
                    ],
                )
            )
    return findings


def sensitive_env_passthrough(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-002: broad host environment passthrough to the server process."""
    findings: List[Finding] = []
    env = config.get("env") or {}
    if not isinstance(env, dict):
        return findings

    for key, value in env.items():
        if isinstance(value, str) and re.fullmatch(r"\$\{?[A-Z0-9_]+\}?", value.strip()):
            ref = value.strip().strip("${}")
            if SENSITIVE_KEY_NAMES.search(ref):
                findings.append(
                    Finding(
                        rule_id="MAT-002",
                        severity=Severity.HIGH,
                        title="Sensitive host environment variable passed to MCP server",
                        description=(
                            f"'{key}' forwards host variable '{ref}' into server '{server}'. "
                            "A compromised or malicious server process inherits the credential "
                            "and can exfiltrate it."
                        ),
                        server=server,
                        source_file=source_file,
                        location=f"env.{key}",
                        remediation=(
                            "Grant the server a narrowly-scoped token instead of your "
                            "primary credential, and prefer per-service least-privilege keys."
                        ),
                        cwe="CWE-200",
                    )
                )
    return findings
