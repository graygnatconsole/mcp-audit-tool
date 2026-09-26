"""Rules for remote MCP server transport security (SSE / streamable HTTP)."""

from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from mcp_audit_tool.models import Finding, Severity

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _server_url(config: dict) -> str:
    for key in ("url", "serverUrl", "endpoint", "sse_url"):
        if isinstance(config.get(key), str):
            return config[key]
    return ""


def insecure_remote_transport(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-008: plaintext http:// remote MCP endpoint."""
    findings: List[Finding] = []
    url = _server_url(config)
    if not url:
        return findings
    parsed = urlparse(url)
    if parsed.scheme == "http" and parsed.hostname not in LOCAL_HOSTS:
        findings.append(
            Finding(
                rule_id="MAT-008",
                severity=Severity.HIGH,
                title="Remote MCP server over plaintext HTTP",
                description=(
                    f"Server '{server}' connects to '{url}' without TLS. Tool calls, "
                    "responses and any embedded credentials traverse the network in cleartext "
                    "and can be intercepted or modified (MITM)."
                ),
                server=server,
                source_file=source_file,
                location="url",
                remediation="Switch the endpoint to https:// and verify certificates.",
                cwe="CWE-319",
            )
        )
    return findings


def missing_authentication(server: str, config: dict, source_file: str) -> List[Finding]:
    """MAT-009: remote MCP endpoint with no auth headers configured."""
    findings: List[Finding] = []
    url = _server_url(config)
    if not url:
        return findings
    parsed = urlparse(url)
    if parsed.hostname in LOCAL_HOSTS:
        return findings

    headers = config.get("headers") or {}
    env = config.get("env") or {}
    has_auth = any(
        k.lower() in ("authorization", "x-api-key", "proxy-authorization") for k in headers
    ) or any("TOKEN" in k.upper() or "KEY" in k.upper() for k in env)

    if not has_auth:
        findings.append(
            Finding(
                rule_id="MAT-009",
                severity=Severity.MEDIUM,
                title="Remote MCP server without authentication",
                description=(
                    f"Server '{server}' reaches '{url}' with no Authorization header or API "
                    "key configured. Unauthenticated MCP endpoints let anyone who can reach "
                    "the server invoke its tools."
                ),
                server=server,
                source_file=source_file,
                location="url",
                remediation=(
                    "Enable OAuth 2.1 or a bearer token on the server and configure the "
                    "client headers accordingly. Never pass tokens through unvalidated."
                ),
                cwe="CWE-306",
                references=[
                    "https://modelcontextprotocol.io/specification/draft/basic/authorization"
                ],
            )
        )
    return findings
