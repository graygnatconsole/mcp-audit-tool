"""Audit engine: load MCP configs, extract server entries, run all rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

from mcp_audit_tool.models import AuditReport, Finding
from mcp_audit_tool.rules import ALL_RULES


class ConfigParseError(Exception):
    """Raised when a config file cannot be parsed."""


def load_config(path: Path) -> dict:
    """Load a JSON or YAML MCP config file."""
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigParseError(f"{path}: not valid JSON or YAML ({exc})") from exc
        if not isinstance(data, dict):
            raise ConfigParseError(f"{path}: top-level value is not an object")
        return data


def extract_servers(data: dict) -> Dict[str, dict]:
    """Pull the MCP server map out of known config shapes.

    Supports: ``mcpServers`` (Claude Desktop, Cursor, VS Code), ``servers``
    (Zed / generic), and ``mcp.servers`` wrappers.
    """
    for key in ("mcpServers", "servers"):
        section = data.get(key)
        if isinstance(section, dict):
            return {k: v for k, v in section.items() if isinstance(v, dict)}
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        section = mcp.get("servers")
        if isinstance(section, dict):
            return {k: v for k, v in section.items() if isinstance(v, dict)}
    return {}


def audit_file(path: Path) -> Tuple[List[Finding], int]:
    """Audit a single config file. Returns (findings, server_count)."""
    data = load_config(path)
    servers = extract_servers(data)
    findings: List[Finding] = []
    for name, cfg in servers.items():
        for rule in ALL_RULES:
            findings.extend(rule(name, cfg, str(path)))
    return findings, len(servers)


def audit_paths(paths: List[Path]) -> AuditReport:
    """Audit every config file and aggregate a report."""
    report = AuditReport()
    for path in paths:
        findings, count = audit_file(path)
        report.findings.extend(findings)
        report.servers_scanned += count
        report.scanned_files.append(str(path))
    return report
