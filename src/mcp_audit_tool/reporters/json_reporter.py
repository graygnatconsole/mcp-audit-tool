"""JSON reporter."""

from __future__ import annotations

import json

from mcp_audit_tool.models import AuditReport


def render(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2)
