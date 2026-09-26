"""SARIF 2.1.0 reporter — feed results into GitHub Code Scanning."""

from __future__ import annotations

import json

from mcp_audit_tool import __version__
from mcp_audit_tool.models import AuditReport, Severity
from mcp_audit_tool.rules import RULE_METADATA

SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def render(report: AuditReport) -> str:
    rules = [
        {
            "id": rule_id,
            "name": meta["name"],
            "shortDescription": {"text": meta["name"].replace("-", " ")},
            "defaultConfiguration": {"level": meta["severity"]},
        }
        for rule_id, meta in RULE_METADATA.items()
    ]

    results = []
    for f in report.findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": SARIF_LEVELS[f.severity],
                "message": {"text": f"{f.title} — {f.description} Remediation: {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.source_file.replace("\\", "/") or "unknown"
                            },
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": (
                            [{"name": f.server, "kind": "module"}] if f.server else []
                        ),
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-audit-tool",
                        "version": __version__,
                        "informationUri": "https://github.com/graygnatconsole/mcp-audit-tool",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
