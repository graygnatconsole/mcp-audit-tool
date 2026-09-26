"""Tests for JSON and SARIF reporters."""

import json
from pathlib import Path

from mcp_audit_tool.auditor import audit_paths
from mcp_audit_tool.reporters import json_reporter, sarif

FIXTURES = Path(__file__).parent / "fixtures"


def test_json_report_structure():
    report = audit_paths([FIXTURES / "vulnerable_config.json"])
    data = json.loads(json_reporter.render(report))
    assert data["tool"] == "mcp-audit-tool"
    assert data["servers_scanned"] == 4
    assert data["summary"]["CRITICAL"] >= 1
    assert all("rule_id" in f and "remediation" in f for f in data["findings"])


def test_sarif_is_valid_2_1_0():
    report = audit_paths([FIXTURES / "vulnerable_config.json"])
    data = json.loads(sarif.render(report))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-audit-tool"
    assert len(run["tool"]["driver"]["rules"]) == 12
    assert len(run["results"]) == len(report.findings)
    for result in run["results"]:
        assert result["ruleId"].startswith("MAT-")
        assert result["level"] in {"error", "warning", "note", "none"}
