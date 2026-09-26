"""End-to-end tests for the audit engine."""

from pathlib import Path

import pytest

from mcp_audit_tool.auditor import ConfigParseError, audit_file, audit_paths, extract_servers
from mcp_audit_tool.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_vulnerable_config_triggers_core_rules():
    findings, count = audit_file(FIXTURES / "vulnerable_config.json")
    assert count == 4
    ids = rule_ids(findings)
    assert "MAT-001" in ids  # hardcoded GitHub token
    assert "MAT-003" in ids  # unpinned npx package
    assert "MAT-004" in ids  # curl | bash
    assert "MAT-007" in ids  # filesystem rooted at /
    assert "MAT-008" in ids  # plaintext http remote
    assert "MAT-009" in ids  # no auth on remote
    assert "MAT-010" in ids  # tool poisoning in description
    assert "MAT-011" in ids  # auto-approved destructive tools
    assert "MAT-012" in ids  # wildcard permission


def test_clean_config_has_no_findings():
    findings, count = audit_file(FIXTURES / "clean_config.json")
    assert count == 2
    assert findings == []


def test_report_score_and_grade():
    report = audit_paths([FIXTURES / "vulnerable_config.json"])
    assert report.score < 50
    assert report.grade in {"D", "F"}
    assert report.has_at_least(Severity.CRITICAL)


def test_clean_report_perfect_score():
    report = audit_paths([FIXTURES / "clean_config.json"])
    assert report.score == 100
    assert report.grade == "A+"
    assert not report.has_at_least(Severity.LOW)


def test_extract_servers_shapes():
    assert extract_servers({"mcpServers": {"a": {}}}) == {"a": {}}
    assert extract_servers({"servers": {"b": {}}}) == {"b": {}}
    assert extract_servers({"mcp": {"servers": {"c": {}}}}) == {"c": {}}
    assert extract_servers({"unrelated": True}) == {}


def test_parse_error_on_garbage(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("::: not json or yaml :::", encoding="utf-8")
    with pytest.raises(ConfigParseError):
        audit_file(bad)
