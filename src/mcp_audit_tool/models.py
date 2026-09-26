"""Core data models for findings and audit reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER: List[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# Score deduction per finding, used for the 0-100 security score.
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    """A single security finding produced by a rule."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    server: str
    source_file: str = ""
    location: str = ""
    remediation: str = ""
    cwe: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "server": self.server,
            "source_file": self.source_file,
            "location": self.location,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "references": self.references,
        }


@dataclass
class AuditReport:
    """Aggregated result of an audit run."""

    findings: List[Finding] = field(default_factory=list)
    scanned_files: List[str] = field(default_factory=list)
    servers_scanned: int = 0

    @property
    def score(self) -> int:
        """Security score from 0 (worst) to 100 (clean)."""
        penalty = sum(SEVERITY_WEIGHTS[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 95:
            return "A+"
        if s >= 90:
            return "A"
        if s >= 80:
            return "B"
        if s >= 70:
            return "C"
        if s >= 50:
            return "D"
        return "F"

    def counts_by_severity(self) -> dict:
        counts = {s.value: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def has_at_least(self, severity: Severity) -> bool:
        threshold = SEVERITY_ORDER.index(severity)
        return any(SEVERITY_ORDER.index(f.severity) <= threshold for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "tool": "mcp-audit-tool",
            "score": self.score,
            "grade": self.grade,
            "servers_scanned": self.servers_scanned,
            "scanned_files": self.scanned_files,
            "summary": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }
