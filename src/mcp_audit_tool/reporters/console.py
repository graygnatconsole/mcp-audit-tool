"""Rich terminal rendering of audit reports."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_audit_tool.models import SEVERITY_ORDER, AuditReport, Severity

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

GRADE_COLORS = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "bold red"}


def render(report: AuditReport, console: Console | None = None) -> None:
    console = console or Console()

    if not report.scanned_files:
        console.print("[yellow]No MCP configuration files found.[/yellow]")
        console.print("Pass one explicitly: [bold]mcp-audit scan path/to/config.json[/bold]")
        return

    grade_color = GRADE_COLORS.get(report.grade, "white")
    header = Text()
    header.append("MCP Security Audit\n", style="bold white")
    header.append(f"Score: {report.score}/100  ", style="bold")
    header.append(f"Grade: {report.grade}\n", style=f"bold {grade_color}")
    header.append(
        f"{report.servers_scanned} server(s) across {len(report.scanned_files)} config file(s)",
        style="dim",
    )
    console.print(Panel(header, border_style=grade_color))

    if not report.findings:
        console.print("[bold green]✔ No security findings. Your MCP setup looks clean.[/bold green]")
        return

    table = Table(show_lines=False, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True, style="dim")
    table.add_column("Server", no_wrap=True)
    table.add_column("Finding", ratio=3)

    ordered = sorted(report.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
    for f in ordered:
        style = SEVERITY_STYLES[f.severity]
        table.add_row(
            Text(f.severity.value, style=style),
            f.rule_id,
            f.server,
            Text(f.title),
        )
    console.print(table)

    counts = report.counts_by_severity()
    summary = "  ".join(
        f"[{SEVERITY_STYLES[s]}]{s.value}: {counts[s.value]}[/]" for s in SEVERITY_ORDER if counts[s.value]
    )
    console.print(summary)

    console.print("\n[bold]Top remediations[/bold]")
    for f in ordered[:5]:
        console.print(f"  • [dim]{f.rule_id}[/dim] {f.remediation}")
