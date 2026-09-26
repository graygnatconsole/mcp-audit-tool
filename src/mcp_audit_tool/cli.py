"""Command-line interface for mcp-audit-tool."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console

from mcp_audit_tool import __version__
from mcp_audit_tool.auditor import ConfigParseError, audit_paths
from mcp_audit_tool.discovery import discover_configs
from mcp_audit_tool.models import AuditReport, Severity
from mcp_audit_tool.reporters import console as console_reporter
from mcp_audit_tool.reporters import json_reporter, sarif
from mcp_audit_tool.rules import RULE_METADATA

app = typer.Typer(
    name="mcp-audit",
    help="Security audit CLI for Model Context Protocol (MCP) servers and AI agent configs.",
    add_completion=False,
    no_args_is_help=True,
)
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mcp-audit-tool {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-v", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """mcp-audit-tool — audit your MCP setup before the model does something you regret."""


@app.command()
def scan(
    paths: Optional[List[Path]] = typer.Argument(
        None, help="Config file(s) to audit. Auto-discovers known client configs if omitted."
    ),
    format: str = typer.Option(
        "console", "--format", "-f", help="Output format: console | json | sarif."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write the report to a file instead of stdout."
    ),
    fail_on: str = typer.Option(
        "none", "--fail-on", help="Exit 1 if findings of this severity or worse exist: "
        "critical | high | medium | low | none."
    ),
    no_discovery: bool = typer.Option(
        False, "--no-discovery", help="Disable auto-discovery; require explicit paths."
    ),
) -> None:
    """Scan MCP client configs for security risks."""

    targets: List[Path] = list(paths or [])
    if not targets and not no_discovery:
        targets = discover_configs()

    if not targets:
        if format == "console":
            console_reporter.render(AuditReport())
            raise typer.Exit(0)
        err_console.print("[red]No config files found to audit.[/red]")
        raise typer.Exit(2)

    for t in targets:
        if not t.is_file():
            err_console.print(f"[red]File not found:[/red] {t}")
            raise typer.Exit(2)

    try:
        report = audit_paths(targets)
    except ConfigParseError as exc:
        err_console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(2)

    fmt = format.lower()
    if fmt == "console":
        if output:
            err_console.print("[red]--output is only supported with json/sarif formats.[/red]")
            raise typer.Exit(2)
        console_reporter.render(report)
    elif fmt == "json":
        payload = json_reporter.render(report)
        output.write_text(payload + "\n", encoding="utf-8") if output else typer.echo(payload)
    elif fmt == "sarif":
        payload = sarif.render(report)
        output.write_text(payload + "\n", encoding="utf-8") if output else typer.echo(payload)
    else:
        err_console.print(f"[red]Unknown format:[/red] {format} (use console|json|sarif)")
        raise typer.Exit(2)

    threshold = fail_on.lower()
    if threshold != "none":
        try:
            sev = Severity[threshold.upper()]
        except KeyError:
            err_console.print(f"[red]Unknown severity:[/red] {fail_on}")
            raise typer.Exit(2)
        if report.has_at_least(sev):
            raise typer.Exit(1)


@app.command(name="rules")
def list_rules() -> None:
    """List all built-in audit rules."""
    console = Console()
    from rich.table import Table

    table = Table(title="mcp-audit-tool rules")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Default severity")
    for rule_id, meta in RULE_METADATA.items():
        table.add_row(rule_id, meta["name"], meta["severity"])
    console.print(table)


if __name__ == "__main__":
    app()
