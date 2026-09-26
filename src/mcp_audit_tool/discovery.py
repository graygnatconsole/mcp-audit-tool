"""Auto-discovery of MCP client configuration files on the local machine."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

# Well-known MCP config locations for popular AI clients.
CANDIDATE_PATHS = {
    "darwin": [
        "~/Library/Application Support/Claude/claude_desktop_config.json",
        "~/.cursor/mcp.json",
        "~/.codeium/windsurf/mcp_config.json",
        "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "~/.config/zed/settings.json",
        "~/.vscode/mcp.json",
        "~/.mcp.json",
    ],
    "linux": [
        "~/.config/Claude/claude_desktop_config.json",
        "~/.cursor/mcp.json",
        "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "~/.config/zed/settings.json",
        "~/.vscode/mcp.json",
        "~/.mcp.json",
    ],
    "win32": [
        "~/AppData/Roaming/Claude/claude_desktop_config.json",
        "~/.cursor/mcp.json",
        "~/AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "~/.vscode/mcp.json",
        "~/.mcp.json",
    ],
}

# Project-level configs that are also worth auditing.
PROJECT_CONFIG_NAMES = [
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
]


def _platform_key() -> str:
    if sys.platform.startswith("darwin"):
        return "darwin"
    if sys.platform.startswith("win"):
        return "win32"
    return "linux"


def discover_configs(cwd: Path | None = None) -> List[Path]:
    """Return existing MCP config files: user-level client configs + project configs."""
    found: List[Path] = []

    for raw in CANDIDATE_PATHS.get(_platform_key(), CANDIDATE_PATHS["linux"]):
        p = Path(raw).expanduser()
        if p.is_file():
            found.append(p)

    base = cwd or Path.cwd()
    for name in PROJECT_CONFIG_NAMES:
        p = base / name
        if p.is_file() and p not in found:
            found.append(p)

    return found
