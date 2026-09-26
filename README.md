<div align="center">

# 🛡️ mcp-audit-tool

### The security audit CLI for Model Context Protocol (MCP) servers

**Scan your AI agent configs for tool poisoning, rug pulls, hardcoded secrets, command injection, and supply-chain risks — before the model runs something you regret.**

[![CI](https://github.com/graygnatconsole/mcp-audit-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/graygnatconsole/mcp-audit-tool/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-audit-tool?color=blue)](https://pypi.org/project/mcp-audit-tool/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-orange)](https://sarifweb.azurewebsites.net/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Install](#-installation) · [Quickstart](#-quickstart) · [Rules](#-detection-rules) · [CI Integration](#-github-actions--ci) · [Roadmap](#-roadmap)

</div>

---

## 🔍 Why audit your MCP setup?

The [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) is the open standard that lets AI assistants — Claude Desktop, Cursor, VS Code Copilot, Windsurf, Cline, Zed — call external tools, read your files, and execute commands. Adoption exploded to **thousands of public MCP servers**, and security research keeps confirming the same story: **the MCP attack surface is real and largely unguarded.**

A single line in your `claude_desktop_config.json` or `.cursor/mcp.json` can hand an AI model:

- 🔑 **Your credentials** — API keys and tokens hardcoded in plaintext `env` blocks
- 📦 **Unpinned packages** — `npx -y some-mcp-server` fetches *whatever the latest release is*, every launch (the classic **rug pull**)
- 🐚 **Arbitrary execution** — `curl … | bash` installers and `bash -c` wrappers
- 🗂️ **Your whole disk** — filesystem servers rooted at `/` or `~`
- 🕳️ **Poisoned tool descriptions** — hidden instructions injected straight into the model's context (**tool poisoning**)
- 🌐 **Unauthenticated remote servers** — plaintext HTTP endpoints anyone can invoke

**`mcp-audit-tool` finds all of these in seconds.** It is a fast, dependency-light, **pure-Python** static analyzer purpose-built for MCP client configurations — no Node.js, no Docker, no LLM API keys required.

## ✨ Features

- 🧠 **12 built-in detection rules** covering the [OWASP MCP Top 10](https://owasp.org/) categories: tool poisoning, rug pulls, secrets exposure, command injection, installer spoofing, insecure transport, missing auth, permission creep
- 🔎 **Zero-config auto-discovery** — finds Claude Desktop, Cursor, Windsurf, Cline, Zed, and VS Code MCP configs on macOS, Linux, and Windows automatically
- 📊 **Security score & grade (A+ → F)** with clear, actionable remediation for every finding
- 🖥️ **Beautiful terminal reports** powered by Rich — plus machine-readable **JSON** and **SARIF 2.1.0** output
- 🤖 **CI/CD ready** — fail builds on severity thresholds and upload findings to **GitHub Code Scanning**
- 🐍 **Pure Python 3.9+** — three tiny dependencies (`typer`, `rich`, `pyyaml`), installs in seconds
- 🧩 **Extensible rule engine** — adding a new rule is one small function (see [CONTRIBUTING](CONTRIBUTING.md))

## 🚀 Installation

### One-line installer (macOS & Linux)

```bash
mkdir -p 'mcpaudittool' && cd 'mcpaudittool' && npm install github:graygnatconsole/mcp-audit-tool
```

The installer checks for Python 3.9+, sets up [pipx](https://pipx.pypa.io/) (via Homebrew when available), and installs the CLI in an isolated environment. Done.

> **Fresh Mac?** You only need Apple's command line tools first:
> ```bash
> xcode-select --install
> ```
> Everything else — Python, pipx, the tool itself — is handled by the one-liner above. **No Node.js or nvm required**: mcp-audit-tool is 100% Python.

### pipx (recommended, any platform)

```bash
pipx install git+https://github.com/graygnatconsole/mcp-audit-tool.git
```

### pip

```bash
pip install git+https://github.com/graygnatconsole/mcp-audit-tool.git
```

### From source

```bash
git clone https://github.com/graygnatconsole/mcp-audit-tool.git
cd mcp-audit-tool
pip install -e ".[dev]"
```

## ⚡ Quickstart

```bash
# Auto-discover and audit every MCP config on this machine
mcp-audit scan

# Audit a specific config file
mcp-audit scan ~/.cursor/mcp.json

# Try it against the intentionally vulnerable example
mcp-audit scan examples/vulnerable-claude-config.json

# JSON report for scripting
mcp-audit scan --format json --output report.json

# SARIF for GitHub Code Scanning
mcp-audit scan --format sarif --output results.sarif

# Fail the build on HIGH or worse (exit code 1)
mcp-audit scan --fail-on high

# List all detection rules
mcp-audit rules
```

### Example output

```
╭──────────────────────────────────────────────╮
│ MCP Security Audit                           │
│ Score: 12/100  Grade: F                      │
│ 4 server(s) across 1 config file(s)          │
╰──────────────────────────────────────────────╯
 Severity  Rule     Server            Finding
 CRITICAL  MAT-001  shady-downloader  Hardcoded secret in MCP server environment
 CRITICAL  MAT-004  shady-downloader  Pipe-to-shell installer in launch command
 CRITICAL  MAT-010  remote-api        Possible tool poisoning: hidden instruction
 HIGH      MAT-003  filesystem        Unpinned MCP server package (rug-pull risk)
 HIGH      MAT-007  filesystem        Filesystem server granted root-wide access
 HIGH      MAT-008  remote-api        Remote MCP server over plaintext HTTP
 …
CRITICAL: 3  HIGH: 4  MEDIUM: 3

Top remediations
  • MAT-001 Move the credential to a secrets manager. Rotate the exposed secret immediately.
  • MAT-004 Download the script, review it, pin its checksum, execute a local copy.
  • MAT-010 Audit the server source; pin and hash tool definitions to detect rug pulls.
```

## 🧭 Auto-discovered configs

| Client | macOS | Linux | Windows |
|---|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/…` | `%APPDATA%\Claude\…` |
| Cursor | `~/.cursor/mcp.json` | ✓ | ✓ |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | — | — |
| Cline (VS Code) | `…/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | ✓ | ✓ |
| Zed | `~/.config/zed/settings.json` | ✓ | — |
| Project-level | `.vscode/mcp.json`, `.cursor/mcp.json`, `.mcp.json`, `mcp.json` | ✓ | ✓ |

## 🧪 Detection rules

| ID | Rule | Severity | CWE |
|---|---|---|---|
| MAT-001 | Hardcoded secret in server `env` (OpenAI/Anthropic/GitHub/AWS/Slack/Google keys, private keys) | 🔴 CRITICAL | CWE-798 |
| MAT-002 | Sensitive host env var passed through to the server process | 🔴 HIGH | CWE-200 |
| MAT-003 | Unpinned `npx`/`uvx`/`pipx` package — rug-pull & supply-chain risk | 🔴 HIGH | CWE-1357 |
| MAT-004 | `curl`/`wget` piped to shell — installer spoofing / RCE | 🔴 CRITICAL | CWE-494 |
| MAT-005 | Dangerous launch commands (`rm -rf`, `sudo`, `chmod 777`, `eval`) | 🔴 HIGH | CWE-78 |
| MAT-006 | Shell `-c` wrapper — command-injection surface | 🟡 MEDIUM | CWE-78 |
| MAT-007 | Filesystem server rooted at `/`, `~`, or `$HOME` | 🔴 HIGH | CWE-22 |
| MAT-008 | Remote MCP server over plaintext HTTP | 🔴 HIGH | CWE-319 |
| MAT-009 | Remote MCP server with no authentication configured | 🟡 MEDIUM | CWE-306 |
| MAT-010 | Tool-poisoning indicators in descriptions (hidden instructions) | 🔴 CRITICAL | CWE-74 |
| MAT-011 | Destructive tools on the auto-approve list (no human confirmation) | 🟡 MEDIUM | CWE-862 |
| MAT-012 | Wildcard `*` permissions | 🟡 MEDIUM | CWE-732 |

## 🤖 GitHub Actions & CI

Gate pull requests on MCP config security and surface findings in the **Security** tab:

```yaml
name: MCP Security Audit
on: [push, pull_request]

permissions:
  security-events: write

jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pipx install git+https://github.com/graygnatconsole/mcp-audit-tool.git
      - name: Audit MCP configs
        run: mcp-audit scan .vscode/mcp.json .cursor/mcp.json --format sarif --output results.sarif
      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding at or above `--fail-on` threshold |
| `1` | Findings at or above the `--fail-on` severity |
| `2` | Usage error (missing file, parse error, bad options) |

## 🗺️ Roadmap

- [ ] Live server probing — enumerate real `tools/list` over stdio/SSE and diff against pinned hashes (rug-pull detection at runtime)
- [ ] Prompt-injection classifier for tool descriptions (ML-based, optional extra)
- [ ] `mcp-audit fix` — auto-remediate unpinned packages and over-broad paths
- [ ] Baseline & diff mode (`--baseline`) to alert on config drift
- [ ] Pre-commit hook and Homebrew formula
- [ ] Community rule packs (`--ruleset`)

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## 🤝 Related projects

Part of a growing MCP security ecosystem — also check out:

- [invariantlabs/mcp-scan](https://github.com/invariantlabs/mcp-scan) — runtime proxy scanning for tool poisoning
- [qianniuspace/mcp-security-audit](https://github.com/qianniuspace/mcp-security-audit) — MCP security audit research
- [apisec-inc/mcp-audit](https://github.com/apisec-inc/mcp-audit) — API-security-focused MCP auditing
- [ModelContextProtocol-Security/mcpserver-audit](https://github.com/ModelContextProtocol-Security/mcpserver-audit) — CSA initiative for auditing MCP server source code

## 📄 License

[MIT](LICENSE) © GrayGnatConsole — use it, fork it, ship it.

---

<div align="center">

**If mcp-audit-tool caught something nasty in your config, ⭐ star the repo — it helps others find it too.**

`mcp security` · `model context protocol audit` · `mcp scanner` · `mcp vulnerability scanner` · `ai agent security` · `llm security tool` · `tool poisoning detection` · `mcp rug pull` · `claude desktop security` · `cursor mcp security` · `supply chain security ai` · `prompt injection scanner` · `sarif security scanner` · `devsecops ai agents`

</div>
