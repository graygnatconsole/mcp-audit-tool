# Contributing to mcp-audit-tool

Thanks for helping make the MCP ecosystem safer. 🛡️

## Development setup

```bash
git clone https://github.com/graygnatconsole/mcp-audit-tool.git
cd mcp-audit-tool
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Adding a new audit rule

1. Pick the next `MAT-XXX` id and register it in `src/mcp_audit_tool/rules/__init__.py`.
2. Implement the rule in the matching module (`secrets.py`, `supply_chain.py`,
   `execution.py`, `transport.py`, or `metadata.py`). A rule is a function
   `(server_name, config, source_file) -> list[Finding]`.
3. Give every finding a concrete `remediation` and, where possible, a CWE id.
4. Add a fixture case in `tests/fixtures/` and assertions in `tests/`.
5. Document the rule in the README rules table.

## Pull requests

- Keep changes focused; one rule or fix per PR.
- Run `ruff check src tests` and `pytest` before pushing.
- Describe the attack scenario your rule detects — real-world references welcome.
