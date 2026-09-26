#!/usr/bin/env bash
#
# mcp-audit-tool — one-line installer (macOS & Linux)
#
#   curl -fsSL https://raw.githubusercontent.com/graygnatconsole/mcp-audit-tool/main/install.sh | bash
#
set -euo pipefail

REPO="https://github.com/graygnatconsole/mcp-audit-tool.git"
BOLD="$(tput bold 2>/dev/null || true)"
GREEN="$(tput setaf 2 2>/dev/null || true)"
RED="$(tput setaf 1 2>/dev/null || true)"
RESET="$(tput sgr0 2>/dev/null || true)"

info()  { printf "%s==>%s %s\n" "$BOLD" "$RESET" "$1"; }
ok()    { printf "%s✔%s %s\n" "$GREEN" "$RESET" "$1"; }
fail()  { printf "%s✘ %s%s\n" "$RED" "$1" "$RESET" >&2; exit 1; }

# --- 1. Python 3.9+ -----------------------------------------------------------
info "Checking for Python 3.9+..."
PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
      PYTHON="$candidate"
      break
    fi
  fi
done

if [ -z "$PYTHON" ]; then
  if command -v brew >/dev/null 2>&1; then
    info "Installing Python via Homebrew..."
    brew install python@3.12 || fail "Could not install Python."
    PYTHON="python3"
  else
    fail "Python 3.9+ is required. Install it from https://www.python.org/downloads/ and re-run."
  fi
fi
ok "Found $($PYTHON --version)"

# --- 2. pipx (isolated CLI installs) ------------------------------------------
info "Checking for pipx..."
if ! command -v pipx >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    info "Installing pipx via Homebrew..."
    brew install pipx || fail "Could not install pipx."
  else
    info "Installing pipx via pip..."
    "$PYTHON" -m pip install --user pipx || fail "Could not install pipx."
  fi
  "$PYTHON" -m pipx ensurepath >/dev/null 2>&1 || true
fi
ok "pipx is available"

# --- 3. Install mcp-audit-tool -------------------------------------------------
info "Installing mcp-audit-tool from GitHub..."
pipx install --force "git+${REPO}" || fail "Installation failed."
ok "mcp-audit-tool installed"

# --- 4. First run ---------------------------------------------------------------
printf "\n%s🛡  mcp-audit-tool is ready!%s\n" "$BOLD" "$RESET"
printf "Run your first audit:\n\n"
printf "    %smcp-audit scan%s\n\n" "$GREEN" "$RESET"
printf "If 'mcp-audit' is not found, open a new terminal or run: %spipx ensurepath%s\n" "$BOLD" "$RESET"
