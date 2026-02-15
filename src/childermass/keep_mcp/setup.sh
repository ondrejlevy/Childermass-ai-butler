#!/usr/bin/env bash
#
# Childermass Google Keep MCP Server – Setup Script
#
# Usage:
#   cd /Users/ondrej.levy/Agents/Home
#   ./src/childermass/keep_mcp/setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"

echo "=== Childermass Keep MCP – Setup ==="
echo "Project root: $PROJECT_ROOT"
echo ""

# 1. Virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "→ Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
echo "✓ Virtual environment: $VENV_DIR"

# 2. Dependencies
echo "→ Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
echo "✓ Dependencies installed"

# 3. Childermass directory
HOUSTON_DIR="$HOME/.childermass"
mkdir -p "$HOUSTON_DIR"
chmod 700 "$HOUSTON_DIR"
echo "✓ Config directory: $HOUSTON_DIR"

# 4. Keyring check
echo ""
echo "→ Checking keyring availability..."
if python3 -c "
import keyring
from keyring.errors import NoKeyringError
try:
    keyring.set_password('childermass-test', 'test', 'test')
    keyring.delete_password('childermass-test', 'test')
    print('✓ System keyring available – tokens will be stored securely')
except Exception:
    print('⚠  System keyring not available – tokens stored as files (chmod 600)')
" 2>/dev/null; then
    true
else
    echo "⚠  Keyring check failed – tokens will be stored as files"
fi

# 5. Test import
echo ""
echo "→ Testing module imports..."
PYTHONPATH="$PROJECT_ROOT/src" python3 -c "
from childermass.keep_mcp import __version__
from childermass.keep_mcp.security import SecurityError, rate_limiter, audit_log
from childermass.keep_mcp.auth import list_authenticated_accounts
from childermass.keep_mcp.server import mcp
print(f'✓ All modules loaded (v{__version__})')
"

# 6. Summary
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo ""
echo "  1. Get a master token (see README.md for instructions)"
echo ""
echo "  2. Authenticate:"
echo "     PYTHONPATH=$PROJECT_ROOT/src python3 -m childermass.keep_mcp.auth --account=your@gmail.com"
echo ""
echo "  3. Enable in OpenCode (.opencode/opencode.json):"
echo '     "keep": { "enabled": true }'
echo ""
echo "  4. Run tests:"
echo "     PYTHONPATH=$PROJECT_ROOT/src pytest $SCRIPT_DIR/tests/ -v"
echo ""
