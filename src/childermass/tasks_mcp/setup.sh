#!/usr/bin/env bash
#
# Childermass Tasks MCP Server – Setup Script
#
# Usage:
#   cd /Users/ondrej.levy/Agents/Home
#   ./src/childermass/tasks_mcp/setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"

echo "=== Childermass Tasks MCP – Setup ==="
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
pip install --quiet --upgrade pip==24.3.1
pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
echo "✓ Dependencies installed"

# 3. Childermass directory
HOUSTON_DIR="$HOME/.childermass"
mkdir -p "$HOUSTON_DIR"
chmod 700 "$HOUSTON_DIR"
echo "✓ Config directory: $HOUSTON_DIR"

# 4. Check OAuth credentials
CREDS_FILE="$HOUSTON_DIR/tasks-credentials.json"
if [ ! -f "$CREDS_FILE" ]; then
    echo ""
    echo "⚠  OAuth credentials not found at $CREDS_FILE"
    echo ""
    echo "   To set up Google Tasks API access:"
    echo "   1. Go to https://console.cloud.google.com/"
    echo "   2. Create a project (or use existing) and enable Google Tasks API"
    echo "   3. Create OAuth 2.0 credentials (Desktop app type)"
    echo "   4. Download the JSON and save to:"
    echo "      $CREDS_FILE"
    echo ""
else
    chmod 600 "$CREDS_FILE"
    echo "✓ OAuth credentials: $CREDS_FILE"
fi

# 5. Keyring check
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

# 6. Test import
echo ""
echo "→ Testing module imports..."
PYTHONPATH="$PROJECT_ROOT/src" python3 -c "
from childermass.tasks_mcp import __version__
from childermass.tasks_mcp.security import SecurityError, rate_limiter, audit_log
from childermass.tasks_mcp.auth import list_authenticated_accounts
from childermass.tasks_mcp.client import get_tasks_service
from childermass.tasks_mcp.server import mcp
print(f'✓ All modules loaded (v{__version__})')
"

# 7. Summary
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"

if [ -f "$CREDS_FILE" ]; then
    echo "  1. Authenticate:"
    echo "     PYTHONPATH=$PROJECT_ROOT/src python3 -m childermass.tasks_mcp.auth --account=your@email.com"
    echo ""
    echo "  2. Enable in OpenCode (.opencode/opencode.json):"
    echo '     "tasks": { "enabled": true }'
    echo ""
    echo "  3. Run tests:"
    echo "     PYTHONPATH=$PROJECT_ROOT/src pytest $SCRIPT_DIR/tests/ -v"
else
    echo "  1. Set up OAuth credentials (see instructions above)"
    echo "  2. Then re-run this script"
fi
echo ""
