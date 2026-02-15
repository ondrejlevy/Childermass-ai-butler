#!/usr/bin/env bash
#
# Childermass UniFi Protect MCP Server – Setup Script
#
# Usage:
#   cd /Users/ondrej.levy/Agents/Home
#   ./src/childermass/protect_mcp/setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"

echo "=== Childermass UniFi Protect MCP – Setup ==="
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

# 4. Check existing configuration
CONFIG_FILE="$HOUSTON_DIR/protect-config.json"
if [ -f "$CONFIG_FILE" ]; then
    chmod 600 "$CONFIG_FILE"
    echo "✓ NVR configuration: $CONFIG_FILE"
else
    echo ""
    echo "⚠  NVR configuration not found at $CONFIG_FILE"
    echo ""
    echo "   Run interactive setup:"
    echo "   source venv/bin/activate"
    echo "   PYTHONPATH=src python -m childermass.protect_mcp.auth --setup"
    echo ""
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
    print('✓ System keyring available – credentials will be stored securely')
except Exception:
    print('⚠  System keyring not available – credentials stored in config file (chmod 600)')
" 2>/dev/null; then
    true
else
    echo "⚠  Keyring check failed – credentials will be stored in config file"
fi

# 6. Test import
echo ""
echo "→ Testing module imports..."
PYTHONPATH="$PROJECT_ROOT/src" python3 -c "
from childermass.protect_mcp import __version__
from childermass.protect_mcp.security import SecurityError, rate_limiter, audit_log
from childermass.protect_mcp.auth import load_config, get_nvr_url
from childermass.protect_mcp.server import mcp
print(f'✓ All modules loaded (v{__version__})')
print(f'✓ MCP server name: {mcp.name}')
tools = [t.name for t in mcp._tool_manager.list_tools()]
print(f'✓ Tools registered: {len(tools)}')
for name in sorted(tools):
    print(f'  - {name}')
"

echo ""
echo "=== Setup complete! ==="
echo ""
echo "Next steps:"
echo "  1. Configure NVR connection:"
echo "     PYTHONPATH=src python -m childermass.protect_mcp.auth --setup"
echo ""
echo "  2. Test connectivity:"
echo "     PYTHONPATH=src python -m childermass.protect_mcp.auth --test"
echo ""
echo "  3. Enable in OpenCode (.opencode/opencode.json):"
echo '     "protect": {'
echo '       "type": "stdio",'
echo '       "command": "python",'
echo '       "args": ["-m", "childermass.protect_mcp.server"],'
echo '       "env": {"PYTHONPATH": "src"},'
echo '       "enabled": true'
echo '     }'
echo ""
echo "  4. Run tests:"
echo "     PYTHONPATH=src pytest src/childermass/protect_mcp/tests/ -v"
