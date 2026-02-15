#!/usr/bin/env bash
#
# Childermass Mapy.com MCP Server – Setup Script
#
# Usage:
#   cd /Users/ondrej.levy/Agents/Home
#   ./src/childermass/mapy_mcp/setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"

echo "=== Childermass Mapy.com MCP – Setup ==="
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
    print('✓ System keyring available – API key will be stored securely')
except Exception:
    print('⚠  System keyring not available – API key stored as file (chmod 600)')
" 2>/dev/null; then
    true
else
    echo "⚠  Keyring check failed – API key will be stored as file"
fi

# 5. Test imports
echo ""
echo "→ Testing module imports..."
PYTHONPATH="$PROJECT_ROOT/src" python3 -c "
from childermass.mapy_mcp import __version__
from childermass.mapy_mcp.security import SecurityError, rate_limiter
from childermass.mapy_mcp.auth import get_api_key, AuthenticationError
from childermass.mapy_mcp.client import get_client
from childermass.mapy_mcp.server import mcp
print(f'✓ All modules loaded (v{__version__})')
"

# 6. Check API key or prompt for it
echo ""
API_KEY_FILE="$HOUSTON_DIR/mapy_api_key"
API_KEY_EXISTS=false

# Check if API key is already configured
if PYTHONPATH="$PROJECT_ROOT/src" python3 -m childermass.mapy_mcp.auth --verify 2>/dev/null; then
    API_KEY_EXISTS=true
fi

if [ "$API_KEY_EXISTS" = false ]; then
    echo "→ Mapy.com API Key Setup"
    echo ""
    echo "  You need a Mapy.com API key to use this MCP server."
    echo "  Get a free key at: https://developer.mapy.com/account/"
    echo ""
    echo "  Free tier includes:"
    echo "    • 250,000 credits per month"
    echo "    • Geocoding, routing, elevation, timezone"
    echo "    • Map tiles and static maps"
    echo ""

    read -p "  Enter your Mapy.com API key (or press Enter to skip): " API_KEY

    if [ -n "$API_KEY" ]; then
        echo ""
        echo "→ Storing API key securely..."
        PYTHONPATH="$PROJECT_ROOT/src" python3 -m childermass.mapy_mcp.auth --set-api-key "$API_KEY"
    else
        echo ""
        echo "⚠  Skipped API key configuration"
        echo "   Configure later with:"
        echo "   PYTHONPATH=$PROJECT_ROOT/src python3 -m childermass.mapy_mcp.auth --set-api-key YOUR_KEY"
    fi
else
    echo "✓ API key already configured"
fi

# 7. Summary
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo ""
echo "  1. Add to your MCP client configuration:"
echo "     {"
echo '       "mcpServers": {'
echo '         "mapy": {'
echo "           \"command\": \"$PROJECT_ROOT/venv/bin/python\","
echo '           "args": ["-m", "childermass.mapy_mcp.server"],'
echo "           \"cwd\": \"$SCRIPT_DIR\","
echo '           "env": {'
echo "             \"PYTHONPATH\": \"$PROJECT_ROOT/src\""
echo '           }'
echo '         }'
echo '       }'
echo '     }'
echo ""
echo "  2. Run tests:"
echo "     PYTHONPATH=$PROJECT_ROOT/src pytest $SCRIPT_DIR/tests/ -v"
echo ""
