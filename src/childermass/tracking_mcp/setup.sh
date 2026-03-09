#!/usr/bin/env bash
#
# Childermass Tracking MCP Server – Setup Script
#
# Usage:
#   cd /Users/ondrej.levy/Agents/Home
#   ./src/childermass/tracking_mcp/setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"

echo "=== Childermass Tracking MCP – Setup ==="
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

# 4. Tracking database directory
TRACKING_DIR="$HOUSTON_DIR/tracking"
mkdir -p "$TRACKING_DIR"
chmod 700 "$TRACKING_DIR"
echo "✓ Tracking database directory: $TRACKING_DIR"

# 5. Test imports
echo ""
echo "→ Testing module imports..."
PYTHONPATH="$PROJECT_ROOT/src" python3 -c "
from childermass.tracking_mcp import __version__
from childermass.tracking_mcp.security import SecurityError, rate_limiter, audit_log
from childermass.tracking_mcp.auth import get_db_path
from childermass.tracking_mcp.client import get_client
from childermass.tracking_mcp.server import mcp
print(f'✓ All modules loaded (v{__version__})')
"

# 6. Initialize database
echo ""
echo "→ Initializing database..."
PYTHONPATH="$PROJECT_ROOT/src" python3 -c "
from childermass.tracking_mcp.client import get_client
client = get_client()
print('✓ Database initialized')
"

# 7. Summary
echo ""
echo "=== Setup Complete ==="
echo ""
echo "  Database: $TRACKING_DIR/tracking.sqlite"
echo ""
echo "Next steps:"
echo "  1. Enable in OpenCode (.opencode/opencode.json):"
echo '     "tracking": { "enabled": true }'
echo ""
echo "  2. Run tests:"
echo "     PYTHONPATH=$PROJECT_ROOT/src pytest $SCRIPT_DIR/tests/ -v"
echo ""
