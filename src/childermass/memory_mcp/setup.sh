#!/usr/bin/env bash
#
# Childermass Memory MCP Server – Setup Script
#
# Usage:
#   cd /Users/ondrej.levy/Agents/Home
#   ./src/childermass/memory_mcp/setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"

echo "=== Childermass Memory MCP – Setup ==="
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

# 3. Data directory
DATA_DIR="$SCRIPT_DIR/data"
mkdir -p "$DATA_DIR"
echo "✓ Data directory: $DATA_DIR"

# 4. Childermass config directory
HOUSTON_DIR="$HOME/.childermass"
mkdir -p "$HOUSTON_DIR"
chmod 700 "$HOUSTON_DIR"
echo "✓ Config directory: $HOUSTON_DIR"

# 5. Verify OpenMemory SDK
echo ""
echo "→ Verifying OpenMemory SDK..."
if python3 -c "
from openmemory.client import Memory
print('✓ OpenMemory SDK available')
" 2>/dev/null; then
    :
else
    echo "⚠ OpenMemory SDK could not be verified. Try:"
    echo "  pip install openmemory-py"
    exit 1
fi

# 6. Test server import
echo "→ Verifying server module..."
if PYTHONPATH="$PROJECT_ROOT/src" python3 -c "
import os
os.environ.setdefault('OM_EMBEDDINGS', 'synthetic')
from childermass.memory_mcp.server import mcp
print('✓ Server module loads correctly')
" 2>/dev/null; then
    :
else
    echo "⚠ Server module failed to load. Check error output."
    exit 1
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To test: PYTHONPATH=$PROJECT_ROOT/src python3 -m pytest $SCRIPT_DIR/tests/ -v"
echo "To run:  PYTHONPATH=$PROJECT_ROOT/src python3 -m childermass.memory_mcp.server"
echo ""
echo "Database will be created at: $DATA_DIR/memory.sqlite"
echo "Audit log: $HOUSTON_DIR/memory-audit.log"
