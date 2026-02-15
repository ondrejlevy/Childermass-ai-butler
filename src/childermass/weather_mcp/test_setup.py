#!/usr/bin/env python3
"""Test script to verify Weather MCP setup and API key."""

import sys
from pathlib import Path


# Add src to path
src_path = Path(__file__).parent.parent.parent.parent / "src"
sys.path.insert(0, str(src_path))


# Test 1: Import modules
try:
    from childermass.weather_mcp.auth import get_api_key
    from childermass.weather_mcp.client import get_client
    from childermass.weather_mcp.security import SecurityError
except ImportError:
    sys.exit(1)


# Test 2: Check API key
try:
    api_key = get_api_key()
except Exception:
    sys.exit(1)


# Test 3: Test weather API

try:
    client = get_client()
    weather = client.get_current_weather("London", "metric")


except SecurityError as e:
    error_msg = str(e)
    if "Invalid API key" in error_msg or "401" in error_msg:
        sys.exit(1)
    else:
        sys.exit(1)

except Exception:
    import traceback

    traceback.print_exc()
    sys.exit(1)
