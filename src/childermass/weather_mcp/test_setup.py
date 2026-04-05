#!/usr/bin/env python3
"""Test script to verify Weather MCP setup and API key."""

import sys
from pathlib import Path


# Add src to path
src_path = Path(__file__).parent.parent.parent.parent / "src"
sys.path.insert(0, str(src_path))


def main() -> int:
    # Import lazily so pytest collection can import this module without executing setup checks.
    try:
        from childermass.weather_mcp.auth import get_api_key
        from childermass.weather_mcp.client import get_client
        from childermass.weather_mcp.security import SecurityError
    except ImportError:
        return 1

    try:
        get_api_key()
    except Exception:
        return 1

    try:
        client = get_client()
        client.get_current_weather("London", "metric")
    except SecurityError as error:
        error_msg = str(error)
        if "Invalid API key" in error_msg or "401" in error_msg:
            return 1
        return 1
    except Exception:
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
