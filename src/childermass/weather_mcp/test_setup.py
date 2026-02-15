#!/usr/bin/env python3
"""Test script to verify Weather MCP setup and API key."""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent.parent.parent / "src"
sys.path.insert(0, str(src_path))

print("=" * 60)
print("Childermass Weather MCP - Test Script")
print("=" * 60)
print()

# Test 1: Import modules
print("Test 1: Importing modules...")
try:
    from childermass.weather_mcp.auth import get_api_key
    from childermass.weather_mcp.client import get_client
    from childermass.weather_mcp.security import SecurityError
    print("✓ Modules imported successfully")
except ImportError as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)

print()

# Test 2: Check API key
print("Test 2: Checking API key...")
try:
    api_key = get_api_key()
    print(f"✓ API key found: {api_key[:8]}...{api_key[-4:]}")
except Exception as e:
    print(f"✗ API key check failed: {e}")
    sys.exit(1)

print()

# Test 3: Test weather API
print("Test 3: Testing OpenWeatherMap API...")
print("(This will fail if your API key is not activated yet)")
print()

try:
    client = get_client()
    weather = client.get_current_weather('London', 'metric')
    
    print("✓ API test SUCCESSFUL!")
    print()
    print(f"  Location: {weather.location_name}")
    print(f"  Temperature: {weather.temperature}°C")
    print(f"  Feels like: {weather.feels_like}°C")
    print(f"  Conditions: {weather.conditions[0].description if weather.conditions else 'Unknown'}")
    print(f"  Humidity: {weather.humidity}%")
    print(f"  Wind speed: {weather.wind_speed} m/s")
    print(f"  Pressure: {weather.pressure} hPa")
    print()
    print("=" * 60)
    print("✓ All tests passed! Weather MCP is ready to use.")
    print("=" * 60)
    
except SecurityError as e:
    error_msg = str(e)
    if "Invalid API key" in error_msg or "401" in error_msg:
        print("✗ API key authentication failed")
        print()
        print("This usually means:")
        print("  1. Your API key is not activated yet (can take up to 2 hours)")
        print("  2. The API key is invalid")
        print()
        print("Next steps:")
        print("  • Wait a few hours if you just created the API key")
        print("  • Check your API key at: https://home.openweathermap.org/api_keys")
        print("  • Verify the key in your account matches the stored key")
        print()
        sys.exit(1)
    else:
        print(f"✗ API test failed: {e}")
        sys.exit(1)

except Exception as e:
    print(f"✗ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
