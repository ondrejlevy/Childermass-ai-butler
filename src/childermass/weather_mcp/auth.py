"""Authentication management for Childermass Weather MCP.

This module handles secure storage and retrieval of OpenWeatherMap API keys
using keyring (for macOS Keychain, Windows Credential Manager, etc.) with
file-based fallback for systems without keyring support.
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False


KEYRING_SERVICE = "childermass-weather"
KEYRING_USERNAME = "api_key"
CONFIG_DIR = Path.home() / ".childermass"
API_KEY_FILE = CONFIG_DIR / "weather_api_key"


class AuthenticationError(Exception):
    """Raised when authentication configuration is invalid or missing."""
    pass


def get_api_key() -> str:
    """Get OpenWeatherMap API key from keyring or file.
    
    Returns:
        str: The API key.
        
    Raises:
        AuthenticationError: If no API key is configured.
    """
    # Try keyring first
    if KEYRING_AVAILABLE:
        try:
            api_key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            if api_key:
                return api_key
        except Exception as e:
            print(f"Warning: Failed to read from keyring: {e}", file=sys.stderr)
    
    # Fallback to file
    if API_KEY_FILE.exists():
        try:
            api_key = API_KEY_FILE.read_text().strip()
            if api_key:
                return api_key
        except Exception as e:
            print(f"Warning: Failed to read API key from file: {e}", file=sys.stderr)
    
    raise AuthenticationError(
        "No OpenWeatherMap API key configured. "
        "Run: python -m childermass.weather_mcp.auth --set-api-key YOUR_KEY\n"
        "Get a free API key at: https://openweathermap.org/api"
    )


def set_api_key(api_key: str) -> None:
    """Store OpenWeatherMap API key in keyring and/or file.
    
    Args:
        api_key: The API key to store.
        
    Raises:
        ValueError: If api_key is empty or invalid format.
    """
    if not api_key or not api_key.strip():
        raise ValueError("API key cannot be empty")
    
    api_key = api_key.strip()
    
    # Basic validation - OpenWeatherMap keys are 32 character hex strings
    if len(api_key) != 32 or not all(c in "0123456789abcdef" for c in api_key.lower()):
        print("Warning: API key format looks unusual (expected 32 hex characters)", file=sys.stderr)
    
    # Store in keyring if available
    if KEYRING_AVAILABLE:
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, api_key)
            print(f"✓ API key stored in system keyring (service: {KEYRING_SERVICE})")
        except Exception as e:
            print(f"Warning: Failed to store in keyring: {e}", file=sys.stderr)
            print("Will use file storage only", file=sys.stderr)
    else:
        print("Note: keyring not available, using file storage only", file=sys.stderr)
    
    # Always store in file as backup
    _store_in_file(api_key)


def _store_in_file(api_key: str) -> None:
    """Store API key in file with secure permissions.
    
    Args:
        api_key: The API key to store.
    """
    # Create config directory if needed
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    # Write API key
    API_KEY_FILE.write_text(api_key + "\n")
    
    # Set secure permissions (owner read/write only)
    os.chmod(API_KEY_FILE, 0o600)
    
    print(f"✓ API key stored in {API_KEY_FILE} (permissions: 600)")


def delete_api_key() -> None:
    """Remove API key from keyring and file."""
    deleted_any = False
    
    # Remove from keyring
    if KEYRING_AVAILABLE:
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
            print("✓ Removed API key from system keyring")
            deleted_any = True
        except keyring.errors.PasswordDeleteError:
            pass  # Not found in keyring
        except Exception as e:
            print(f"Warning: Failed to remove from keyring: {e}", file=sys.stderr)
    
    # Remove file
    if API_KEY_FILE.exists():
        try:
            API_KEY_FILE.unlink()
            print(f"✓ Removed API key file: {API_KEY_FILE}")
            deleted_any = True
        except Exception as e:
            print(f"Warning: Failed to remove file: {e}", file=sys.stderr)
    
    if not deleted_any:
        print("No API key was configured")


def verify_api_key() -> bool:
    """Check if API key is configured and accessible.
    
    Returns:
        bool: True if API key is accessible, False otherwise.
    """
    try:
        api_key = get_api_key()
        print(f"✓ API key configured: {api_key[:8]}...{api_key[-4:]}")
        return True
    except AuthenticationError as e:
        print(f"✗ {e}", file=sys.stderr)
        return False


def main():
    """CLI for managing OpenWeatherMap API key."""
    parser = argparse.ArgumentParser(
        description="Manage OpenWeatherMap API key for Childermass Weather MCP"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--set-api-key",
        metavar="KEY",
        help="Store OpenWeatherMap API key"
    )
    group.add_argument(
        "--verify",
        action="store_true",
        help="Verify API key is configured"
    )
    group.add_argument(
        "--delete",
        action="store_true",
        help="Remove stored API key"
    )
    
    args = parser.parse_args()
    
    try:
        if args.set_api_key:
            set_api_key(args.set_api_key)
            print("\n✓ Setup complete! You can now use the weather MCP server.")
        elif args.verify:
            if verify_api_key():
                sys.exit(0)
            else:
                sys.exit(1)
        elif args.delete:
            delete_api_key()
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
