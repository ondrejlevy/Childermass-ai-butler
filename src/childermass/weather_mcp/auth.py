"""Authentication management for Childermass Weather MCP.

This module handles secure storage and retrieval of OpenWeatherMap API keys
using keyring (for macOS Keychain, Windows Credential Manager, etc.) with
file-based fallback for systems without keyring support.
"""

import argparse
import contextlib
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
        except Exception:
            pass

    # Fallback to file
    if API_KEY_FILE.exists():
        try:
            api_key = API_KEY_FILE.read_text().strip()
            if api_key:
                return api_key
        except Exception:
            pass

    msg = (
        "No OpenWeatherMap API key configured. "
        "Run: python -m childermass.weather_mcp.auth --set-api-key YOUR_KEY\n"
        "Get a free API key at: https://openweathermap.org/api"
    )
    raise AuthenticationError(msg)


def set_api_key(api_key: str) -> None:
    """Store OpenWeatherMap API key in keyring and/or file.

    Args:
        api_key: The API key to store.

    Raises:
        ValueError: If api_key is empty or invalid format.
    """
    if not api_key or not api_key.strip():
        msg = "API key cannot be empty"
        raise ValueError(msg)

    api_key = api_key.strip()

    # Basic validation - OpenWeatherMap keys are 32 character hex strings
    if len(api_key) != 32 or not all(c in "0123456789abcdef" for c in api_key.lower()):
        pass

    # Store in keyring if available
    if KEYRING_AVAILABLE:
        with contextlib.suppress(Exception):
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, api_key)
    else:
        pass

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


def delete_api_key() -> None:
    """Remove API key from keyring and file."""
    deleted_any = False

    # Remove from keyring
    if KEYRING_AVAILABLE:
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
            deleted_any = True
        except keyring.errors.PasswordDeleteError:
            pass  # Not found in keyring
        except Exception:
            pass

    # Remove file
    if API_KEY_FILE.exists():
        try:
            API_KEY_FILE.unlink()
            deleted_any = True
        except Exception:
            pass

    if not deleted_any:
        pass


def verify_api_key() -> bool:
    """Check if API key is configured and accessible.

    Returns:
        bool: True if API key is accessible, False otherwise.
    """
    try:
        get_api_key()
    except AuthenticationError:
        return False
    else:
        return True


def main():
    """CLI for managing OpenWeatherMap API key."""
    parser = argparse.ArgumentParser(
        description="Manage OpenWeatherMap API key for Childermass Weather MCP"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--set-api-key", metavar="KEY", help="Store OpenWeatherMap API key")
    group.add_argument("--verify", action="store_true", help="Verify API key is configured")
    group.add_argument("--delete", action="store_true", help="Remove stored API key")

    args = parser.parse_args()

    try:
        if args.set_api_key:
            set_api_key(args.set_api_key)
        elif args.verify:
            if verify_api_key():
                sys.exit(0)
            else:
                sys.exit(1)
        elif args.delete:
            delete_api_key()
    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    main()
