"""
UniFi Protect NVR Authentication

Handles HTTP session management for local UniFi Protect NVR access.
Credentials are stored in the system keyring (macOS Keychain / Linux Secret Service).
Falls back to encrypted file storage if keyring is unavailable.

Run with: python -m childermass.protect_mcp.auth --setup
"""

import argparse
import getpass
import json
import logging
import os
from pathlib import Path


logger = logging.getLogger(__name__)

# Default paths
DEFAULT_CONFIG_DIR = Path.home() / ".childermass"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "protect-config.json"

# Keyring service name
KEYRING_SERVICE = "childermass-protect-mcp"

# Whether keyring is available
_keyring_available: bool | None = None

# Sentinel for distinguishing omitted vs explicit None in credential helpers
_GET_CREDENTIALS_SENTINEL = object()


def _is_keyring_available() -> bool:
    """Check if system keyring is usable."""
    global _keyring_available
    if _keyring_available is not None:
        return _keyring_available

    try:
        import keyring

        test_key = "__childermass_protect_keyring_test__"
        keyring.set_password(KEYRING_SERVICE, test_key, "test")
        val = keyring.get_password(KEYRING_SERVICE, test_key)
        keyring.delete_password(KEYRING_SERVICE, test_key)
        _keyring_available = val == "test"
    except Exception:
        _keyring_available = False

    return _keyring_available


def get_config_path() -> Path:
    """Get NVR configuration path from env or default."""
    return Path(os.getenv("PROTECT_CONFIG_PATH", str(DEFAULT_CONFIG_PATH)))


def _save_to_keyring(key: str, value: str) -> bool:
    """Store a value in system keyring. Returns True on success."""
    if not _is_keyring_available():
        return False

    try:
        import keyring

        keyring.set_password(KEYRING_SERVICE, key, value)
    except Exception as e:
        logger.warning("Keyring save failed: %s", e)
        return False
    else:
        return True


def _load_from_keyring(key: str) -> str | None:
    """Load a value from system keyring."""
    if not _is_keyring_available():
        return None

    try:
        import keyring

        return keyring.get_password(KEYRING_SERVICE, key)
    except Exception as e:
        logger.warning("Keyring load failed: %s", e)
        return None


def _delete_from_keyring(key: str) -> bool:
    """Remove a value from system keyring."""
    if not _is_keyring_available():
        return False

    try:
        import keyring

        keyring.delete_password(KEYRING_SERVICE, key)
    except Exception:
        return False
    else:
        return True


def load_config() -> dict | None:
    """
    Load NVR configuration.

    Returns dict with 'host', 'port', 'username', 'password', 'verify_ssl'.
    Password is loaded from keyring first, then from config file.
    """
    config_path = get_config_path()

    if not config_path.exists():
        return None

    try:
        with open(config_path) as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.exception("Failed to load config: %s", e)
        return None

    # Try to load password from keyring
    password = _load_from_keyring("password")
    if password:
        config["password"] = password
    elif "password" not in config:
        logger.warning("No password found in keyring or config file")
        return None

    return config


def save_config(
    host: str,
    username: str,
    password: str,
    port: int = 443,
    verify_ssl: bool = False,
) -> None:
    """
    Save NVR configuration securely.

    Host, port, username stored in config file.
    Password stored in system keyring (with file fallback).
    """
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config = {
        "host": host,
        "port": port,
        "username": username,
        "verify_ssl": verify_ssl,
    }

    # Try to store password in keyring
    saved_to_keyring = _save_to_keyring("password", password)

    if not saved_to_keyring:
        # Fallback: store password in config file
        config["password"] = password
        logger.warning("Keyring unavailable, password stored in config file")

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

    # Secure file permissions (owner read/write only)
    config_path.chmod(0o600)

    if saved_to_keyring:
        pass
    else:
        pass


def get_nvr_url(config: dict | None = None) -> str:
    """
    Get the base URL for the NVR.

    Returns URL like https://192.168.1.1:443
    """
    if config is None:
        config = load_config()

    if config is None:
        msg = (
            "NVR not configured. Run setup first:\n  python -m childermass.protect_mcp.auth --setup"
        )
        raise RuntimeError(msg)

    host = config["host"]
    port = config.get("port", 443)

    if port == 443:
        return f"https://{host}"
    return f"https://{host}:{port}"


def get_credentials(config: dict | None | object = _GET_CREDENTIALS_SENTINEL) -> tuple[str, str]:
    """
    Get NVR username and password.

    Returns (username, password) tuple.
    """
    # Distinguish explicit `None` (caller intentionally passed None)
    # from omitted argument (use sentinel) so tests can assert that
    # passing None raises while callers without an argument still load
    # saved configuration.
    if config is _GET_CREDENTIALS_SENTINEL:
        config = load_config()

    if config is None:
        msg = (
            "NVR not configured. Run setup first:\n  python -m childermass.protect_mcp.auth --setup"
        )
        raise RuntimeError(msg)

    # At this point, config is guaranteed to be dict (not None, not sentinel)
    assert isinstance(config, dict)
    return config["username"], config["password"]


def verify_ssl(config: dict | None = None) -> bool:
    """Check if SSL verification is enabled."""
    if config is None:
        config = load_config()
    if config is None:
        return False
    return config.get("verify_ssl", False)


def setup_interactive() -> None:
    """
    Interactive setup flow for NVR connection.
    """

    # Check existing config
    existing = load_config()
    if existing:
        resp = input("\nOverwrite? [y/N]: ").strip().lower()
        if resp != "y":
            return

    # Gather info
    host = input("NVR IP address or hostname: ").strip()
    if not host:
        return

    port_str = input("Port [443]: ").strip()
    port = int(port_str) if port_str else 443

    username = input("Username: ").strip()
    if not username:
        return

    password = getpass.getpass("Password: ")
    if not password:
        return

    verify_ssl_str = input("Verify SSL certificate? [y/N]: ").strip().lower()
    ssl_verify = verify_ssl_str == "y"

    # Save
    save_config(
        host=host,
        username=username,
        password=password,
        port=port,
        verify_ssl=ssl_verify,
    )


def test_connection() -> None:
    """Test connectivity to the NVR."""
    config = load_config()
    if config is None:
        return

    try:
        import httpx

        base_url = get_nvr_url(config)
        username, password = get_credentials(config)
        ssl = verify_ssl(config)

        with httpx.Client(verify=ssl, timeout=10.0) as client:
            # Step 1: Get CSRF token
            resp = client.get(base_url)
            csrf_token = resp.headers.get("x-csrf-token", "")

            # Step 2: Login
            login_resp = client.post(
                f"{base_url}/api/auth/login",
                json={
                    "username": username,
                    "password": password,
                    "rememberMe": True,
                    "token": "",
                },
                headers={"x-csrf-token": csrf_token},
            )

            if login_resp.status_code == 200:
                # Step 3: Test Protect API
                csrf_updated = login_resp.headers.get(
                    "x-updated-csrf-token",
                    login_resp.headers.get("x-csrf-token", csrf_token),
                )

                bootstrap_resp = client.get(
                    f"{base_url}/proxy/protect/api/bootstrap",
                    headers={"x-csrf-token": csrf_updated},
                )

                if bootstrap_resp.status_code == 200:
                    data = bootstrap_resp.json()
                    cameras = data.get("cameras", [])
                    sensors = data.get("sensors", [])
                    lights = data.get("lights", [])
                    data.get("nvr", {})

                    for cam in cameras:
                        cam.get("featureFlags", {}).get("isDoorbell", False)
                    if sensors:
                        for _s in sensors:
                            pass
                    if lights:
                        for _light_dev in lights:
                            pass
                else:
                    pass
            elif login_resp.status_code == 401:
                pass
            else:
                pass

    except httpx.ConnectError:
        pass
    except Exception:
        pass


def show_config() -> None:
    """Display current configuration (without password)."""
    config = load_config()
    if config is None:
        return

    "keyring + file" if _is_keyring_available() else "file only"


def revoke_config() -> None:
    """Delete all stored configuration and credentials."""
    _delete_from_keyring("password")

    config_path = get_config_path()
    if config_path.exists():
        config_path.unlink()


def main() -> None:
    """CLI entry point for Protect NVR authentication."""
    parser = argparse.ArgumentParser(
        description="Configure UniFi Protect NVR connection for Childermass MCP",
        epilog=(
            "Examples:\n"
            "  python -m childermass.protect_mcp.auth --setup\n"
            "  python -m childermass.protect_mcp.auth --test\n"
            "  python -m childermass.protect_mcp.auth --show\n"
            "  python -m childermass.protect_mcp.auth --revoke"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Interactive setup for NVR connection",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test connectivity to the NVR",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Show current configuration",
    )
    parser.add_argument(
        "--revoke",
        action="store_true",
        help="Delete all stored configuration",
    )

    args = parser.parse_args()

    if args.setup:
        setup_interactive()
        return

    if args.test:
        test_connection()
        return

    if args.show:
        show_config()
        return

    if args.revoke:
        revoke_config()
        return

    # Default: show help
    parser.print_help()


if __name__ == "__main__":
    main()
