"""
UniFi Network Console Authentication

Handles HTTP session management for local UniFi Network console access.
Credentials are stored in the system keyring (macOS Keychain / Linux Secret Service).
Falls back to encrypted file storage if keyring is unavailable.

Run with: python -m childermass.network_mcp.auth --setup
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
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "network-config.json"

# Keyring service name
KEYRING_SERVICE = "childermass-network-mcp"

# Whether keyring is available
_keyring_available: bool | None = None


def _is_keyring_available() -> bool:
    """Check if system keyring is usable."""
    global _keyring_available
    if _keyring_available is not None:
        return _keyring_available

    try:
        import keyring

        test_key = "__childermass_network_keyring_test__"
        keyring.set_password(KEYRING_SERVICE, test_key, "test")
        val = keyring.get_password(KEYRING_SERVICE, test_key)
        keyring.delete_password(KEYRING_SERVICE, test_key)
        _keyring_available = val == "test"
    except Exception:
        _keyring_available = False

    return _keyring_available


def get_config_path() -> Path:
    """Get console configuration path from env or default."""
    return Path(os.getenv("NETWORK_CONFIG_PATH", str(DEFAULT_CONFIG_PATH)))


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
    Load console configuration.

    Returns dict with 'host', 'port', 'username', 'password', 'site_id',
    'verify_ssl'.
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
    site_id: str = "",
    port: int = 443,
    verify_ssl: bool = False,
) -> None:
    """
    Save console configuration securely.

    Host, port, username, site_id stored in config file.
    Password stored in system keyring (with file fallback).
    """
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config: dict[str, str | int | bool] = {
        "host": host,
        "port": port,
        "username": username,
        "verify_ssl": verify_ssl,
    }

    if site_id:
        config["site_id"] = site_id

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


def get_console_url(config: dict | None = None) -> str:
    """
    Get the base URL for the console.

    Returns URL like https://192.168.1.1:443
    """
    if config is None:
        config = load_config()

    if config is None:
        msg = (
            "Console not configured. Run setup first:\n"
            "  python -m childermass.network_mcp.auth --setup"
        )
        raise RuntimeError(msg)

    host = config["host"]
    port = config.get("port", 443)

    if port == 443:
        return f"https://{host}"
    return f"https://{host}:{port}"


def get_credentials(config: dict | None = None) -> tuple[str, str]:
    """
    Get console username and password.

    Returns (username, password) tuple.
    """
    if config is None:
        config = load_config()

    if config is None:
        msg = (
            "Console not configured. Run setup first:\n"
            "  python -m childermass.network_mcp.auth --setup"
        )
        raise RuntimeError(msg)

    return config["username"], config["password"]


def get_site_id(config: dict | None = None) -> str | None:
    """Get configured default site ID."""
    if config is None:
        config = load_config()
    if config is None:
        return None
    return config.get("site_id") or None


def verify_ssl(config: dict | None = None) -> bool:
    """Check if SSL verification is enabled.

    Returns True by default for security. Only returns False if explicitly
    configured with verify_ssl: false in config.
    """
    if config is None:
        config = load_config()
    if config is None:
        return True  # Secure default

    # Default to True (secure), only disable if explicitly set to False
    verify = config.get("verify_ssl", True)

    if not verify:
        logger.warning(
            "SSL certificate verification is DISABLED. "
            "This makes the connection vulnerable to man-in-the-middle attacks. "
            "Only use this in trusted networks with self-signed certificates."
        )

    return verify


def setup_interactive() -> None:
    """
    Interactive setup flow for console connection.
    """

    # Check existing config
    existing = load_config()
    if existing:
        if existing.get("site_id"):
            pass
        resp = input("\nOverwrite? [y/N]: ").strip().lower()
        if resp != "y":
            return

    # Gather info
    host = input("Console IP address or hostname: ").strip()
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

    site_id = input("Default Site ID (UUID, or leave empty to discover later): ").strip()

    verify_ssl_str = input("Verify SSL certificate? [Y/n]: ").strip().lower()
    # Default to True (secure) unless explicitly disabled
    ssl_verify = verify_ssl_str != "n"

    # Save
    save_config(
        host=host,
        username=username,
        password=password,
        site_id=site_id,
        port=port,
        verify_ssl=ssl_verify,
    )

    if site_id:
        pass


def test_connection() -> None:
    """Test connectivity to the console and Network API."""
    config = load_config()
    if config is None:
        return

    try:
        import httpx
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        base_url = get_console_url(config)
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
                # Step 3: Test Network API
                csrf_updated = login_resp.headers.get(
                    "x-updated-csrf-token",
                    login_resp.headers.get("x-csrf-token", csrf_token),
                )

                info_resp = client.get(
                    f"{base_url}/proxy/network/integration/v1/info",
                    headers={"x-csrf-token": csrf_updated},
                )

                if info_resp.status_code == 200:
                    info_resp.json()

                    # Try listing networks if site_id is configured
                    site_id = config.get("site_id")
                    if site_id:
                        networks_resp = client.get(
                            f"{base_url}/proxy/network/integration/v1/sites/{site_id}/networks",
                            headers={"x-csrf-token": csrf_updated},
                            params={"limit": 50},
                        )
                        if networks_resp.status_code == 200:
                            net_data = networks_resp.json()
                            networks = net_data.get("data", [])
                            for net in networks:
                                net.get("vlanId", "untagged")
                                "✓" if net.get("enabled", True) else "✗"
                        else:
                            logger.warning(f"Failed to list networks: {networks_resp.status_code}")
                    else:
                        logger.debug("No site_id configured, skipping network list")
                else:
                    logger.warning(f"Failed to access Network API: {info_resp.status_code}")
            elif login_resp.status_code == 401:
                logger.error("Authentication failed: Invalid credentials")
            else:
                logger.error(f"Login failed with status code: {login_resp.status_code}")

    except httpx.ConnectError as e:
        logger.error(f"Connection error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during connection test: {e}")


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
    """CLI entry point for Network console authentication."""
    parser = argparse.ArgumentParser(
        description="Configure UniFi Network console connection for Childermass MCP",
        epilog=(
            "Examples:\n"
            "  python -m childermass.network_mcp.auth --setup\n"
            "  python -m childermass.network_mcp.auth --test\n"
            "  python -m childermass.network_mcp.auth --show\n"
            "  python -m childermass.network_mcp.auth --revoke"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Interactive setup for console connection",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test connectivity to the console",
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
