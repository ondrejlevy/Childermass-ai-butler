"""
Tracking MCP Authentication

Minimal auth module – no external API keys required.
The tracking MCP scrapes public tracking pages and stores data locally.

This module provides the auth pattern consistent with other Childermass
MCP servers, handling configuration directory management.
"""

import argparse
import logging
import os
from pathlib import Path


logger = logging.getLogger(__name__)

# Default paths
DEFAULT_CONFIG_DIR = Path.home() / ".childermass"
DEFAULT_DB_DIR = DEFAULT_CONFIG_DIR / "tracking"


class AuthenticationError(Exception):
    """Raised when configuration is invalid or missing."""


def get_config_dir() -> Path:
    """Get the Childermass config directory."""
    config_dir = Path(os.getenv("CHILDERMASS_CONFIG_DIR", str(DEFAULT_CONFIG_DIR)))
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_db_dir() -> Path:
    """Get the tracking database directory."""
    db_dir = Path(os.getenv("TRACKING_DB_DIR", str(DEFAULT_DB_DIR)))
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir


def get_db_path() -> Path:
    """Get the tracking SQLite database path."""
    return get_db_dir() / "tracking.sqlite"


def verify_setup() -> bool:
    """Check if tracking MCP is properly configured.

    Returns:
        bool: True if configuration is valid.
    """
    try:
        db_dir = get_db_dir()
        return db_dir.exists() and db_dir.is_dir()
    except Exception:
        return False


def setup() -> None:
    """Set up tracking MCP directories and database."""
    config_dir = get_config_dir()
    db_dir = get_db_dir()

    config_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(config_dir, 0o700)

    db_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(db_dir, 0o700)


def main() -> None:
    """CLI entry point for tracking MCP setup."""
    parser = argparse.ArgumentParser(
        description="Configure Childermass Tracking MCP",
        epilog=(
            "Examples:\n"
            "  python -m childermass.tracking_mcp.auth --setup\n"
            "  python -m childermass.tracking_mcp.auth --verify\n"
            "  python -m childermass.tracking_mcp.auth --show"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Set up tracking MCP directories",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify configuration is valid",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Show current configuration paths",
    )

    args = parser.parse_args()

    if args.setup:
        setup()
        print("✓ Tracking MCP configured")
        print(f"  Config: {get_config_dir()}")
        print(f"  Database: {get_db_path()}")
        return

    if args.verify:
        if verify_setup():
            print("✓ Tracking MCP configuration is valid")
            print(f"  Database: {get_db_path()}")
        else:
            print("✗ Tracking MCP not configured. Run: --setup")
        return

    if args.show:
        print(f"Config directory: {get_config_dir()}")
        print(f"Database directory: {get_db_dir()}")
        print(f"Database file: {get_db_path()}")
        print(f"Configured: {'yes' if verify_setup() else 'no'}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
