"""Configuration management for Childermass Memory MCP.

This module handles database path configuration, embedding provider setup,
and CLI tools for memory database administration.
"""

import argparse
import json
import os
import sys
from pathlib import Path


# Default paths
MODULE_DIR = Path(__file__).parent
DATA_DIR = MODULE_DIR / "data"
DEFAULT_DB_PATH = DATA_DIR / "memory.sqlite"
CONFIG_DIR = Path.home() / ".childermass"


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""


def get_db_path() -> Path:
    """Get the database file path.

    Priority:
    1. HOUSTON_MEMORY_DB_PATH environment variable
    2. Default: <module>/data/memory.sqlite

    Returns:
        Path: Path to the SQLite database file.
    """
    env_path = os.environ.get("HOUSTON_MEMORY_DB_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_DB_PATH


def get_db_url() -> str:
    """Get the database URL for OpenMemory SDK.

    Returns:
        str: SQLite URL string.
    """
    db_path = get_db_path()
    return f"sqlite:///{db_path}"


def ensure_data_dir() -> None:
    """Create the data directory if it doesn't exist."""
    data_dir = get_db_path().parent
    data_dir.mkdir(parents=True, exist_ok=True)


def configure_environment() -> None:
    """Set environment variables for OpenMemory SDK.

    Must be called BEFORE importing the OpenMemory SDK,
    as the SDK reads env vars at module import time.
    """
    os.environ.setdefault("OM_DB_URL", get_db_url())
    os.environ.setdefault("OM_EMBEDDINGS", "synthetic")
    os.environ.setdefault("OM_TIER", "smart")

    ensure_data_dir()


def get_config() -> dict:
    """Get current configuration as a dictionary.

    Returns:
        dict: Configuration details.
    """
    db_path = get_db_path()
    return {
        "db_path": str(db_path),
        "db_exists": db_path.exists(),
        "db_size_bytes": db_path.stat().st_size if db_path.exists() else 0,
        "embeddings": os.environ.get("OM_EMBEDDINGS", "synthetic"),
        "tier": os.environ.get("OM_TIER", "smart"),
        "data_dir": str(db_path.parent),
    }


def export_memories(output_path: str) -> None:
    """Export all memories to a JSON file for backup.

    Args:
        output_path: Path to the output JSON file.
    """
    configure_environment()

    try:
        import asyncio

        from .client import get_client

        client = get_client()

        async def _export():
            return await client.list_all(limit=10000)

        all_memories = asyncio.run(_export())

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(all_memories, f, ensure_ascii=False, indent=2, default=str)

    except Exception:
        sys.exit(1)


def main():
    """CLI for managing Childermass Memory MCP configuration."""
    parser = argparse.ArgumentParser(
        description="Manage Childermass Memory MCP configuration and data"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--info", action="store_true", help="Show current configuration and database info"
    )
    group.add_argument("--export", metavar="FILE", help="Export all memories to JSON file")

    args = parser.parse_args()

    try:
        if args.info:
            configure_environment()
            config = get_config()
            if config["db_exists"]:
                config["db_size_bytes"] / 1024
        elif args.export:
            export_memories(args.export)
    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    main()
