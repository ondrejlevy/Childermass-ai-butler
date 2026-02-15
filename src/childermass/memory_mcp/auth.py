"""Configuration management for Childermass Memory MCP.

This module handles CLI tools for memory database administration and export.
Environment configuration has been moved to env.py to avoid circular imports.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from .env import configure_environment, get_db_path


# Config directory for settings
CONFIG_DIR = Path.home() / ".childermass"


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""


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
