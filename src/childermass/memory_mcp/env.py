"""Environment configuration for Childermass Memory MCP.

This module handles environment variable setup for the OpenMemory SDK.
Separated from auth.py to avoid circular imports with client.py.
"""

import os
from pathlib import Path


# Default paths
MODULE_DIR = Path(__file__).parent
DATA_DIR = MODULE_DIR / "data"
DEFAULT_DB_PATH = DATA_DIR / "memory.sqlite"


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
