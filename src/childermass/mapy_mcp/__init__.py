"""Childermass Mapy.com MCP - Mapy.com REST API integration for smart home and personal assistant.

Provides geocoding, route planning, elevation, and timezone lookups
via the Mapy.com REST API (https://developer.mapy.com/).
"""

__version__ = "1.0.0"
__author__ = "Childermass Team"
__description__ = "MCP server for Mapy.com geocoding, routing, elevation and timezone"


def __getattr__(name: str):
    """Lazy imports to avoid circular / double-import issues with ``python -m``."""
    if name == "mcp":
        from .server import mcp

        return mcp
    if name == "MapyClient":
        from .client import MapyClient

        return MapyClient
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


__all__ = ["MapyClient", "__version__", "mcp"]
