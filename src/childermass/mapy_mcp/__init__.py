"""Childermass Mapy.com MCP - Mapy.com REST API integration for smart home and personal assistant.

Provides geocoding, route planning, elevation, and timezone lookups
via the Mapy.com REST API (https://developer.mapy.com/).
"""

from .client import MapyClient
from .server import mcp


__version__ = "1.0.0"
__author__ = "Childermass Team"
__description__ = "MCP server for Mapy.com geocoding, routing, elevation and timezone"

__all__ = ["MapyClient", "__version__", "mcp"]
