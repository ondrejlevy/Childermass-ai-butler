"""Childermass Memory MCP - Persistent long-term memory for the Childermass AI butler system."""

__version__ = "1.0.0"
__author__ = "Childermass Team"
__description__ = "MCP server for persistent memory storage, semantic recall, and temporal knowledge graph"

from .server import mcp

__all__ = ["mcp", "__version__"]
