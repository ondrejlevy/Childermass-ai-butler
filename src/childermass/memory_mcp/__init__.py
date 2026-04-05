"""Childermass Memory MCP - Persistent long-term memory for the Childermass AI butler system."""

__version__ = "1.0.0"
__author__ = "Childermass Team"
__description__ = (
    "MCP server for persistent memory storage, semantic recall, and temporal knowledge graph"
)


def __getattr__(name: str):
    """Lazy-load server exports so package imports don't pull runtime-only dependencies."""
    if name == "mcp":
        from .server import mcp

        return mcp
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


__all__ = ["__version__", "mcp"]
