"""
Childermass Memory MCP Server

Persistent cognitive memory for the Childermass AI butler.
Uses OpenMemory SDK with local SQLite storage.
Supports both episodic/semantic memory and temporal knowledge graph.

Security: All inputs are validated and rate-limited.
All tool responses go through error sanitization so that
internal paths, SQL, or keys are never leaked to the LLM.

Run with: python -m childermass.memory_mcp.server
"""

from mcp.server.fastmcp import FastMCP

from .client import get_client
from .security import SecurityError, sanitize_error_message

# Create FastMCP server
mcp = FastMCP("childermass-memory")


# ---------------------------------------------------------------------------
# Memory tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def memory_store(
    content: str,
    category: str,
    tags: list[str] | None = None,
) -> dict:
    """
    Store a memory (preference, routine, fact, feedback, or pattern).

    Use this to persist useful information about the household, user
    preferences, learned patterns, or explicit feedback.

    Args:
        content: Text to memorize. Be specific and concise.
        category: One of: preference, routine, fact, feedback, pattern, temporal.
        tags: Optional tags for organization (e.g. ["bedroom", "temperature"]).

    Returns:
        Stored memory info with assigned ID and cognitive sector.

    Examples:
        memory_store("User prefers 21°C in the bedroom at night", "preference", ["bedroom", "temperature"])
        memory_store("Monday garbage collection at 7:00 AM", "routine", ["garbage", "monday"])
        memory_store("User dislikes verbose responses", "feedback", ["communication"])
    """
    try:
        client = get_client()
        return await client.store(content, category, tags)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
async def memory_recall(
    query: str,
    limit: int = 5,
    min_score: float = 0.3,
) -> dict:
    """
    Search memories by semantic similarity.

    Use this to recall relevant memories before making decisions or
    answering questions about the household.

    Args:
        query: Natural language search query.
        limit: Maximum number of results (1-100, default 5).
        min_score: Minimum similarity score 0-1 (default 0.3).

    Returns:
        Matching memories sorted by relevance with scores.

    Examples:
        memory_recall("bedroom temperature preferences")
        memory_recall("what does the user dislike", limit=3)
        memory_recall("morning routines", min_score=0.5)
    """
    try:
        client = get_client()
        return await client.recall(query, limit, min_score)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
async def memory_recall_by_sector(
    sector: str,
    limit: int = 10,
) -> dict:
    """
    Get memories from a specific cognitive sector.

    Sectors represent different types of knowledge:
    - episodic: specific events and experiences
    - semantic: general facts and knowledge
    - procedural: how-to knowledge and procedures
    - emotional: emotional associations and preferences
    - reflective: self-assessments and meta-knowledge

    Args:
        sector: One of: episodic, semantic, procedural, emotional, reflective.
        limit: Maximum number of results (1-100, default 10).

    Returns:
        Memories classified in the specified sector.
    """
    try:
        client = get_client()
        return await client.recall_by_sector(sector, limit)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
async def memory_get(memory_id: str) -> dict:
    """
    Get a specific memory by its ID.

    Args:
        memory_id: The memory identifier.

    Returns:
        Full memory record including content, sector, tags, and metadata.
    """
    try:
        client = get_client()
        return await client.get_memory(memory_id)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
async def memory_list(
    category: str | None = None,
    limit: int = 20,
) -> dict:
    """
    List memories, optionally filtered by Childermass category.

    Args:
        category: Optional filter: preference, routine, fact, feedback, pattern.
        limit: Maximum number of results (1-100, default 20).

    Returns:
        List of memories with their content, sector, and tags.
    """
    try:
        client = get_client()
        return await client.list_memories(category, limit)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
async def memory_forget(memory_id: str) -> dict:
    """
    Delete a specific memory.

    Args:
        memory_id: The memory identifier to delete.

    Returns:
        Confirmation of deletion.
    """
    try:
        client = get_client()
        return await client.forget(memory_id)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Temporal knowledge graph tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def memory_store_fact(
    subject: str,
    predicate: str,
    obj: str,
    valid_from: str,
) -> dict:
    """
    Store a temporal fact (something that is true from a specific date).

    Temporal facts track how things change over time. Each fact has a
    subject, predicate, object, and validity period.

    Args:
        subject: Entity name (e.g. "bedroom", "user", "coffee_machine").
        predicate: Relationship/property (e.g. "preferred_temperature", "wake_up_time").
        obj: Value (e.g. "21°C", "06:30").
        valid_from: Start date in YYYY-MM-DD format.

    Returns:
        Stored fact with assigned ID.

    Examples:
        memory_store_fact("bedroom", "preferred_temperature", "21°C", "2025-01-15")
        memory_store_fact("user", "wake_up_time", "06:30", "2025-03-01")
        memory_store_fact("coffee_machine", "brand", "DeLonghi Magnifica", "2024-06-15")
    """
    try:
        client = get_client()
        return await client.store_temporal_fact(subject, predicate, obj, valid_from)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
async def memory_update_fact(
    subject: str,
    predicate: str,
    new_value: str,
    valid_from: str,
) -> dict:
    """
    Update a temporal fact — marks old value as historical and stores new one.

    The old fact's history is preserved with its validity range.

    Args:
        subject: Entity name (e.g. "bedroom").
        predicate: Relationship/property (e.g. "preferred_temperature").
        new_value: New value (e.g. "22°C").
        valid_from: Start date of new value in YYYY-MM-DD format.

    Returns:
        Updated fact info including previous value.

    Examples:
        memory_update_fact("bedroom", "preferred_temperature", "22°C", "2025-07-01")
        memory_update_fact("user", "wake_up_time", "07:00", "2025-06-15")
    """
    try:
        client = get_client()
        return await client.update_temporal_fact(subject, predicate, new_value, valid_from)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
async def memory_timeline(subject: str) -> dict:
    """
    Get the chronological history of an entity.

    Shows how facts about a subject changed over time.

    Args:
        subject: Entity name to get timeline for.

    Returns:
        Chronological list of facts with validity periods.

    Examples:
        memory_timeline("bedroom")
        memory_timeline("user")
    """
    try:
        client = get_client()
        return await client.get_timeline(subject)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
async def memory_summary() -> dict:
    """
    Get memory system statistics.

    Returns total memory count, sector breakdown, temporal fact count,
    and the 5 most recent memories. Useful for diagnostics and overview.

    Returns:
        Summary statistics about the memory system.
    """
    try:
        client = get_client()
        return await client.get_summary()
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
