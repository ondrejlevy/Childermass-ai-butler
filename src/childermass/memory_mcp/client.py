"""OpenMemory client wrapper for Childermass Memory MCP.

This module provides a MemoryClient class that wraps the OpenMemory Python SDK
with input validation, rate limiting, and audit logging. It manages a singleton
Memory instance and provides both memory storage/recall and temporal graph operations.
"""

import json
import uuid
from datetime import datetime
from typing import Any

# Configure environment BEFORE importing openmemory
from .auth import configure_environment


configure_environment()

# Import OpenMemory SDK
from openmemory.client import Memory  # noqa: E402
from openmemory.core.db import db as om_db  # noqa: E402

from .security import (  # noqa: E402
    audit_log,
    rate_limiter,
    sanitize_error_message,
    validate_category,
    validate_limit,
    validate_memory_content,
    validate_memory_id,
    validate_predicate,
    validate_query,
    validate_sector,
    validate_subject,
    validate_tags,
    validate_temporal_date,
)


# Default user ID for the Childermass household
DEFAULT_USER_ID = "childermass"

# Temporal graph SQL — implemented directly because the SDK's temporal_graph
# module has a schema mismatch bug (user_id column missing from migration).
_TEMPORAL_INIT_SQL = """
CREATE TABLE IF NOT EXISTS childermass_temporal_facts (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    predicate TEXT NOT NULL,
    object TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    confidence REAL DEFAULT 1.0,
    created_at TEXT NOT NULL,
    metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_htf_subject ON childermass_temporal_facts(subject);
CREATE INDEX IF NOT EXISTS idx_htf_predicate ON childermass_temporal_facts(predicate);
"""


class MemoryClient:
    """Client wrapper for OpenMemory SDK with Childermass-specific logic."""

    def __init__(self):
        """Initialize the memory client."""
        self._memory: Memory | None = None

    @property
    def memory(self) -> Memory:
        """Lazy-initialize the Memory instance."""
        if self._memory is None:
            self._memory = Memory(user=DEFAULT_USER_ID)
            # Initialize temporal facts table
            om_db.conn.executescript(_TEMPORAL_INIT_SQL)
        return self._memory

    # ========================================================================
    # Memory Operations
    # ========================================================================

    async def store(
        self,
        content: str,
        category: str,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Store a new memory.

        Args:
            content: Text content to memorize.
            category: Childermass category (preference, routine, fact, feedback, pattern).
            tags: Optional tags for organization.

        Returns:
            dict: Store result with memory ID and sector classification.

        Raises:
            SecurityError: If input validation fails.
        """
        content = validate_memory_content(content)
        category = validate_category(category)
        tags = validate_tags(tags)
        rate_limiter.check("store")

        # Add category as a tag for filtering
        all_tags = [f"category:{category}", *tags]

        result = await self.memory.add(
            content,
            user_id=DEFAULT_USER_ID,
            tags=all_tags,
            meta={"childermass_category": category},
        )

        memory_id = result.get("id") or result.get("root_memory_id", "unknown")

        audit_log(
            "store",
            details={
                "memory_id": memory_id,
                "content_preview": content[:80],
                "category": category,
                "tags": tags,
            },
        )

        return {
            "id": memory_id,
            "sector": result.get("primary_sector", "unknown"),
            "category": category,
            "success": True,
        }

    async def recall(
        self,
        query: str,
        limit: int = 5,
        min_score: float = 0.3,
    ) -> dict[str, Any]:
        """Search memories by semantic similarity.

        Args:
            query: Search query text.
            limit: Maximum number of results.
            min_score: Minimum similarity score (0-1).

        Returns:
            dict: Search results with matching memories.

        Raises:
            SecurityError: If input validation fails.
        """
        query = validate_query(query)
        limit = validate_limit(limit)
        rate_limiter.check("recall")

        results = await self.memory.search(
            query,
            user_id=DEFAULT_USER_ID,
            limit=limit,
        )

        memories = []
        for r in results:
            score = r.get("score", 0)
            if score < min_score:
                continue
            memories.append(
                {
                    "id": r.get("id", ""),
                    "content": r.get("content", ""),
                    "sector": r.get("primary_sector", "unknown"),
                    "score": round(score, 3),
                    "tags": _parse_tags(r.get("tags")),
                    "created_at": _format_timestamp(r.get("created_at")),
                    "salience": round(r.get("salience", 0), 3),
                }
            )

        return {
            "memories": memories,
            "count": len(memories),
            "query": query,
        }

    async def recall_by_sector(
        self,
        sector: str,
        limit: int = 10,
    ) -> dict[str, Any]:
        """Get memories from a specific cognitive sector.

        Args:
            sector: Cognitive sector (episodic, semantic, procedural, emotional, reflective).
            limit: Maximum number of results.

        Returns:
            dict: Memories from the specified sector.

        Raises:
            SecurityError: If input validation fails.
        """
        sector = validate_sector(sector)
        limit = validate_limit(limit)
        rate_limiter.check("recall")

        # Search with sector filter
        results = await self.memory.search(
            f"sector:{sector}",
            user_id=DEFAULT_USER_ID,
            limit=limit,
            sectors=[sector],
        )

        memories = []
        for r in results:
            memories.append(
                {
                    "id": r.get("id", ""),
                    "content": r.get("content", ""),
                    "sector": r.get("primary_sector", "unknown"),
                    "score": round(r.get("score", 0), 3),
                    "tags": _parse_tags(r.get("tags")),
                    "salience": round(r.get("salience", 0), 3),
                }
            )

        return {
            "memories": memories,
            "count": len(memories),
            "sector": sector,
        }

    async def get_memory(self, memory_id: str) -> dict[str, Any]:
        """Get a specific memory by ID.

        Args:
            memory_id: Memory identifier.

        Returns:
            dict: Memory record.

        Raises:
            SecurityError: If input validation fails.
        """
        memory_id = validate_memory_id(memory_id)
        rate_limiter.check("get")

        # Ensure memory is initialized
        _ = self.memory

        row = om_db.fetchone(
            "SELECT id, content, primary_sector, tags, salience, created_at FROM memories WHERE id = ?",
            (memory_id,),
        )

        if not row:
            return {"error": f"Memory not found: {memory_id}"}

        return {
            "id": row[0],
            "content": row[1],
            "sector": row[2] or "unknown",
            "tags": _parse_tags(row[3]),
            "salience": round(float(row[4] or 0), 3),
            "created_at": _format_timestamp(row[5]),
        }

    async def list_memories(
        self,
        category: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """List memories, optionally filtered by category.

        Args:
            category: Optional Childermass category filter.
            limit: Maximum number of results.

        Returns:
            dict: List of memories.

        Raises:
            SecurityError: If input validation fails.
        """
        if category:
            category = validate_category(category)
        limit = validate_limit(limit)
        rate_limiter.check("list")

        # Use search with category tag if filtered
        if category:
            results = await self.memory.search(
                f"category:{category}",
                user_id=DEFAULT_USER_ID,
                limit=limit,
            )
        else:
            # Search with broad query to get recent memories
            results = await self.memory.search(
                "*",
                user_id=DEFAULT_USER_ID,
                limit=limit,
            )

        memories = []
        for r in results:
            tags = _parse_tags(r.get("tags"))
            # Filter by category tag if specified
            if category:
                cat_tag = f"category:{category}"
                if cat_tag not in tags:
                    # Check metadata as well
                    meta = r.get("metadata") or r.get("meta") or {}
                    if isinstance(meta, str):
                        try:
                            meta = json.loads(meta)
                        except (json.JSONDecodeError, TypeError):
                            meta = {}
                    if meta.get("childermass_category") != category:
                        continue

            memories.append(
                {
                    "id": r.get("id", ""),
                    "content": r.get("content", ""),
                    "sector": r.get("primary_sector", "unknown"),
                    "tags": tags,
                    "score": round(r.get("score", 0), 3),
                    "salience": round(r.get("salience", 0), 3),
                }
            )

        return {
            "memories": memories,
            "count": len(memories),
            "category": category,
        }

    async def list_all(self, limit: int = 10000) -> list[dict]:
        """List all memories (for export/backup).

        Args:
            limit: Maximum number of results.

        Returns:
            list: All memory records.
        """
        from openmemory.core.db import db as _db

        rows = _db.fetchall(
            "SELECT id, content, primary_sector, tags, salience, created_at FROM memories ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        result = []
        for row in rows:
            result.append(
                {
                    "id": row[0],
                    "content": row[1],
                    "sector": row[2],
                    "tags": row[3],
                    "salience": row[4],
                    "created_at": row[5],
                }
            )
        return result

    async def forget(self, memory_id: str) -> dict[str, Any]:
        """Delete a memory by ID.

        Args:
            memory_id: Memory identifier.

        Returns:
            dict: Deletion result.

        Raises:
            SecurityError: If input validation fails.
        """
        memory_id = validate_memory_id(memory_id)
        rate_limiter.check("forget")

        try:
            await self.memory.delete(memory_id)
            audit_log("forget", details={"memory_id": memory_id})
            return {"success": True, "deleted_id": memory_id}
        except Exception as e:
            return {"error": f"Failed to delete memory: {sanitize_error_message(e)}"}

    # ========================================================================
    # Temporal Knowledge Graph Operations
    # ========================================================================

    async def store_temporal_fact(
        self,
        subject: str,
        predicate: str,
        obj: str,
        valid_from: str,
    ) -> dict[str, Any]:
        """Store a temporal fact (subject-predicate-object with time validity).

        Args:
            subject: Subject entity (e.g., "bedroom").
            predicate: Relationship (e.g., "preferred_temperature").
            obj: Object value (e.g., "21°C").
            valid_from: Start date in YYYY-MM-DD format.

        Returns:
            dict: Store result with fact ID.

        Raises:
            SecurityError: If input validation fails.
        """
        subject = validate_subject(subject)
        predicate = validate_predicate(predicate)
        obj = validate_memory_content(obj)
        valid_from = validate_temporal_date(valid_from)
        rate_limiter.check("temporal")

        # Ensure memory (and temporal table) is initialized
        _ = self.memory

        fact_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        om_db.execute(
            "INSERT INTO childermass_temporal_facts (id, subject, predicate, object, valid_from, valid_to, confidence, created_at) VALUES (?,?,?,?,?,NULL,1.0,?)",
            (fact_id, subject, predicate, obj, valid_from, now),
        )

        audit_log(
            "store_fact",
            details={
                "fact_id": fact_id,
                "subject": subject,
                "predicate": predicate,
                "valid_from": valid_from,
            },
        )

        return {
            "fact_id": fact_id,
            "subject": subject,
            "predicate": predicate,
            "object": obj,
            "valid_from": valid_from,
            "success": True,
        }

    async def update_temporal_fact(
        self,
        subject: str,
        predicate: str,
        new_object: str,
        valid_from: str,
    ) -> dict[str, Any]:
        """Update a temporal fact by closing the old one and creating a new one.

        Args:
            subject: Subject entity.
            predicate: Relationship.
            new_object: New object value.
            valid_from: Start date of new value (YYYY-MM-DD).

        Returns:
            dict: Update result with new fact ID.

        Raises:
            SecurityError: If input validation fails.
        """
        subject = validate_subject(subject)
        predicate = validate_predicate(predicate)
        new_object = validate_memory_content(new_object)
        valid_from = validate_temporal_date(valid_from)
        rate_limiter.check("temporal")

        # Ensure memory (and temporal table) is initialized
        _ = self.memory

        # Find and close current fact
        current = om_db.fetchone(
            "SELECT id, object FROM childermass_temporal_facts WHERE subject=? AND predicate=? AND valid_to IS NULL ORDER BY valid_from DESC LIMIT 1",
            (subject, predicate),
        )
        old_value = None
        if current:
            old_value = current[1]
            om_db.execute(
                "UPDATE childermass_temporal_facts SET valid_to=? WHERE id=?",
                (valid_from, current[0]),
            )

        # Insert new fact
        fact_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        om_db.execute(
            "INSERT INTO childermass_temporal_facts (id, subject, predicate, object, valid_from, valid_to, confidence, created_at) VALUES (?,?,?,?,?,NULL,1.0,?)",
            (fact_id, subject, predicate, new_object, valid_from, now),
        )

        audit_log(
            "update_fact",
            details={
                "new_fact_id": fact_id,
                "subject": subject,
                "predicate": predicate,
                "previous_value": old_value,
                "valid_from": valid_from,
            },
        )

        return {
            "fact_id": fact_id,
            "subject": subject,
            "predicate": predicate,
            "object": new_object,
            "previous_object": old_value,
            "valid_from": valid_from,
            "success": True,
        }

    async def get_timeline(self, subject: str) -> dict[str, Any]:
        """Get the chronological history of an entity.

        Args:
            subject: Subject entity name.

        Returns:
            dict: Timeline of facts about the entity.

        Raises:
            SecurityError: If input validation fails.
        """
        subject = validate_subject(subject)
        rate_limiter.check("temporal")

        # Ensure memory (and temporal table) is initialized
        _ = self.memory

        rows = om_db.fetchall(
            "SELECT id, subject, predicate, object, valid_from, valid_to, confidence FROM childermass_temporal_facts WHERE subject=? ORDER BY valid_from ASC",
            (subject,),
        )

        timeline = []
        for row in rows or []:
            timeline.append(
                {
                    "id": row[0],
                    "subject": row[1],
                    "predicate": row[2],
                    "object": row[3],
                    "valid_from": row[4],
                    "valid_to": row[5],
                    "confidence": round(float(row[6]), 2),
                    "is_current": row[5] is None,
                }
            )

        return {
            "subject": subject,
            "facts": timeline,
            "count": len(timeline),
        }

    async def get_summary(self) -> dict[str, Any]:
        """Get memory system statistics.

        Returns:
            dict: Summary statistics about stored memories.
        """
        rate_limiter.check("get")

        try:
            # Count total memories
            row = om_db.fetchone(
                "SELECT COUNT(*) FROM memories WHERE user_id = ?", (DEFAULT_USER_ID,)
            )
            total = row[0] if row else 0

            # Count by sector
            sector_rows = om_db.fetchall(
                "SELECT primary_sector, COUNT(*) FROM memories WHERE user_id = ? GROUP BY primary_sector",
                (DEFAULT_USER_ID,),
            )
            sectors = {r[0]: r[1] for r in sector_rows} if sector_rows else {}

            # Count temporal facts
            try:
                fact_row = om_db.fetchone("SELECT COUNT(*) FROM childermass_temporal_facts", ())
                temporal_count = fact_row[0] if fact_row else 0
            except Exception:
                temporal_count = 0

            # Recent memories
            recent_rows = om_db.fetchall(
                "SELECT id, content, primary_sector, created_at FROM memories WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
                (DEFAULT_USER_ID,),
            )
            recent = []
            for r in recent_rows or []:
                recent.append(
                    {
                        "id": r[0],
                        "content": r[1][:100] + ("..." if len(r[1]) > 100 else ""),
                        "sector": r[2],
                        "created_at": _format_timestamp(r[3]),
                    }
                )

            return {
                "total_memories": total,
                "sectors": sectors,
                "temporal_facts": temporal_count,
                "recent_memories": recent,
            }
        except Exception:
            return {
                "total_memories": 0,
                "sectors": {},
                "temporal_facts": 0,
                "recent_memories": [],
                "note": "Database may not be initialized yet",
            }


# ============================================================================
# Helpers
# ============================================================================


def _parse_tags(tags: Any) -> list[str]:
    """Parse tags from various formats to a list of strings."""
    if tags is None:
        return []
    if isinstance(tags, list):
        return tags
    if isinstance(tags, str):
        try:
            parsed = json.loads(tags)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
        return [t.strip() for t in tags.split(",") if t.strip()]
    return []


def _format_timestamp(ts: Any) -> str | None:
    """Format a Unix timestamp (seconds or milliseconds) to ISO string."""
    if ts is None:
        return None
    try:
        ts_float = float(ts)
        # If timestamp is in milliseconds (> year 2100 in seconds)
        if ts_float > 4_000_000_000:
            ts_float = ts_float / 1000.0
        return datetime.fromtimestamp(ts_float).isoformat()
    except (ValueError, TypeError, OSError):
        return str(ts)


def _format_ms_timestamp(ts: Any) -> str | None:
    """Format a millisecond timestamp to ISO date string."""
    if ts is None:
        return None
    try:
        ts_float = float(ts) / 1000.0
        return datetime.fromtimestamp(ts_float).strftime("%Y-%m-%d")
    except (ValueError, TypeError, OSError):
        return str(ts)


# ============================================================================
# Singleton
# ============================================================================


_client: MemoryClient | None = None


def get_client() -> MemoryClient:
    """Get or create the singleton MemoryClient instance.

    Returns:
        MemoryClient: The memory client instance.
    """
    global _client
    if _client is None:
        _client = MemoryClient()
    return _client
