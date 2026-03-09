"""OpenMemory client wrapper for Childermass Memory MCP.

This module provides a MemoryClient class that wraps the OpenMemory Python SDK
with input validation, rate limiting, and audit logging. It manages a singleton
Memory instance and provides both memory storage/recall and temporal graph operations.
"""

import contextlib
import json
import logging
import math
import os
import time as time_mod
import uuid
from datetime import datetime
from typing import Any

# Configure environment BEFORE importing openmemory
from .env import configure_environment


logger = logging.getLogger(__name__)
configure_environment()

# Import OpenMemory SDK
from openmemory.client import Memory  # noqa: E402
from openmemory.core.db import db as om_db  # noqa: E402

from .security import (  # noqa: E402
    audit_log,
    rate_limiter,
    sanitize_error_message,
    validate_category,
    validate_github_repo,
    validate_limit,
    validate_memory_content,
    validate_memory_id,
    validate_predicate,
    validate_query,
    validate_salience_boost,
    validate_sector,
    validate_subject,
    validate_tags,
    validate_temporal_date,
    validate_url,
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
        en_summary: str | None = None,
    ) -> dict[str, Any]:
        """Store a new memory with optional bilingual support.

        Args:
            content: Text content to memorize.
            category: Childermass category (preference, routine, fact, feedback, pattern).
            tags: Optional tags for organization.
            en_summary: Optional English translation/summary for bilingual recall.
                        Appended to content so both languages are embedded together.

        Returns:
            dict: Store result with memory ID and sector classification.

        Raises:
            SecurityError: If input validation fails.
        """
        content = validate_memory_content(content)
        category = validate_category(category)
        tags = validate_tags(tags)
        rate_limiter.check("store")

        # Bilingual support: if en_summary provided, create composite content
        # so embeddings capture both languages for cross-language recall
        store_content = content
        lang_meta: dict[str, str] = {}
        if en_summary:
            en_summary = en_summary.strip()
            if len(en_summary) >= 3:
                store_content = f"{content}\n\n[EN] {en_summary}"
                lang_meta = {"original_lang": "cs", "en_summary": en_summary}

        # Add category as a tag for filtering
        all_tags = [f"category:{category}", *tags]
        if lang_meta:
            all_tags.append("bilingual")

        result = await self.memory.add(
            store_content,
            user_id=DEFAULT_USER_ID,
            tags=all_tags,
            meta={"childermass_category": category, **lang_meta},
        )

        memory_id = result.get("id") or result.get("root_memory_id", "unknown")

        audit_log(
            "store",
            details={
                "memory_id": memory_id,
                "content_preview": content[:80],
                "category": category,
                "tags": tags,
                "bilingual": bool(lang_meta),
            },
        )

        return {
            "id": memory_id,
            "sector": result.get("primary_sector", "unknown"),
            "category": category,
            "bilingual": bool(lang_meta),
            "success": True,
        }

    async def recall(
        self,
        query: str,
        limit: int = 5,
        min_score: float = 0.3,
        also_search: list[str] | None = None,
    ) -> dict[str, Any]:
        """Search memories by semantic similarity with optional bilingual search.

        Args:
            query: Search query text.
            limit: Maximum number of results.
            min_score: Minimum similarity score (0-1).
            also_search: Additional query phrasings (e.g. translations) to
                         search with. Results are merged and deduplicated.

        Returns:
            dict: Search results with matching memories.

        Raises:
            SecurityError: If input validation fails.
        """
        query = validate_query(query)
        limit = validate_limit(limit)
        rate_limiter.check("recall")

        # Primary search
        results = await self.memory.search(
            query,
            user_id=DEFAULT_USER_ID,
            limit=limit,
        )

        # Bilingual / multi-query search: run additional queries and merge
        if also_search:
            seen_ids: set[str] = set()
            all_results = list(results)
            for r in all_results:
                rid = r.get("id", "")
                if rid:
                    seen_ids.add(rid)

            for alt_query in also_search[:3]:  # max 3 alternative queries
                alt_query = alt_query.strip()
                if len(alt_query) < 2:
                    continue
                try:
                    alt_results = await self.memory.search(
                        alt_query,
                        user_id=DEFAULT_USER_ID,
                        limit=limit,
                    )
                    for r in alt_results:
                        rid = r.get("id", "")
                        if rid and rid not in seen_ids:
                            seen_ids.add(rid)
                            all_results.append(r)
                except Exception:
                    logger.debug("Alternative query failed: %s", alt_query)

            # Re-sort all results by score descending
            all_results.sort(key=lambda x: x.get("score", 0), reverse=True)
            results = all_results[:limit]

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
            "bilingual": bool(also_search),
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
    # Reinforcement
    # ========================================================================

    async def reinforce(self, memory_id: str, boost: float = 0.1) -> dict[str, Any]:
        """Reinforce a memory by boosting its salience.

        Reinforcement makes a memory more important and resistant to decay.
        It also strengthens any waypoint (associative link) connections.

        Args:
            memory_id: Memory identifier to reinforce.
            boost: Salience boost amount (0.01-0.5, default 0.1).

        Returns:
            dict: Reinforcement result with old and new salience.

        Raises:
            SecurityError: If input validation fails.
        """
        memory_id = validate_memory_id(memory_id)
        boost = validate_salience_boost(boost)
        rate_limiter.check("reinforce")

        # Ensure memory is initialized
        _ = self.memory

        # First try the SDK's reinforce if available
        try:
            result = await self.memory.reinforce(memory_id)
            audit_log("reinforce", details={"memory_id": memory_id, "method": "sdk"})
            return {
                "memory_id": memory_id,
                "method": "sdk",
                "success": True,
                **(dict(result.items()) if isinstance(result, dict) else {}),
            }
        except (AttributeError, NotImplementedError):
            pass  # SDK doesn't support reinforce; fall back to manual
        except Exception as exc:
            logger.debug("SDK reinforce failed, falling back to manual: %s", exc)

        # Manual reinforcement: boost salience + update last_seen_at
        row = om_db.fetchone(
            "SELECT salience, last_seen_at FROM memories WHERE id = ?",
            (memory_id,),
        )
        if not row:
            return {"error": f"Memory not found: {memory_id}"}

        old_salience = float(row[0] or 0.5)
        new_salience = min(1.0, old_salience + boost)
        now_ms = int(time_mod.time() * 1000)

        om_db.execute(
            "UPDATE memories SET salience = ?, last_seen_at = ? WHERE id = ?",
            (new_salience, now_ms, memory_id),
        )

        # Also strengthen any waypoint connections
        with contextlib.suppress(Exception):
            om_db.execute(
                "UPDATE waypoints SET weight = MIN(1.0, weight + 0.05), updated_at = ? WHERE src_id = ? OR dst_id = ?",
                (now_ms, memory_id, memory_id),
            )

        audit_log(
            "reinforce",
            details={
                "memory_id": memory_id,
                "old_salience": round(old_salience, 3),
                "new_salience": round(new_salience, 3),
                "boost": boost,
                "method": "manual",
            },
        )

        return {
            "memory_id": memory_id,
            "old_salience": round(old_salience, 3),
            "new_salience": round(new_salience, 3),
            "boost": boost,
            "success": True,
        }

    # ========================================================================
    # Connectors (GitHub, Web Crawler)
    # ========================================================================

    async def ingest_github(self, repo: str) -> dict[str, Any]:
        """Ingest data from a GitHub repository into memory.

        Uses the OpenMemory source connector API. Requires GITHUB_TOKEN
        or GH_TOKEN environment variable.

        Args:
            repo: Repository in 'owner/repo' format.

        Returns:
            dict: Ingestion result with count of memories created.

        Raises:
            SecurityError: If input validation fails.
        """
        repo = validate_github_repo(repo)
        rate_limiter.check("ingest")

        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            return {
                "error": "GitHub token not configured. Set GITHUB_TOKEN or GH_TOKEN environment variable.",
                "success": False,
            }

        try:
            github = self.memory.source("github")
            await github.connect(token=token)
            result = await github.ingest_all(repo=repo)

            audit_log(
                "ingest_github",
                details={"repo": repo, "result_type": type(result).__name__},
            )

            if isinstance(result, dict):
                return {"success": True, "repo": repo, **result}
            return {"success": True, "repo": repo, "result": str(result)}
        except AttributeError:
            return {
                "error": "OpenMemory SDK version does not support source connectors. "
                "Upgrade to openmemory-py >= 1.3.0 with connector support.",
                "success": False,
            }
        except Exception as e:
            return {
                "error": f"GitHub ingestion failed: {sanitize_error_message(e)}",
                "success": False,
            }

    async def ingest_web(self, url: str) -> dict[str, Any]:
        """Crawl and ingest content from a URL into memory.

        Uses the OpenMemory web_crawler source connector.

        Args:
            url: URL to crawl and ingest.

        Returns:
            dict: Ingestion result with count of memories created.

        Raises:
            SecurityError: If input validation fails.
        """
        url = validate_url(url)
        rate_limiter.check("ingest")

        try:
            crawler = self.memory.source("web_crawler")
            result = await crawler.ingest(url=url)

            audit_log(
                "ingest_web",
                details={"url": url, "result_type": type(result).__name__},
            )

            if isinstance(result, dict):
                return {"success": True, "url": url, **result}
            return {"success": True, "url": url, "result": str(result)}
        except AttributeError:
            return {
                "error": "OpenMemory SDK version does not support source connectors. "
                "Upgrade to openmemory-py >= 1.3.0 with connector support.",
                "success": False,
            }
        except Exception as e:
            return {"error": f"Web ingestion failed: {sanitize_error_message(e)}", "success": False}

    # ========================================================================
    # Decay & Waypoint Operations
    # ========================================================================

    async def run_decay(self) -> dict[str, Any]:
        """Run memory decay processing on all memories.

        Applies sector-specific decay rates to reduce salience over time.
        Memories that haven't been recalled recently lose importance.
        Formula: new_salience = salience * e^(-decay_lambda * days_since_last_seen)

        Returns:
            dict: Decay statistics (total processed, updated count).
        """
        rate_limiter.check("decay")

        # Ensure memory is initialized
        _ = self.memory

        rows = om_db.fetchall(
            "SELECT id, salience, decay_lambda, last_seen_at, created_at "
            "FROM memories WHERE user_id = ?",
            (DEFAULT_USER_ID,),
        )

        now = time_mod.time()
        updated = 0
        total = len(rows or [])

        for row in rows or []:
            mem_id, salience, decay_lambda, last_seen, created_at = row
            if salience is None or decay_lambda is None:
                continue

            # Determine last activity timestamp
            last_ts = last_seen or created_at or now
            try:
                last_ts_float = float(last_ts)
                # Timestamps in milliseconds
                if last_ts_float > 4_000_000_000:
                    last_ts_float = last_ts_float / 1000.0
            except (ValueError, TypeError):
                continue

            days = (now - last_ts_float) / 86400.0
            if days <= 0:
                continue

            new_salience = float(salience) * math.exp(-float(decay_lambda) * days)
            new_salience = max(0.001, new_salience)  # never fully zero

            if abs(new_salience - float(salience)) > 0.001:
                om_db.execute(
                    "UPDATE memories SET salience = ? WHERE id = ?",
                    (new_salience, mem_id),
                )
                updated += 1

        audit_log("decay", details={"total": total, "updated": updated})

        return {
            "total_processed": total,
            "updated": updated,
            "success": True,
        }

    async def get_waypoints(self, memory_id: str | None = None) -> dict[str, Any]:
        """Get waypoint (associative link) connections.

        Waypoints are single-waypoint links between semantically related memories.
        They enable graph traversal during recall for better results.

        Args:
            memory_id: If provided, get links for this specific memory.
                       If None, return top 50 strongest links.

        Returns:
            dict: Waypoint connections with source, target, and weight.
        """
        rate_limiter.check("get")

        # Ensure memory is initialized
        _ = self.memory

        try:
            if memory_id:
                memory_id = validate_memory_id(memory_id)
                rows = om_db.fetchall(
                    "SELECT src_id, dst_id, weight FROM waypoints "
                    "WHERE src_id = ? OR dst_id = ? ORDER BY weight DESC",
                    (memory_id, memory_id),
                )
            else:
                rows = om_db.fetchall(
                    "SELECT src_id, dst_id, weight FROM waypoints ORDER BY weight DESC LIMIT 50",
                    (),
                )
        except Exception:
            # waypoints table may not exist
            return {
                "waypoints": [],
                "count": 0,
                "note": "Waypoints table not available (may require real embeddings)",
            }

        links = []
        for row in rows or []:
            links.append(
                {
                    "source": row[0],
                    "target": row[1],
                    "weight": round(float(row[2]), 3),
                }
            )

        return {
            "waypoints": links,
            "count": len(links),
            "memory_id": memory_id,
        }

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
        except (json.JSONDecodeError, TypeError) as e:
            logger.debug("Tags not in JSON format, parsing as comma-separated: %s", e)
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
