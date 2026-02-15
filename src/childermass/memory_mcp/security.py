"""Security and validation for Childermass Memory MCP.

This module provides input validation, rate limiting, error sanitization,
and audit logging for the memory MCP server.
"""

import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any


# Configuration
CONFIG_DIR = Path.home() / ".childermass"
AUDIT_LOG_FILE = CONFIG_DIR / "memory-audit.log"

# Validation limits
MAX_CONTENT_LENGTH = 5000
MAX_QUERY_LENGTH = 500
MAX_TAG_LENGTH = 50
MAX_TAGS_COUNT = 10
MAX_MEMORY_ID_LENGTH = 128
MAX_SUBJECT_LENGTH = 100
MAX_PREDICATE_LENGTH = 100


class SecurityError(Exception):
    """Raised when security validation fails."""
    pass


# ============================================================================
# Input Validators
# ============================================================================


def validate_memory_content(content: str) -> str:
    """Validate memory content to store.

    Args:
        content: Text content to memorize.

    Returns:
        str: Sanitized content.

    Raises:
        SecurityError: If content is invalid.
    """
    if not content or not isinstance(content, str):
        raise SecurityError("Memory content must be a non-empty string")

    content = content.strip()

    if len(content) < 3:
        raise SecurityError("Memory content too short (minimum 3 characters)")

    if len(content) > MAX_CONTENT_LENGTH:
        raise SecurityError(f"Memory content too long (maximum {MAX_CONTENT_LENGTH} characters)")

    return content


def validate_query(query: str) -> str:
    """Validate search query.

    Args:
        query: Search query text.

    Returns:
        str: Sanitized query.

    Raises:
        SecurityError: If query is invalid.
    """
    if not query or not isinstance(query, str):
        raise SecurityError("Query must be a non-empty string")

    query = query.strip()

    if len(query) < 2:
        raise SecurityError("Query too short (minimum 2 characters)")

    if len(query) > MAX_QUERY_LENGTH:
        raise SecurityError(f"Query too long (maximum {MAX_QUERY_LENGTH} characters)")

    return query


def validate_memory_id(memory_id: str) -> str:
    """Validate memory ID format.

    Args:
        memory_id: Memory identifier.

    Returns:
        str: Validated memory ID.

    Raises:
        SecurityError: If ID is invalid.
    """
    if not memory_id or not isinstance(memory_id, str):
        raise SecurityError("Memory ID must be a non-empty string")

    memory_id = memory_id.strip()

    if len(memory_id) > MAX_MEMORY_ID_LENGTH:
        raise SecurityError(f"Memory ID too long (maximum {MAX_MEMORY_ID_LENGTH} characters)")

    # Allow UUIDs, hex strings, and alphanumeric IDs
    if not re.match(r"^[a-zA-Z0-9\-_]+$", memory_id):
        raise SecurityError(
            "Memory ID contains invalid characters "
            "(only alphanumeric, hyphens, underscores allowed)"
        )

    return memory_id


def validate_tags(tags: list[str] | None) -> list[str]:
    """Validate memory tags.

    Args:
        tags: List of tag strings.

    Returns:
        list[str]: Validated tags.

    Raises:
        SecurityError: If tags are invalid.
    """
    if tags is None:
        return []

    if not isinstance(tags, list):
        raise SecurityError("Tags must be a list of strings")

    if len(tags) > MAX_TAGS_COUNT:
        raise SecurityError(f"Too many tags (maximum {MAX_TAGS_COUNT})")

    validated = []
    for tag in tags:
        if not isinstance(tag, str):
            raise SecurityError("Each tag must be a string")
        tag = tag.strip().lower()
        if not tag:
            continue
        if len(tag) > MAX_TAG_LENGTH:
            raise SecurityError(f"Tag too long: '{tag[:20]}...' (maximum {MAX_TAG_LENGTH} characters)")
        if not re.match(r"^[a-zA-Z0-9\-_\u00C0-\u024F]+$", tag):
            raise SecurityError(
                f"Tag '{tag}' contains invalid characters "
                "(only alphanumeric, hyphens, underscores, accented letters allowed)"
            )
        validated.append(tag)

    return validated


VALID_SECTORS = {"episodic", "semantic", "procedural", "emotional", "reflective"}


def validate_sector(sector: str) -> str:
    """Validate cognitive sector name.

    Args:
        sector: Sector name.

    Returns:
        str: Validated sector name.

    Raises:
        SecurityError: If sector is invalid.
    """
    if not sector or not isinstance(sector, str):
        raise SecurityError("Sector must be a non-empty string")

    sector = sector.strip().lower()

    if sector not in VALID_SECTORS:
        raise SecurityError(
            f"Invalid sector: '{sector}' "
            f"(must be one of: {', '.join(sorted(VALID_SECTORS))})"
        )

    return sector


VALID_CATEGORIES = {"preference", "routine", "fact", "feedback", "pattern", "temporal"}


def validate_category(category: str) -> str:
    """Validate Childermass memory category.

    Args:
        category: Category name.

    Returns:
        str: Validated category name.

    Raises:
        SecurityError: If category is invalid.
    """
    if not category or not isinstance(category, str):
        raise SecurityError("Category must be a non-empty string")

    category = category.strip().lower()

    if category not in VALID_CATEGORIES:
        raise SecurityError(
            f"Invalid category: '{category}' "
            f"(must be one of: {', '.join(sorted(VALID_CATEGORIES))})"
        )

    return category


def validate_limit(limit: int) -> int:
    """Validate result limit.

    Args:
        limit: Maximum number of results.

    Returns:
        int: Validated limit.

    Raises:
        SecurityError: If limit is invalid.
    """
    if not isinstance(limit, int):
        raise SecurityError("Limit must be an integer")

    if limit < 1:
        raise SecurityError("Limit must be at least 1")

    if limit > 100:
        raise SecurityError("Limit cannot exceed 100")

    return limit


def validate_temporal_date(date_str: str) -> str:
    """Validate temporal date string in ISO 8601 format.

    Args:
        date_str: Date string (YYYY-MM-DD).

    Returns:
        str: Validated date string.

    Raises:
        SecurityError: If date format is invalid.
    """
    if not date_str or not isinstance(date_str, str):
        raise SecurityError("Date must be a non-empty string")

    date_str = date_str.strip()

    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        raise SecurityError(
            f"Invalid date format: '{date_str}' (expected YYYY-MM-DD)"
        )

    try:
        year, month, day = map(int, date_str.split("-"))
        if not (1900 <= year <= 2100):
            raise SecurityError(f"Year out of range: {year}")
        if not (1 <= month <= 12):
            raise SecurityError(f"Month out of range: {month}")
        if not (1 <= day <= 31):
            raise SecurityError(f"Day out of range: {day}")
        # Verify it's a real date
        datetime(year, month, day)
    except ValueError:
        raise SecurityError(f"Invalid date: {date_str}")

    return date_str


def validate_subject(subject: str) -> str:
    """Validate temporal fact subject.

    Args:
        subject: Subject entity name.

    Returns:
        str: Validated subject.

    Raises:
        SecurityError: If subject is invalid.
    """
    if not subject or not isinstance(subject, str):
        raise SecurityError("Subject must be a non-empty string")

    subject = subject.strip()

    if len(subject) < 1:
        raise SecurityError("Subject too short")

    if len(subject) > 200:
        raise SecurityError("Subject too long (maximum 200 characters)")

    return subject


def validate_predicate(predicate: str) -> str:
    """Validate temporal fact predicate.

    Args:
        predicate: Predicate/relationship name.

    Returns:
        str: Validated predicate.

    Raises:
        SecurityError: If predicate is invalid.
    """
    if not predicate or not isinstance(predicate, str):
        raise SecurityError("Predicate must be a non-empty string")

    predicate = predicate.strip()

    if len(predicate) < 1:
        raise SecurityError("Predicate too short")

    if len(predicate) > 200:
        raise SecurityError("Predicate too long (maximum 200 characters)")

    return predicate


# ============================================================================
# Rate Limiter (Token Bucket Algorithm)
# ============================================================================


class RateLimiter:
    """Thread-safe token bucket rate limiter for memory operations."""

    def __init__(self):
        """Initialize rate limiter with operation limits."""
        # Format: operation -> (tokens_per_minute, bucket_capacity)
        self.limits = {
            "store": (30, 30),
            "recall": (60, 60),
            "list": (30, 30),
            "get": (60, 60),
            "forget": (10, 10),
            "temporal": (30, 30),
        }

        # State: operation -> {"tokens": float, "last_update": float}
        self.buckets: dict[str, dict[str, float]] = {}
        self._lock = Lock()

    def check(self, operation: str) -> None:
        """Check if operation is allowed under rate limit.

        Args:
            operation: Operation name (e.g., "store", "recall").

        Raises:
            SecurityError: If rate limit exceeded.
        """
        if operation not in self.limits:
            operation = "recall"

        rate, capacity = self.limits[operation]

        with self._lock:
            if operation not in self.buckets:
                self.buckets[operation] = {
                    "tokens": float(capacity),
                    "last_update": time.time()
                }

            bucket = self.buckets[operation]

            now = time.time()
            elapsed = now - bucket["last_update"]
            tokens_to_add = elapsed * (rate / 60.0)
            bucket["tokens"] = min(capacity, bucket["tokens"] + tokens_to_add)
            bucket["last_update"] = now

            if bucket["tokens"] < 1.0:
                wait_time = (1.0 - bucket["tokens"]) / (rate / 60.0)
                raise SecurityError(
                    f"Rate limit exceeded for {operation}. "
                    f"Please wait {wait_time:.1f} seconds."
                )

            bucket["tokens"] -= 1.0


# Global rate limiter instance
rate_limiter = RateLimiter()


# ============================================================================
# Error Sanitization
# ============================================================================


def sanitize_error_message(error: Exception) -> str:
    """Sanitize error message to prevent leaking sensitive information.

    Args:
        error: Exception to sanitize.

    Returns:
        str: Sanitized error message.
    """
    message = str(error)

    # Remove file paths
    message = re.sub(r'/[a-zA-Z0-9_\-./]+', '[PATH]', message)
    message = re.sub(r'[A-Z]:\\[a-zA-Z0-9_\-\\]+', '[PATH]', message)

    # Remove potential API keys
    message = re.sub(r'\b[0-9a-f]{32}\b', '[KEY]', message, flags=re.IGNORECASE)
    message = re.sub(r'sk-[a-zA-Z0-9]+', '[KEY]', message)

    # Remove SQL queries that might leak schema
    message = re.sub(r'(SELECT|INSERT|UPDATE|DELETE|CREATE)\s+.*', '[SQL]', message, flags=re.IGNORECASE)

    # Limit length
    if len(message) > 300:
        message = message[:297] + "..."

    return message


# ============================================================================
# Audit Logging
# ============================================================================


_AUDIT_DIR = Path.home() / ".childermass"
_AUDIT_LOG_FILE = _AUDIT_DIR / "memory-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.memory_mcp.audit")
    # Recreate handlers if the configured AUDIT_LOG_FILE changed (tests may
    # monkeypatch `AUDIT_LOG_FILE` and `CONFIG_DIR` per-test).
    if logger.handlers:
        try:
            first = logger.handlers[0]
            base = getattr(first, "baseFilename", None)
            if base is not None and base != str(AUDIT_LOG_FILE):
                for h in list(logger.handlers):
                    try:
                        h.close()
                    except Exception:
                        pass
                    logger.removeHandler(h)
        except Exception:
            for h in list(logger.handlers):
                try:
                    h.close()
                except Exception:
                    pass
                logger.removeHandler(h)

    if not logger.handlers:
        # Ensure the configured directory exists (tests may override CONFIG_DIR)
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        from logging.handlers import RotatingFileHandler

        handler = RotatingFileHandler(
            str(AUDIT_LOG_FILE),
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def audit_log(
    operation: str,
    account: str = "",
    details: dict[str, Any] | None = None,
    success: bool = True,
) -> None:
    """Write a structured audit log entry.

    Args:
        operation: Operation name (e.g., "store", "forget")
        account: Account or context identifier
        details: Additional context (sanitised - no credentials!)
        success: Whether the operation succeeded
    """
    logger = _get_audit_logger()

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "operation": operation,
        "account": account,
        "success": success,
    }
    if details:
        entry["details"] = details

    try:
        logger.info(json.dumps(entry, ensure_ascii=False))
    except Exception:
        pass  # Audit logging must never crash the server
