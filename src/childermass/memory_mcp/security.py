"""Security and validation for Childermass Memory MCP.

This module provides input validation, rate limiting, error sanitization,
and audit logging for the memory MCP server.
"""

import contextlib
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import urlparse


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
MAX_URL_LENGTH = 2000


class SecurityError(Exception):
    """Raised when security validation fails."""


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
        msg = "Memory content must be a non-empty string"
        raise SecurityError(msg)

    content = content.strip()

    if len(content) < 3:
        msg = "Memory content too short (minimum 3 characters)"
        raise SecurityError(msg)

    if len(content) > MAX_CONTENT_LENGTH:
        msg = f"Memory content too long (maximum {MAX_CONTENT_LENGTH} characters)"
        raise SecurityError(msg)

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
        msg = "Query must be a non-empty string"
        raise SecurityError(msg)

    query = query.strip()

    if len(query) < 2:
        msg = "Query too short (minimum 2 characters)"
        raise SecurityError(msg)

    if len(query) > MAX_QUERY_LENGTH:
        msg = f"Query too long (maximum {MAX_QUERY_LENGTH} characters)"
        raise SecurityError(msg)

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
        msg = "Memory ID must be a non-empty string"
        raise SecurityError(msg)

    memory_id = memory_id.strip()

    if len(memory_id) > MAX_MEMORY_ID_LENGTH:
        msg = f"Memory ID too long (maximum {MAX_MEMORY_ID_LENGTH} characters)"
        raise SecurityError(msg)

    # Allow UUIDs, hex strings, and alphanumeric IDs
    if not re.match(r"^[a-zA-Z0-9\-_]+$", memory_id):
        msg = (
            "Memory ID contains invalid characters "
            "(only alphanumeric, hyphens, underscores allowed)"
        )
        raise SecurityError(msg)

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
        msg = "Tags must be a list of strings"
        raise SecurityError(msg)

    if len(tags) > MAX_TAGS_COUNT:
        msg = f"Too many tags (maximum {MAX_TAGS_COUNT})"
        raise SecurityError(msg)

    validated = []
    for tag in tags:
        if not isinstance(tag, str):
            msg = "Each tag must be a string"
            raise SecurityError(msg)
        tag = tag.strip().lower()
        if not tag:
            continue
        if len(tag) > MAX_TAG_LENGTH:
            msg = f"Tag too long: '{tag[:20]}...' (maximum {MAX_TAG_LENGTH} characters)"
            raise SecurityError(msg)
        if not re.match(r"^[a-zA-Z0-9\-_\u00C0-\u024F]+$", tag):
            msg = (
                f"Tag '{tag}' contains invalid characters "
                "(only alphanumeric, hyphens, underscores, accented letters allowed)"
            )
            raise SecurityError(msg)
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
        msg = "Sector must be a non-empty string"
        raise SecurityError(msg)

    sector = sector.strip().lower()

    if sector not in VALID_SECTORS:
        msg = f"Invalid sector: '{sector}' (must be one of: {', '.join(sorted(VALID_SECTORS))})"
        raise SecurityError(msg)

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
        msg = "Category must be a non-empty string"
        raise SecurityError(msg)

    category = category.strip().lower()

    if category not in VALID_CATEGORIES:
        msg = (
            f"Invalid category: '{category}' "
            f"(must be one of: {', '.join(sorted(VALID_CATEGORIES))})"
        )
        raise SecurityError(msg)

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
        msg = "Limit must be an integer"
        raise SecurityError(msg)

    if limit < 1:
        msg = "Limit must be at least 1"
        raise SecurityError(msg)

    if limit > 100:
        msg = "Limit cannot exceed 100"
        raise SecurityError(msg)

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
        msg = "Date must be a non-empty string"
        raise SecurityError(msg)

    date_str = date_str.strip()

    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        msg = f"Invalid date format: '{date_str}' (expected YYYY-MM-DD)"
        raise SecurityError(msg)

    try:
        year, month, day = map(int, date_str.split("-"))
        if not (1900 <= year <= 2100):
            msg = f"Year out of range: {year}"
            raise SecurityError(msg)
        if not (1 <= month <= 12):
            msg = f"Month out of range: {month}"
            raise SecurityError(msg)
        if not (1 <= day <= 31):
            msg = f"Day out of range: {day}"
            raise SecurityError(msg)
        # Verify it's a real date
        datetime(year, month, day)
    except ValueError:
        msg = f"Invalid date: {date_str}"
        raise SecurityError(msg) from None

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
        msg = "Subject must be a non-empty string"
        raise SecurityError(msg)

    subject = subject.strip()

    if len(subject) < 1:
        msg = "Subject too short"
        raise SecurityError(msg)

    if len(subject) > 200:
        msg = "Subject too long (maximum 200 characters)"
        raise SecurityError(msg)

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
        msg = "Predicate must be a non-empty string"
        raise SecurityError(msg)

    predicate = predicate.strip()

    if len(predicate) < 1:
        msg = "Predicate too short"
        raise SecurityError(msg)

    if len(predicate) > 200:
        msg = "Predicate too long (maximum 200 characters)"
        raise SecurityError(msg)

    return predicate


def validate_url(url: str) -> str:
    """Validate URL for web crawling (with SSRF prevention).

    Args:
        url: URL string to validate.

    Returns:
        str: Validated URL.

    Raises:
        SecurityError: If URL is invalid or points to internal network.
    """
    if not url or not isinstance(url, str):
        msg = "URL must be a non-empty string"
        raise SecurityError(msg)

    url = url.strip()

    if len(url) > MAX_URL_LENGTH:
        msg = f"URL too long (maximum {MAX_URL_LENGTH} characters)"
        raise SecurityError(msg)

    if not re.match(r"^https?://", url, re.IGNORECASE):
        msg = "URL must start with http:// or https://"
        raise SecurityError(msg)

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Block private/internal IPs (SSRF prevention)
    blocked_patterns = [
        r"^localhost$",
        r"^127\.",
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"^192\.168\.",
        r"^0\.",
        r"^\[?::1\]?$",
        r"^169\.254\.",
    ]

    for pattern in blocked_patterns:
        if re.match(pattern, hostname, re.IGNORECASE):
            msg = "URL points to a private/internal address (not allowed)"
            raise SecurityError(msg)

    return url


def validate_github_repo(repo: str) -> str:
    """Validate GitHub repository format (owner/repo).

    Args:
        repo: Repository in 'owner/repo' format.

    Returns:
        str: Validated repository string.

    Raises:
        SecurityError: If repo format is invalid.
    """
    if not repo or not isinstance(repo, str):
        msg = "Repository must be a non-empty string"
        raise SecurityError(msg)

    repo = repo.strip()

    if not re.match(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", repo):
        msg = f"Invalid repository format: '{repo}' (expected 'owner/repo')"
        raise SecurityError(msg)

    if len(repo) > 200:
        msg = "Repository name too long (maximum 200 characters)"
        raise SecurityError(msg)

    return repo


def validate_salience_boost(boost: float) -> float:
    """Validate salience boost value for reinforcement.

    Args:
        boost: Salience boost amount (0.01-0.5).

    Returns:
        float: Validated boost value.

    Raises:
        SecurityError: If boost is out of range.
    """
    if not isinstance(boost, (int, float)):
        msg = "Salience boost must be a number"
        raise SecurityError(msg)

    boost = float(boost)

    if boost < 0.01:
        msg = "Salience boost too small (minimum 0.01)"
        raise SecurityError(msg)

    if boost > 0.5:
        msg = "Salience boost too large (maximum 0.5)"
        raise SecurityError(msg)

    return boost


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
            "reinforce": (30, 30),
            "ingest": (10, 10),
            "decay": (5, 5),
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
                self.buckets[operation] = {"tokens": float(capacity), "last_update": time.time()}

            bucket = self.buckets[operation]

            now = time.time()
            elapsed = now - bucket["last_update"]
            tokens_to_add = elapsed * (rate / 60.0)
            bucket["tokens"] = min(capacity, bucket["tokens"] + tokens_to_add)
            bucket["last_update"] = now

            if bucket["tokens"] < 1.0:
                wait_time = (1.0 - bucket["tokens"]) / (rate / 60.0)
                msg = f"Rate limit exceeded for {operation}. Please wait {wait_time:.1f} seconds."
                raise SecurityError(msg)

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
    message = re.sub(r"/[a-zA-Z0-9_\-./]+", "[PATH]", message)
    message = re.sub(r"[A-Z]:\\[a-zA-Z0-9_\-\\]+", "[PATH]", message)

    # Remove potential API keys
    message = re.sub(r"\b[0-9a-f]{32}\b", "[KEY]", message, flags=re.IGNORECASE)
    message = re.sub(r"sk-[a-zA-Z0-9]+", "[KEY]", message)

    # Remove SQL queries that might leak schema
    message = re.sub(
        r"(SELECT|INSERT|UPDATE|DELETE|CREATE)\s+.*", "[SQL]", message, flags=re.IGNORECASE
    )

    # Limit length
    if len(message) > 300:
        message = message[:297] + "..."

    return message


# ============================================================================
# Audit Logging
# ============================================================================


_AUDIT_LOG_FILE = Path.home() / ".childermass" / "memory-audit.log"


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
                    with contextlib.suppress(Exception):
                        h.close()
                    logger.removeHandler(h)
        except Exception:
            for h in list(logger.handlers):
                with contextlib.suppress(Exception):
                    h.close()
                logger.removeHandler(h)

    if not logger.handlers:
        # Ensure the configured directory exists (tests may override CONFIG_DIR)
        with contextlib.suppress(Exception):
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
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
