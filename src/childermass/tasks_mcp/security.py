"""
Security utilities for Google Tasks MCP server.

Provides input validation, sanitization, rate limiting, and audit logging.
"""

import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any


class SecurityError(Exception):
    """Raised when security validation fails."""

    pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum task title length (Google Tasks API limit)
MAX_TITLE_LENGTH = 1024

# Maximum task notes length (Google Tasks API limit)
MAX_NOTES_LENGTH = 8192

# Maximum search query length
MAX_QUERY_LENGTH = 1000

# Valid task statuses
VALID_TASK_STATUSES = {"needsAction", "completed"}


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_tasklist_id(tasklist_id: str) -> str:
    """
    Validate task list ID format.

    Task list IDs are opaque strings assigned by Google.
    Returns normalised task list ID.
    """
    if not tasklist_id or not isinstance(tasklist_id, str):
        raise SecurityError("Task list ID is required")

    tasklist_id = tasklist_id.strip()

    # Check for injection characters
    if any(char in tasklist_id for char in ["\n", "\r", "\0", "\t"]):
        raise SecurityError(
            "Task list ID contains invalid control characters"
        )

    # Task list IDs are alphanumeric strings (base64-like)
    if not re.match(r"^[a-zA-Z0-9_-]+$", tasklist_id):
        raise SecurityError(
            f"Invalid task list ID format: {tasklist_id}"
        )

    return tasklist_id


def validate_task_id(task_id: str) -> str:
    """
    Validate task ID format.

    Task IDs are opaque strings assigned by Google.
    """
    if not task_id or not isinstance(task_id, str):
        raise SecurityError("Task ID is required")

    task_id = task_id.strip()

    # Check for injection characters
    if any(char in task_id for char in ["\n", "\r", "\0", "\t"]):
        raise SecurityError("Task ID contains invalid control characters")

    # Task IDs are alphanumeric strings
    if not re.match(r"^[a-zA-Z0-9_-]+$", task_id):
        raise SecurityError(f"Invalid task ID format: {task_id}")

    return task_id


def validate_task_title(title: str) -> str:
    """
    Validate task title.

    Returns validated title. Raises SecurityError on invalid input.
    Maximum length: 1024 characters.
    """
    if not title or not isinstance(title, str):
        raise SecurityError("Task title is required")

    title = title.strip()
    if not title:
        raise SecurityError("Task title cannot be empty")

    # Reject newlines (potential injection)
    if any(c in title for c in ["\r"]):
        raise SecurityError(
            "Task title contains invalid carriage return characters"
        )

    if len(title) > MAX_TITLE_LENGTH:
        raise SecurityError(
            f"Task title too long: {len(title)} chars "
            f"(max {MAX_TITLE_LENGTH})"
        )

    return title


def validate_tasklist_title(title: str) -> str:
    """
    Validate task list title.

    Returns validated title. Same rules as task title.
    """
    return validate_task_title(title)


def validate_task_notes(notes: str) -> str:
    """
    Validate task notes.

    Returns validated notes. Maximum length: 8192 characters.
    """
    if not notes:
        return ""

    if len(notes) > MAX_NOTES_LENGTH:
        raise SecurityError(
            f"Task notes too long: {len(notes)} chars "
            f"(max {MAX_NOTES_LENGTH})"
        )

    return notes


def validate_task_status(status: str) -> str:
    """
    Validate task status value.

    Only "needsAction" and "completed" are valid.
    """
    if not status or not isinstance(status, str):
        raise SecurityError("Task status is required")

    status = status.strip()

    if status not in VALID_TASK_STATUSES:
        raise SecurityError(
            f"Invalid task status: {status}. "
            f"Must be one of: {', '.join(sorted(VALID_TASK_STATUSES))}"
        )

    return status


def validate_due_date(due: str) -> str:
    """
    Validate task due date.

    The Tasks API accepts RFC3339 timestamps but only uses the date portion.
    Accepts:
    - Full RFC3339: 2024-01-15T00:00:00Z or 2024-01-15T00:00:00+01:00
    - Date only: 2024-01-15 (will be converted to RFC3339)
    """
    if not due or not isinstance(due, str):
        raise SecurityError("Due date is required")

    due = due.strip()

    # Date-only format (yyyy-mm-dd) – convert to RFC3339
    if re.match(r"^\d{4}-\d{2}-\d{2}$", due):
        return f"{due}T00:00:00.000Z"

    # Full RFC3339 datetime
    rfc3339_pattern = (
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
        r"(\.\d+)?"
        r"(Z|[+\-]\d{2}:\d{2})$"
    )

    if not re.match(rfc3339_pattern, due):
        raise SecurityError(
            f"Invalid due date format: {due}. "
            "Expected RFC3339 (e.g., 2024-01-15T00:00:00Z) "
            "or date (2024-01-15)"
        )

    return due


def validate_max_results(max_results: int) -> int:
    """Validate max_results parameter."""
    if max_results < 1:
        raise SecurityError("max_results must be at least 1")
    if max_results > 100:
        raise SecurityError("max_results cannot exceed 100")
    return max_results


def validate_search_query(query: str) -> str:
    """Validate search query string."""
    if not query:
        return ""

    # Reject control characters
    suspicious = ["\0", "\r", chr(0x1B)]
    if any(char in query for char in suspicious):
        raise SecurityError("Query contains invalid control characters")

    if len(query) > MAX_QUERY_LENGTH:
        raise SecurityError(
            f"Query too long (max {MAX_QUERY_LENGTH} characters)"
        )

    return query


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error message to prevent credential leaks.
    """
    msg = str(error)

    patterns = [
        (r"(password|token|key|secret|credential)[\s:=]+\S+", r"\1=***"),
        (r"Bearer \S+", "Bearer ***"),
        (r"ya29\.\S+", "ya29.***"),  # Google access tokens
        (r"1//[A-Za-z0-9_-]+", "1//***"),  # Google refresh tokens
        (r"/[\w\-\.]+/[\w\-\.]+\.json", "/***/credentials.json"),
    ]

    for pattern, replacement in patterns:
        msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)

    return msg


# ---------------------------------------------------------------------------
# Rate Limiting (Token Bucket Algorithm)
# ---------------------------------------------------------------------------


@dataclass
class _Bucket:
    """Token bucket for rate limiting."""

    tokens: float
    last_refill: float
    capacity: int
    refill_rate: float  # tokens per second


class RateLimiter:
    """
    Thread-safe per-account, per-operation rate limiter.

    Default limits (per minute):
      - list/get:                  60
      - create/update/complete:    30
      - delete:                    10
      - move:                      20
      - clear:                     10
    """

    DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        # (capacity, refill_rate tokens/sec)
        "list_tasklists": (60, 60 / 60),
        "get_tasklist": (60, 60 / 60),
        "create_tasklist": (20, 20 / 60),
        "update_tasklist": (20, 20 / 60),
        "delete_tasklist": (10, 10 / 60),
        "list_tasks": (60, 60 / 60),
        "get_task": (60, 60 / 60),
        "create_task": (30, 30 / 60),
        "update_task": (30, 30 / 60),
        "complete_task": (30, 30 / 60),
        "delete_task": (10, 10 / 60),
        "move_task": (20, 20 / 60),
        "clear_completed": (10, 10 / 60),
    }

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()

    def _key(self, account: str, operation: str) -> str:
        return f"{account}:{operation}"

    def allow(self, account: str, operation: str) -> bool:
        """
        Check if operation is allowed under rate limits.

        Returns True and consumes a token, or False if rate-limited.
        """
        key = self._key(account, operation)
        capacity, refill_rate = self.DEFAULT_LIMITS.get(operation, (60, 1.0))

        with self._lock:
            now = time.monotonic()

            if key not in self._buckets:
                self._buckets[key] = _Bucket(
                    tokens=capacity - 1,
                    last_refill=now,
                    capacity=capacity,
                    refill_rate=refill_rate,
                )
                return True

            bucket = self._buckets[key]

            # Refill tokens
            elapsed = now - bucket.last_refill
            bucket.tokens = min(
                bucket.capacity,
                bucket.tokens + elapsed * bucket.refill_rate,
            )
            bucket.last_refill = now

            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return True

            return False

    def check(self, account: str, operation: str) -> None:
        """Like allow() but raises SecurityError on rate limit."""
        if not self.allow(account, operation):
            raise SecurityError(
                f"Rate limit exceeded for {operation}. "
                "Please wait before retrying."
            )


# Module-level singleton
rate_limiter = RateLimiter()


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------

_AUDIT_DIR = Path.home() / ".childermass"
_AUDIT_LOG_FILE = _AUDIT_DIR / "tasks-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.tasks_mcp.audit")
    if not logger.handlers:
        _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        from logging.handlers import RotatingFileHandler

        handler = RotatingFileHandler(
            str(_AUDIT_LOG_FILE),
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
    """
    Write a structured audit log entry.

    Args:
        operation: Operation name (e.g. "create_task", "complete_task")
        account: Email account used
        details: Additional context (sanitised – no credentials!)
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
