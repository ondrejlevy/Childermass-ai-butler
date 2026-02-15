"""
Security utilities for Google Keep MCP server.

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

import validators


class SecurityError(Exception):
    """Raised when security validation fails."""

    pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum note title length (Keep limit)
MAX_TITLE_LENGTH = 1_000

# Maximum note text length (Keep limit)
MAX_TEXT_LENGTH = 20_000

# Maximum list item text length (Keep limit)
MAX_LIST_ITEM_LENGTH = 1_000

# Maximum number of list items per note (Keep limit)
MAX_LIST_ITEMS = 1_000

# Maximum label name length
MAX_LABEL_LENGTH = 100

# Maximum number of collaborators per note
MAX_COLLABORATORS = 50

# Valid Keep note colors
VALID_COLORS: set[str] = {
    "white",
    "red",
    "orange",
    "yellow",
    "green",
    "teal",
    "blue",
    "cerulean",
    "purple",
    "pink",
    "brown",
    "gray",
}

# Valid note types
VALID_NOTE_TYPES: set[str] = {"text", "list"}


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_note_title(title: str) -> str:
    """
    Validate note title.

    Returns normalised title. Raises SecurityError on invalid input.
    """
    if title is None:
        return ""

    if not isinstance(title, str):
        raise SecurityError("Title must be a string")

    # Reject control characters (except newline/tab which are valid)
    suspicious = ["\0", "\r", chr(0x1B)]
    if any(char in title for char in suspicious):
        raise SecurityError("Title contains invalid control characters")

    if len(title) > MAX_TITLE_LENGTH:
        raise SecurityError(
            f"Title too long: {len(title)} chars (max {MAX_TITLE_LENGTH})"
        )

    return title


def validate_note_text(text: str) -> str:
    """
    Validate note text content.

    Returns validated text. Raises SecurityError on invalid input.
    """
    if text is None:
        return ""

    if not isinstance(text, str):
        raise SecurityError("Text must be a string")

    suspicious = ["\0", chr(0x1B)]
    if any(char in text for char in suspicious):
        raise SecurityError("Text contains invalid control characters")

    if len(text) > MAX_TEXT_LENGTH:
        raise SecurityError(
            f"Text too long: {len(text)} chars (max {MAX_TEXT_LENGTH})"
        )

    return text


def validate_list_item_text(text: str) -> str:
    """
    Validate list item text.

    Returns validated text. Raises SecurityError on invalid input.
    """
    if not text or not isinstance(text, str):
        raise SecurityError("List item text is required")

    suspicious = ["\0", chr(0x1B)]
    if any(char in text for char in suspicious):
        raise SecurityError("List item text contains invalid control characters")

    text = text.strip()

    if len(text) > MAX_LIST_ITEM_LENGTH:
        raise SecurityError(
            f"List item too long: {len(text)} chars (max {MAX_LIST_ITEM_LENGTH})"
        )

    return text


def validate_note_id(note_id: str) -> str:
    """
    Validate Keep note ID format.

    Returns validated note ID. Raises SecurityError on invalid input.
    """
    if not note_id or not isinstance(note_id, str):
        raise SecurityError("Note ID is required")

    note_id = note_id.strip()

    # Reject control characters
    if any(char in note_id for char in ["\n", "\r", "\0", "\t"]):
        raise SecurityError("Note ID contains invalid control characters")

    # Keep note IDs are alphanumeric with possible hyphens/underscores/dots
    if not re.match(r"^[a-zA-Z0-9._-]+$", note_id):
        raise SecurityError(f"Invalid note ID format: {note_id}")

    if len(note_id) > 200:
        raise SecurityError("Note ID too long")

    return note_id


def validate_item_id(item_id: str) -> str:
    """
    Validate Keep list item ID format.

    Returns validated item ID. Raises SecurityError on invalid input.
    """
    if not item_id or not isinstance(item_id, str):
        raise SecurityError("Item ID is required")

    item_id = item_id.strip()

    if any(char in item_id for char in ["\n", "\r", "\0", "\t"]):
        raise SecurityError("Item ID contains invalid control characters")

    if not re.match(r"^[a-zA-Z0-9._-]+$", item_id):
        raise SecurityError(f"Invalid item ID format: {item_id}")

    if len(item_id) > 200:
        raise SecurityError("Item ID too long")

    return item_id


def validate_color(color: str) -> str:
    """
    Validate Keep note color.

    Returns normalised color name. Raises SecurityError on invalid input.
    """
    if not color or not isinstance(color, str):
        raise SecurityError("Color is required")

    color = color.lower().strip()

    if color not in VALID_COLORS:
        raise SecurityError(
            f"Invalid color: {color}. Valid colors: {', '.join(sorted(VALID_COLORS))}"
        )

    return color


def validate_note_type(note_type: str) -> str:
    """
    Validate note type.

    Returns normalised note type. Raises SecurityError on invalid input.
    """
    if not note_type or not isinstance(note_type, str):
        raise SecurityError("Note type is required")

    note_type = note_type.lower().strip()

    if note_type not in VALID_NOTE_TYPES:
        raise SecurityError(
            f"Invalid note type: {note_type}. Valid types: {', '.join(sorted(VALID_NOTE_TYPES))}"
        )

    return note_type


def validate_label_name(name: str) -> str:
    """
    Validate label name.

    Returns validated label name. Raises SecurityError on invalid input.
    """
    if not name or not isinstance(name, str):
        raise SecurityError("Label name is required")

    name = name.strip()

    suspicious = ["\0", "\r", chr(0x1B)]
    if any(char in name for char in suspicious):
        raise SecurityError("Label name contains invalid control characters")

    if len(name) > MAX_LABEL_LENGTH:
        raise SecurityError(
            f"Label name too long: {len(name)} chars (max {MAX_LABEL_LENGTH})"
        )

    return name


def validate_email(email: str) -> str:
    """
    Validate email address format for collaborator operations.

    Returns normalised email address. Raises SecurityError on invalid input.
    """
    if not email or not isinstance(email, str):
        raise SecurityError("Email address is required")

    email = email.strip()

    # Extract email from "Name <email@example.com>" format
    if "<" in email and ">" in email:
        match = re.search(r"<([^>]+)>", email)
        if match:
            email = match.group(1).strip()

    email_lower = email.lower()

    # Check for injection characters
    if any(char in email_lower for char in ["\n", "\r", "\0", "\t"]):
        raise SecurityError("Email contains invalid control characters")

    # Basic email format check
    if not validators.email(email_lower):
        raise SecurityError(f"Invalid email address format: {email}")

    return email_lower


def validate_query(query: str) -> str:
    """Validate search query string."""
    if not query:
        return ""

    suspicious = ["\0", "\r", chr(0x1B)]
    if any(char in query for char in suspicious):
        raise SecurityError("Query contains invalid control characters")

    if len(query) > 1000:
        raise SecurityError("Query too long (max 1000 characters)")

    return query


def validate_max_results(max_results: int) -> int:
    """Validate and clamp max_results parameter."""
    return min(max(1, max_results), 500)


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error message to prevent credential leaks.
    """
    msg = str(error)

    patterns = [
        (r"(password|token|key|secret|credential|master_token)[\s:=]+\S+", r"\1=***"),
        (r"Bearer \S+", "Bearer ***"),
        (r"ya29\.\S+", "ya29.***"),  # Google access tokens
        (r"1//[A-Za-z0-9_-]+", "1//***"),  # Google refresh tokens
        (r"aas_et/[A-Za-z0-9_-]+", "aas_et/***"),  # Master tokens
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
      - create/update/delete:  20
      - share/unshare:         10
      - list/get/search:       60
      - check/uncheck:         30
      - label operations:      20
    """

    DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        # (capacity, refill_rate tokens/sec)
        "create": (20, 20 / 60),
        "update": (20, 20 / 60),
        "delete": (20, 20 / 60),
        "share": (10, 10 / 60),
        "unshare": (10, 10 / 60),
        "list": (60, 60 / 60),
        "get": (60, 60 / 60),
        "search": (60, 60 / 60),
        "check": (30, 30 / 60),
        "uncheck": (30, 30 / 60),
        "add_item": (30, 30 / 60),
        "delete_item": (30, 30 / 60),
        "label": (20, 20 / 60),
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
_AUDIT_LOG_FILE = _AUDIT_DIR / "keep-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.keep_mcp.audit")
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
        operation: Operation name (e.g. "create_note", "share_note")
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
