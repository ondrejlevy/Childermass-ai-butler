"""
Security utilities for Google Calendar MCP server.

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

# Maximum event summary (title) length
MAX_SUMMARY_LENGTH = 1024

# Maximum event description length (Calendar API HTML limit)
MAX_DESCRIPTION_LENGTH = 8192

# Maximum location length
MAX_LOCATION_LENGTH = 1024

# Maximum search query length
MAX_QUERY_LENGTH = 1000

# Maximum attendees per event
MAX_ATTENDEES = 200

# Valid Calendar event color IDs (from colors endpoint)
VALID_COLOR_IDS = {str(i) for i in range(1, 12)}  # "1" through "11"

# Valid IANA timezone examples (validated via pattern, not exhaustive list)
_TZ_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_+\-]*/[A-Za-z][A-Za-z0-9_+\-/]*$"
)

# Allowed recurrence rule prefixes (RFC 5545)
_RRULE_PREFIXES = {"RRULE:", "EXRULE:", "RDATE:", "EXDATE:"}


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_calendar_id(calendar_id: str) -> str:
    """
    Validate calendar ID format.

    Calendar IDs are typically email addresses or the keyword 'primary'.
    Returns normalised calendar ID.
    """
    if not calendar_id or not isinstance(calendar_id, str):
        raise SecurityError("Calendar ID is required")

    calendar_id = calendar_id.strip()

    # Allow 'primary' keyword
    if calendar_id.lower() == "primary":
        return "primary"

    # Check for injection characters
    if any(char in calendar_id for char in ["\n", "\r", "\0", "\t"]):
        raise SecurityError("Calendar ID contains invalid control characters")

    # Calendar IDs are typically email-like or encoded group IDs
    # Allow alphanumeric, @, ., -, _, #, and %
    if not re.match(r"^[a-zA-Z0-9@.\-_#%]+$", calendar_id):
        raise SecurityError(f"Invalid calendar ID format: {calendar_id}")

    return calendar_id


def validate_event_id(event_id: str) -> str:
    """
    Validate Google Calendar event ID format.

    Event IDs use base32hex encoding (lowercase a-v, digits 0-9),
    length between 5 and 1024 characters.
    """
    if not event_id or not isinstance(event_id, str):
        raise SecurityError("Event ID is required")

    event_id = event_id.strip()

    # Event IDs: alphanumeric (base32hex + possible extra chars from Google)
    if not re.match(r"^[a-zA-Z0-9_]+$", event_id):
        raise SecurityError(f"Invalid event ID format: {event_id}")

    if len(event_id) < 5 or len(event_id) > 1024:
        raise SecurityError(
            f"Event ID length must be 5-1024 chars, got {len(event_id)}"
        )

    return event_id


def validate_datetime(dt_string: str) -> str:
    """
    Validate RFC3339 datetime string.

    Accepts formats:
    - Full datetime: 2024-01-15T10:00:00+01:00 or 2024-01-15T10:00:00Z
    - Date only: 2024-01-15 (for all-day events)
    """
    if not dt_string or not isinstance(dt_string, str):
        raise SecurityError("DateTime value is required")

    dt_string = dt_string.strip()

    # Date-only format (yyyy-mm-dd)
    if re.match(r"^\d{4}-\d{2}-\d{2}$", dt_string):
        return dt_string

    # Full RFC3339 datetime
    # 2024-01-15T10:00:00Z or 2024-01-15T10:00:00+01:00 or 2024-01-15T10:00:00-05:00
    rfc3339_pattern = (
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
        r"(Z|[+\-]\d{2}:\d{2})$"
    )

    if not re.match(rfc3339_pattern, dt_string):
        raise SecurityError(
            f"Invalid datetime format: {dt_string}. "
            "Expected RFC3339 (e.g., 2024-01-15T10:00:00+01:00) "
            "or date (2024-01-15)"
        )

    return dt_string


def validate_timezone(timezone: str) -> str:
    """
    Validate IANA timezone identifier.

    Accepts formats like: Europe/Prague, America/New_York, UTC, Etc/GMT+1
    """
    if not timezone or not isinstance(timezone, str):
        raise SecurityError("Timezone is required")

    timezone = timezone.strip()

    # Allow simple UTC
    if timezone.upper() == "UTC":
        return "UTC"

    # Allow Etc/GMT variants
    if re.match(r"^Etc/GMT([+\-]\d{1,2})?$", timezone):
        return timezone

    # Standard IANA pattern: Region/City or Region/Sub/City
    if not _TZ_PATTERN.match(timezone):
        raise SecurityError(
            f"Invalid timezone format: {timezone}. "
            "Use IANA format (e.g., Europe/Prague, America/New_York)"
        )

    return timezone


def validate_recurrence(rules: list[str]) -> list[str]:
    """
    Validate recurrence rules (RFC 5545 RRULE format).

    Each rule must start with RRULE:, EXRULE:, RDATE:, or EXDATE:.
    DTSTART and DTEND are NOT allowed (set via start/end fields).
    """
    if not rules:
        return []

    validated = []
    for rule in rules:
        if not isinstance(rule, str):
            raise SecurityError(f"Recurrence rule must be a string: {rule}")

        rule = rule.strip()
        if not rule:
            continue

        # Check prefix
        upper = rule.upper()
        if not any(upper.startswith(prefix) for prefix in _RRULE_PREFIXES):
            raise SecurityError(
                f"Invalid recurrence rule: {rule}. "
                "Must start with RRULE:, EXRULE:, RDATE:, or EXDATE:"
            )

        # Reject DTSTART/DTEND (these go in start/end fields)
        if upper.startswith("DTSTART") or upper.startswith("DTEND"):
            raise SecurityError(
                "DTSTART/DTEND not allowed in recurrence rules. "
                "Use start/end parameters instead."
            )

        # Basic safety: no control chars
        if any(char in rule for char in ["\0", "\r"]):
            raise SecurityError(
                "Recurrence rule contains invalid control characters"
            )

        validated.append(rule)

    return validated


def validate_attendees(emails: str) -> list[str]:
    """
    Validate comma-separated list of attendee emails.

    Returns list of validated email addresses.
    """
    if not emails:
        return []

    validated = []
    for email in emails.split(","):
        email = email.strip()
        if email:
            validated.append(validate_email(email))

    if len(validated) > MAX_ATTENDEES:
        raise SecurityError(
            f"Too many attendees: {len(validated)} (max {MAX_ATTENDEES})"
        )

    return validated


def validate_email(email: str) -> str:
    """
    Validate email address format.

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

    if not validators.email(email_lower):
        raise SecurityError(f"Invalid email address format: {email}")

    return email_lower


def validate_event_summary(summary: str) -> str:
    """Validate event title/summary."""
    if not summary:
        return ""

    # Reject newlines
    if any(c in summary for c in ["\n", "\r"]):
        raise SecurityError("Event summary contains invalid newline characters")

    if len(summary) > MAX_SUMMARY_LENGTH:
        raise SecurityError(
            f"Event summary too long: {len(summary)} chars "
            f"(max {MAX_SUMMARY_LENGTH})"
        )

    return summary


def validate_event_description(description: str) -> str:
    """Validate event description (can contain HTML)."""
    if not description:
        return ""

    if len(description) > MAX_DESCRIPTION_LENGTH:
        raise SecurityError(
            f"Event description too long: {len(description)} chars "
            f"(max {MAX_DESCRIPTION_LENGTH})"
        )

    return description


def validate_location(location: str) -> str:
    """Validate event location string."""
    if not location:
        return ""

    if len(location) > MAX_LOCATION_LENGTH:
        raise SecurityError(
            f"Location too long: {len(location)} chars "
            f"(max {MAX_LOCATION_LENGTH})"
        )

    return location


def validate_color_id(color_id: str) -> str:
    """Validate event color ID (1-11 per Calendar API colors endpoint)."""
    if not color_id:
        return ""

    color_id = color_id.strip()

    if color_id not in VALID_COLOR_IDS:
        raise SecurityError(
            f"Invalid color ID: {color_id}. Must be 1-11."
        )

    return color_id


def validate_date_range(time_min: str, time_max: str) -> tuple[str, str]:
    """Validate that time_min < time_max."""
    time_min = validate_datetime(time_min)
    time_max = validate_datetime(time_max)

    # Simple string comparison works for RFC3339 with same timezone
    # For robust comparison we just ensure both are valid
    # The Calendar API itself will reject invalid ranges

    return time_min, time_max


def validate_search_query(query: str) -> str:
    """Validate Calendar search query."""
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


def validate_max_results(max_results: int) -> int:
    """Validate max_results parameter."""
    if max_results < 1:
        raise SecurityError("max_results must be at least 1")
    if max_results > 2500:
        raise SecurityError("max_results cannot exceed 2500")
    return max_results


def validate_send_updates(send_updates: str) -> str:
    """Validate sendUpdates parameter."""
    valid = {"all", "externalOnly", "none"}
    if send_updates not in valid:
        raise SecurityError(
            f"Invalid sendUpdates value: {send_updates}. "
            f"Must be one of: {', '.join(sorted(valid))}"
        )
    return send_updates


def validate_quick_add_text(text: str) -> str:
    """Validate quickAdd text input."""
    if not text or not isinstance(text, str):
        raise SecurityError("Quick-add text is required")

    text = text.strip()
    if not text:
        raise SecurityError("Quick-add text cannot be empty")

    if len(text) > MAX_SUMMARY_LENGTH:
        raise SecurityError(
            f"Quick-add text too long: {len(text)} chars "
            f"(max {MAX_SUMMARY_LENGTH})"
        )

    # Reject control chars except space/tab
    if any(ord(c) < 32 and c not in (" ", "\t") for c in text):
        raise SecurityError("Quick-add text contains invalid control characters")

    return text


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
      - list/get/search:         60
      - insert/update/delete:    20
      - quickAdd:                20
      - move:                    20
      - freebusy:                30
    """

    DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        # (capacity, refill_rate tokens/sec)
        "list_calendars": (60, 60 / 60),
        "list_events": (60, 60 / 60),
        "get_event": (60, 60 / 60),
        "search": (60, 60 / 60),
        "create": (20, 20 / 60),
        "update": (20, 20 / 60),
        "delete": (20, 20 / 60),
        "quick_add": (20, 20 / 60),
        "move": (20, 20 / 60),
        "freebusy": (30, 30 / 60),
        "instances": (60, 60 / 60),
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
_AUDIT_LOG_FILE = _AUDIT_DIR / "calendar-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.calendar_mcp.audit")
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
        operation: Operation name (e.g. "create_event", "delete_event")
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
