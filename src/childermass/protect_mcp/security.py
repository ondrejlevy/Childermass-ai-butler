"""
Security utilities for UniFi Protect MCP server.

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

# UniFi Protect IDs are 24-character hex strings
_PROTECT_ID_PATTERN = re.compile(r"^[a-f0-9]{24}$")

# Max time range for event queries (7 days in milliseconds)
MAX_EVENT_RANGE_MS = 7 * 24 * 60 * 60 * 1000

# Snapshot dimension limits
MIN_SNAPSHOT_DIM = 100
MAX_SNAPSHOT_DIM = 3840

# Default snapshot dimensions (reasonable for AI assistant context)
DEFAULT_SNAPSHOT_WIDTH = 640
DEFAULT_SNAPSHOT_HEIGHT = 360

# Max number of events to return in a single query
MAX_EVENTS_PER_QUERY = 100

# Reasonable timestamp bounds (2020-01-01 to 2035-01-01 in ms)
_MIN_TIMESTAMP_MS = 1_577_836_800_000
_MAX_TIMESTAMP_MS = 2_051_222_400_000


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------


def validate_protect_id(value: str, field_name: str = "ID") -> str:
    """
    Validate a UniFi Protect ID (24-char lowercase hex).

    Returns normalised ID. Raises SecurityError on invalid input.
    """
    if not value or not isinstance(value, str):
        raise SecurityError(f"{field_name} is required")

    value = value.strip().lower()

    if not _PROTECT_ID_PATTERN.match(value):
        raise SecurityError(
            f"Invalid {field_name} format: expected 24-char hex string"
        )

    return value


def validate_camera_id(camera_id: str) -> str:
    """Validate camera ID format."""
    return validate_protect_id(camera_id, "Camera ID")


def validate_event_id(event_id: str) -> str:
    """Validate event ID format."""
    return validate_protect_id(event_id, "Event ID")


def validate_sensor_id(sensor_id: str) -> str:
    """Validate sensor ID format."""
    return validate_protect_id(sensor_id, "Sensor ID")


def validate_light_id(light_id: str) -> str:
    """Validate light ID format."""
    return validate_protect_id(light_id, "Light ID")


def validate_timestamp(ts: int | float, field_name: str = "timestamp") -> int:
    """
    Validate a Unix timestamp in milliseconds.

    Returns integer timestamp. Raises SecurityError if out of bounds.
    """
    if not isinstance(ts, (int, float)):
        raise SecurityError(f"{field_name} must be a number")

    ts = int(ts)

    if ts < _MIN_TIMESTAMP_MS:
        raise SecurityError(
            f"{field_name} is too far in the past (before 2020)"
        )

    if ts > _MAX_TIMESTAMP_MS:
        raise SecurityError(
            f"{field_name} is too far in the future (after 2035)"
        )

    return ts


def validate_time_range(start_ms: int, end_ms: int) -> tuple[int, int]:
    """
    Validate a time range for event queries.

    Returns (start, end) tuple. Raises SecurityError on invalid range.
    """
    start = validate_timestamp(start_ms, "start")
    end = validate_timestamp(end_ms, "end")

    if end <= start:
        raise SecurityError("end must be after start")

    if (end - start) > MAX_EVENT_RANGE_MS:
        raise SecurityError(
            f"Time range too large: max {MAX_EVENT_RANGE_MS // (24*60*60*1000)} days"
        )

    return start, end


def validate_snapshot_dimensions(
    width: int | None, height: int | None
) -> tuple[int, int]:
    """
    Validate and normalise snapshot dimensions.

    Returns (width, height) tuple with defaults applied.
    """
    w = width or DEFAULT_SNAPSHOT_WIDTH
    h = height or DEFAULT_SNAPSHOT_HEIGHT

    if not isinstance(w, int) or not isinstance(h, int):
        raise SecurityError("Snapshot dimensions must be integers")

    if w < MIN_SNAPSHOT_DIM or h < MIN_SNAPSHOT_DIM:
        raise SecurityError(
            f"Snapshot dimensions too small: min {MIN_SNAPSHOT_DIM}x{MIN_SNAPSHOT_DIM}"
        )

    if w > MAX_SNAPSHOT_DIM or h > MAX_SNAPSHOT_DIM:
        raise SecurityError(
            f"Snapshot dimensions too large: max {MAX_SNAPSHOT_DIM}x{MAX_SNAPSHOT_DIM}"
        )

    return w, h


def validate_event_types(types: list[str] | None) -> list[str] | None:
    """Validate event type filter values."""
    if not types:
        return None

    allowed = {"motion", "smartDetectZone", "ring", "sensorMotion", "sensorContact", "sensorAlarm"}
    for t in types:
        if t not in allowed:
            raise SecurityError(
                f"Invalid event type: {t!r}. "
                f"Allowed: {', '.join(sorted(allowed))}"
            )

    return types


def validate_smart_detect_types(types: list[str] | None) -> list[str] | None:
    """Validate smart detection type filter values."""
    if not types:
        return None

    allowed = {"person", "vehicle", "package", "animal", "face", "licensePlate"}
    for t in types:
        if t not in allowed:
            raise SecurityError(
                f"Invalid smart detection type: {t!r}. "
                f"Allowed: {', '.join(sorted(allowed))}"
            )

    return types


def validate_max_results(value: int, maximum: int = MAX_EVENTS_PER_QUERY) -> int:
    """Validate max_results parameter."""
    if not isinstance(value, int) or value < 1:
        raise SecurityError("max_results must be a positive integer")

    if value > maximum:
        raise SecurityError(f"max_results too large: max {maximum}")

    return value


def validate_hours(hours: int | float) -> int:
    """Validate hours parameter for recent activity queries."""
    if not isinstance(hours, (int, float)):
        raise SecurityError("hours must be a number")

    hours = int(hours)
    if hours < 1:
        raise SecurityError("hours must be at least 1")
    if hours > 168:  # 7 days
        raise SecurityError("hours cannot exceed 168 (7 days)")

    return hours


def validate_nvr_address(address: str) -> str:
    """
    Validate NVR IP address or hostname.

    Prevents injection attacks in URL construction.
    """
    if not address or not isinstance(address, str):
        raise SecurityError("NVR address is required")

    # Reject dangerous characters BEFORE stripping
    if any(c in address for c in ["\n", "\r", "\0", "'", '"', ";", "&", "|"]):
        raise SecurityError("NVR address contains invalid characters")

    address = address.strip()

    # Reject spaces (after strip, so leading/trailing whitespace is ok)
    if " " in address:
        raise SecurityError("NVR address contains invalid characters")

    # Must look like an IP or hostname
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    hostname_pattern = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
    )

    if not ip_pattern.match(address) and not hostname_pattern.match(address):
        raise SecurityError(f"Invalid NVR address format: {address}")

    return address


# ---------------------------------------------------------------------------
# Error Sanitization
# ---------------------------------------------------------------------------


def sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error message to prevent credential leaks.

    Strips passwords, tokens, IP addresses, cookies, and internal paths
    from error messages before they reach the LLM.
    """
    msg = str(error)

    patterns = [
        # Credentials
        (r"(password|token|key|secret|credential|cookie)[\s:=]+\S+", r"\1=***"),
        (r"Bearer \S+", "Bearer ***"),
        (r"TOKEN=[^\s;]+", "TOKEN=***"),
        (r"(X-CSRF-Token|x-csrf-token)[\s:]+\S+", r"\1: ***"),
        # IP addresses in error messages
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b", "***NVR_IP***"),
        # File paths
        (r"/Users/[^\s\"']+", "/***/..."),
        (r"/home/[^\s\"']+", "/***/..."),
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
    Thread-safe per-operation rate limiter.

    Default limits (per minute):
      - snapshot:        10
      - thumbnail:       20
      - events:          30
      - bootstrap:        5
      - read (general):  60
      - write (PATCH):   10
    """

    DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        # (capacity, refill_rate tokens/sec)
        "snapshot": (10, 10 / 60),
        "thumbnail": (20, 20 / 60),
        "events": (30, 30 / 60),
        "bootstrap": (5, 5 / 60),
        "read": (60, 60 / 60),
        "write": (10, 10 / 60),
    }

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()

    def _key(self, operation: str) -> str:
        return operation

    def allow(self, operation: str) -> bool:
        """
        Check if operation is allowed under rate limits.

        Returns True and consumes a token, or False if rate-limited.
        """
        key = self._key(operation)
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

    def check(self, operation: str) -> None:
        """Like allow() but raises SecurityError on rate limit."""
        if not self.allow(operation):
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
_AUDIT_LOG_FILE = _AUDIT_DIR / "protect-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.protect_mcp.audit")
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
    details: dict[str, Any] | None = None,
    success: bool = True,
) -> None:
    """
    Write a structured audit log entry.

    Args:
        operation: Operation name (e.g. "get_snapshot", "list_events")
        details: Additional context (sanitised – no credentials!)
        success: Whether the operation succeeded
    """
    logger = _get_audit_logger()

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "operation": operation,
        "success": success,
    }
    if details:
        entry["details"] = details

    try:
        logger.info(json.dumps(entry, ensure_ascii=False))
    except Exception:
        pass  # Audit logging must never crash the server
