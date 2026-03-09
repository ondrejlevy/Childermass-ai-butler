"""
Security utilities for Tracking MCP server.

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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum tracking URL length
MAX_URL_LENGTH = 2048

# Maximum text input lengths
MAX_TRACKING_NUMBER_LENGTH = 100
MAX_ORDER_NUMBER_LENGTH = 100
MAX_STATUS_DETAIL_LENGTH = 2000
MAX_EMAIL_BODY_LENGTH = 500_000  # ~500 KB
MAX_METADATA_LENGTH = 10_000

# Allowed carriers
ALLOWED_CARRIERS = {
    "zasilkovna",
    "balikovna",
    "ceska_posta",
    "ppl",
    "dpd",
    "gls",
    "alza",
    "rohlik",
    "amazon",
    "dhl",
    "unknown",
}

# Allowed shipment statuses
ALLOWED_STATUSES = {
    "registered",
    "in_transit",
    "out_for_delivery",
    "delivered",
    "pickup_ready",
    "returned",
    "cancelled",
    "unknown",
}


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------


def validate_url(url: str, field_name: str = "URL") -> str:
    """
    Validate a URL string.

    Returns normalised URL. Raises SecurityError on invalid input.
    """
    if not url or not isinstance(url, str):
        msg = f"{field_name} is required"
        raise SecurityError(msg)

    url = url.strip()

    if len(url) > MAX_URL_LENGTH:
        msg = f"{field_name} too long (max {MAX_URL_LENGTH} characters)"
        raise SecurityError(msg)

    # Reject control characters
    if any(c in url for c in ["\n", "\r", "\0", "\t"]):
        msg = f"{field_name} contains invalid control characters"
        raise SecurityError(msg)

    # Must be http or https
    if not url.startswith(("http://", "https://")):
        msg = f"{field_name} must start with http:// or https://"
        raise SecurityError(msg)

    if not validators.url(url):
        msg = f"Invalid {field_name} format: {url}"
        raise SecurityError(msg)

    return url


def validate_tracking_number(tracking_number: str) -> str:
    """Validate tracking number format."""
    if not tracking_number or not isinstance(tracking_number, str):
        msg = "Tracking number is required"
        raise SecurityError(msg)

    tracking_number = tracking_number.strip()

    if len(tracking_number) > MAX_TRACKING_NUMBER_LENGTH:
        msg = f"Tracking number too long (max {MAX_TRACKING_NUMBER_LENGTH} characters)"
        raise SecurityError(msg)

    # Allow alphanumeric, hyphens, spaces
    if not re.match(r"^[a-zA-Z0-9\s\-]+$", tracking_number):
        msg = "Tracking number contains invalid characters"
        raise SecurityError(msg)

    return tracking_number


def validate_order_number(order_number: str) -> str:
    """Validate order number format."""
    if not order_number or not isinstance(order_number, str):
        msg = "Order number is required"
        raise SecurityError(msg)

    order_number = order_number.strip()

    if len(order_number) > MAX_ORDER_NUMBER_LENGTH:
        msg = f"Order number too long (max {MAX_ORDER_NUMBER_LENGTH} characters)"
        raise SecurityError(msg)

    # Allow alphanumeric, hyphens, underscores, dots
    if not re.match(r"^[a-zA-Z0-9\s\-_.]+$", order_number):
        msg = "Order number contains invalid characters"
        raise SecurityError(msg)

    return order_number


def validate_carrier(carrier: str) -> str:
    """Validate carrier identifier."""
    if not carrier or not isinstance(carrier, str):
        msg = "Carrier is required"
        raise SecurityError(msg)

    carrier = carrier.strip().lower()

    if carrier not in ALLOWED_CARRIERS:
        msg = f"Unknown carrier: {carrier}. Allowed: {', '.join(sorted(ALLOWED_CARRIERS))}"
        raise SecurityError(msg)

    return carrier


def validate_status(status: str) -> str:
    """Validate shipment status."""
    if not status or not isinstance(status, str):
        msg = "Status is required"
        raise SecurityError(msg)

    status = status.strip().lower()

    if status not in ALLOWED_STATUSES:
        msg = f"Unknown status: {status}. Allowed: {', '.join(sorted(ALLOWED_STATUSES))}"
        raise SecurityError(msg)

    return status


def validate_shipment_id(shipment_id: str) -> str:
    """Validate shipment ID (UUID format)."""
    if not shipment_id or not isinstance(shipment_id, str):
        msg = "Shipment ID is required"
        raise SecurityError(msg)

    shipment_id = shipment_id.strip()

    # UUID format
    uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    if not uuid_pattern.match(shipment_id.lower()):
        msg = f"Invalid shipment ID format (expected UUID): {shipment_id}"
        raise SecurityError(msg)

    return shipment_id.lower()


def validate_email_body(body: str) -> str:
    """Validate email body length."""
    if body and len(body) > MAX_EMAIL_BODY_LENGTH:
        msg = f"Email body too long: {len(body)} chars (max {MAX_EMAIL_BODY_LENGTH})"
        raise SecurityError(msg)
    return body or ""


def validate_email_subject(subject: str) -> str:
    """Validate email subject."""
    if not subject or not isinstance(subject, str):
        return ""
    # Reject newlines (header injection)
    if any(c in subject for c in ["\n", "\r"]):
        msg = "Subject contains invalid newline characters"
        raise SecurityError(msg)
    if len(subject) > 998:  # RFC 5322
        msg = "Subject too long (max 998 chars)"
        raise SecurityError(msg)
    return subject


def validate_email_from(from_addr: str) -> str:
    """Validate email sender address."""
    if not from_addr or not isinstance(from_addr, str):
        msg = "Email sender address is required"
        raise SecurityError(msg)

    from_addr = from_addr.strip()

    if len(from_addr) > 500:
        msg = "Email sender address too long"
        raise SecurityError(msg)

    # Reject control characters
    if any(c in from_addr for c in ["\n", "\r", "\0"]):
        msg = "Email sender contains invalid characters"
        raise SecurityError(msg)

    return from_addr


def validate_metadata(metadata: str) -> str:
    """Validate JSON metadata string."""
    if not metadata:
        return "{}"

    if len(metadata) > MAX_METADATA_LENGTH:
        msg = f"Metadata too long (max {MAX_METADATA_LENGTH} characters)"
        raise SecurityError(msg)

    try:
        json.loads(metadata)
    except json.JSONDecodeError as e:
        msg = f"Invalid JSON metadata: {e}"
        raise SecurityError(msg) from e

    return metadata


# ---------------------------------------------------------------------------
# Error Sanitization
# ---------------------------------------------------------------------------


def sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error message to prevent credential leaks.
    """
    msg = str(error)

    patterns = [
        (r"(password|token|key|secret|credential)[\s:=]+\S+", r"\1=***"),
        (r"Bearer \S+", "Bearer ***"),
        (r"(cookie|session)[\s:=]+\S+", r"\1=***"),
        # File paths
        (r"/Users/[^\s\"']+", "/***/..."),
        (r"/home/[^\s\"']+", "/***/..."),
        # IP addresses
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b", "***"),
    ]

    for pattern, replacement in patterns:
        msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)

    # Limit length
    if len(msg) > 500:
        msg = msg[:497] + "..."

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
      - scrape:    20  (web scraping is slow)
      - register:  30
      - read:      60
      - parse:     30
      - batch:      5  (check_all is heavy)
    """

    DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        # (capacity, refill_rate tokens/sec)
        "scrape": (20, 20 / 60),
        "register": (30, 30 / 60),
        "read": (60, 60 / 60),
        "parse": (30, 30 / 60),
        "batch": (5, 5 / 60),
        "archive": (30, 30 / 60),
    }

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()

    def allow(self, operation: str) -> bool:
        """
        Check if operation is allowed under rate limits.

        Returns True and consumes a token, or False if rate-limited.
        """
        capacity, refill_rate = self.DEFAULT_LIMITS.get(operation, (60, 1.0))

        with self._lock:
            now = time.monotonic()

            if operation not in self._buckets:
                self._buckets[operation] = _Bucket(
                    tokens=capacity - 1,
                    last_refill=now,
                    capacity=capacity,
                    refill_rate=refill_rate,
                )
                return True

            bucket = self._buckets[operation]

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
            msg = f"Rate limit exceeded for {operation}. Please wait before retrying."
            raise SecurityError(msg)


# Module-level singleton
rate_limiter = RateLimiter()


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------

_AUDIT_DIR = Path.home() / ".childermass"
_AUDIT_LOG_FILE = _AUDIT_DIR / "tracking-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.tracking_mcp.audit")
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
        operation: Operation name (e.g. "register_shipment", "scrape_status")
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
