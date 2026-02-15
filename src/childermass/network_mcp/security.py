"""
Security utilities for UniFi Network MCP server.

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

# UniFi Network API uses UUIDs for IDs
_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

# VLAN ID range
MIN_VLAN_ID = 1
MAX_VLAN_ID = 4094

# Max results per query
MAX_RESULTS_PER_QUERY = 200

# Default pagination
DEFAULT_LIMIT = 50
DEFAULT_OFFSET = 0

# Voucher constraints
MAX_VOUCHER_TIME_LIMIT_MINUTES = 525_600  # 1 year
MAX_VOUCHER_DATA_LIMIT_MB = 1_048_576  # 1 TB
MAX_VOUCHER_RATE_LIMIT_KBPS = 1_000_000  # 1 Gbps
MAX_VOUCHER_COUNT = 1000
MAX_VOUCHER_GUEST_LIMIT = 100

# Network name constraints
MAX_NETWORK_NAME_LENGTH = 128
MIN_NETWORK_NAME_LENGTH = 1

# Policy name constraints
MAX_POLICY_NAME_LENGTH = 128

# Allowed firewall action types
ALLOWED_POLICY_ACTIONS = {"ALLOW", "DROP", "REJECT"}

# Allowed IP version scopes
ALLOWED_IP_VERSIONS = {"IPv4", "IPv6", "BOTH"}

# Allowed connection state filters
ALLOWED_CONNECTION_STATES = {
    "NEW", "ESTABLISHED", "RELATED", "INVALID",
}

# Allowed schedule modes
ALLOWED_SCHEDULE_MODES = {"ALWAYS", "CUSTOM"}


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------


def validate_uuid(value: str, field_name: str = "ID") -> str:
    """
    Validate a UUID format string.

    Returns normalised UUID. Raises SecurityError on invalid input.
    """
    if not value or not isinstance(value, str):
        raise SecurityError(f"{field_name} is required")

    value = value.strip().lower()

    if not _UUID_PATTERN.match(value):
        raise SecurityError(
            f"Invalid {field_name} format: expected UUID "
            "(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
        )

    return value


def validate_site_id(site_id: str) -> str:
    """Validate site ID format."""
    return validate_uuid(site_id, "Site ID")


def validate_network_id(network_id: str) -> str:
    """Validate network ID format."""
    return validate_uuid(network_id, "Network ID")


def validate_policy_id(policy_id: str) -> str:
    """Validate firewall policy ID format."""
    return validate_uuid(policy_id, "Policy ID")


def validate_zone_id(zone_id: str) -> str:
    """Validate firewall zone ID format."""
    return validate_uuid(zone_id, "Zone ID")


def validate_voucher_id(voucher_id: str) -> str:
    """Validate voucher ID format."""
    return validate_uuid(voucher_id, "Voucher ID")


def validate_vlan_id(vlan_id: int) -> int:
    """Validate VLAN ID range (1-4094)."""
    if not isinstance(vlan_id, int):
        raise SecurityError("VLAN ID must be an integer")

    if vlan_id < MIN_VLAN_ID or vlan_id > MAX_VLAN_ID:
        raise SecurityError(
            f"VLAN ID must be between {MIN_VLAN_ID} and {MAX_VLAN_ID}"
        )

    return vlan_id


def validate_network_name(name: str) -> str:
    """Validate network name."""
    if not name or not isinstance(name, str):
        raise SecurityError("Network name is required")

    name = name.strip()

    if len(name) < MIN_NETWORK_NAME_LENGTH:
        raise SecurityError("Network name is too short")

    if len(name) > MAX_NETWORK_NAME_LENGTH:
        raise SecurityError(
            f"Network name too long: max {MAX_NETWORK_NAME_LENGTH} characters"
        )

    # Reject control characters and dangerous patterns
    if any(c in name for c in ["\n", "\r", "\0", "\t"]):
        raise SecurityError("Network name contains invalid characters")

    return name


def validate_policy_name(name: str) -> str:
    """Validate firewall policy name."""
    if not name or not isinstance(name, str):
        raise SecurityError("Policy name is required")

    name = name.strip()

    if len(name) > MAX_POLICY_NAME_LENGTH:
        raise SecurityError(
            f"Policy name too long: max {MAX_POLICY_NAME_LENGTH} characters"
        )

    if any(c in name for c in ["\n", "\r", "\0", "\t"]):
        raise SecurityError("Policy name contains invalid characters")

    return name


def validate_policy_action(action: str) -> str:
    """Validate firewall policy action type."""
    if not action or not isinstance(action, str):
        raise SecurityError("Policy action is required")

    action = action.strip().upper()

    if action not in ALLOWED_POLICY_ACTIONS:
        raise SecurityError(
            f"Invalid policy action: {action!r}. "
            f"Allowed: {', '.join(sorted(ALLOWED_POLICY_ACTIONS))}"
        )

    return action


def validate_ip_version(version: str) -> str:
    """Validate IP version scope."""
    if not version or not isinstance(version, str):
        raise SecurityError("IP version is required")

    version = version.strip()

    if version not in ALLOWED_IP_VERSIONS:
        raise SecurityError(
            f"Invalid IP version: {version!r}. "
            f"Allowed: {', '.join(sorted(ALLOWED_IP_VERSIONS))}"
        )

    return version


def validate_max_results(value: int, maximum: int = MAX_RESULTS_PER_QUERY) -> int:
    """Validate max_results / limit parameter."""
    if not isinstance(value, int) or value < 1:
        raise SecurityError("max_results must be a positive integer")

    if value > maximum:
        raise SecurityError(f"max_results too large: max {maximum}")

    return value


def validate_offset(value: int) -> int:
    """Validate pagination offset."""
    if not isinstance(value, int) or value < 0:
        raise SecurityError("offset must be a non-negative integer")

    return value


def validate_voucher_params(
    time_limit_minutes: int | None = None,
    data_limit_mb: int | None = None,
    download_limit_kbps: int | None = None,
    upload_limit_kbps: int | None = None,
    guest_limit: int | None = None,
    count: int | None = None,
) -> dict:
    """
    Validate voucher generation parameters.

    Returns dict of validated non-None params.
    """
    validated: dict[str, Any] = {}

    if time_limit_minutes is not None:
        if not isinstance(time_limit_minutes, int) or time_limit_minutes < 1:
            raise SecurityError("time_limit_minutes must be a positive integer")
        if time_limit_minutes > MAX_VOUCHER_TIME_LIMIT_MINUTES:
            raise SecurityError(
                f"time_limit_minutes too large: max {MAX_VOUCHER_TIME_LIMIT_MINUTES}"
            )
        validated["timeLimitMinutes"] = time_limit_minutes

    if data_limit_mb is not None:
        if not isinstance(data_limit_mb, int) or data_limit_mb < 1:
            raise SecurityError("data_limit_mb must be a positive integer")
        if data_limit_mb > MAX_VOUCHER_DATA_LIMIT_MB:
            raise SecurityError(
                f"data_limit_mb too large: max {MAX_VOUCHER_DATA_LIMIT_MB}"
            )
        validated["dataUsageLimitMBytes"] = data_limit_mb

    if download_limit_kbps is not None:
        if not isinstance(download_limit_kbps, int) or download_limit_kbps < 0:
            raise SecurityError("download_limit_kbps must be a non-negative integer")
        if download_limit_kbps > MAX_VOUCHER_RATE_LIMIT_KBPS:
            raise SecurityError(
                f"download_limit_kbps too large: max {MAX_VOUCHER_RATE_LIMIT_KBPS}"
            )
        validated["rxRateLimitKbps"] = download_limit_kbps

    if upload_limit_kbps is not None:
        if not isinstance(upload_limit_kbps, int) or upload_limit_kbps < 0:
            raise SecurityError("upload_limit_kbps must be a non-negative integer")
        if upload_limit_kbps > MAX_VOUCHER_RATE_LIMIT_KBPS:
            raise SecurityError(
                f"upload_limit_kbps too large: max {MAX_VOUCHER_RATE_LIMIT_KBPS}"
            )
        validated["txRateLimitKbps"] = upload_limit_kbps

    if guest_limit is not None:
        if not isinstance(guest_limit, int) or guest_limit < 1:
            raise SecurityError("guest_limit must be a positive integer")
        if guest_limit > MAX_VOUCHER_GUEST_LIMIT:
            raise SecurityError(
                f"guest_limit too large: max {MAX_VOUCHER_GUEST_LIMIT}"
            )
        validated["authorizedGuestLimit"] = guest_limit

    if count is not None:
        if not isinstance(count, int) or count < 1:
            raise SecurityError("count must be a positive integer")
        if count > MAX_VOUCHER_COUNT:
            raise SecurityError(f"count too large: max {MAX_VOUCHER_COUNT}")
        validated["count"] = count

    return validated


def validate_filter_expression(value: str | None) -> str | None:
    """
    Basic validation of filter query expressions.

    Prevents injection attacks while allowing the UniFi filter DSL.
    """
    if not value:
        return None

    if not isinstance(value, str):
        raise SecurityError("filter must be a string")

    value = value.strip()

    if len(value) > 1000:
        raise SecurityError("filter expression too long: max 1000 characters")

    # Reject dangerous characters not part of filter DSL
    dangerous = [";", "--", "/*", "*/", "\\x", "\\0", "\n", "\r"]
    for d in dangerous:
        if d in value:
            raise SecurityError(
                f"filter expression contains disallowed characters: {d!r}"
            )

    return value


def validate_console_address(address: str) -> str:
    """
    Validate console IP address or hostname.

    Prevents injection attacks in URL construction.
    """
    if not address or not isinstance(address, str):
        raise SecurityError("Console address is required")

    # Reject dangerous characters BEFORE stripping
    if any(c in address for c in ["\n", "\r", "\0", "'", '"', ";", "&", "|"]):
        raise SecurityError("Console address contains invalid characters")

    address = address.strip()

    # Reject spaces (after strip)
    if " " in address:
        raise SecurityError("Console address contains invalid characters")

    # Must look like an IP or hostname
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    hostname_pattern = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
    )

    if not ip_pattern.match(address) and not hostname_pattern.match(address):
        raise SecurityError(f"Invalid console address format: {address}")

    return address


# ---------------------------------------------------------------------------
# Error Sanitization
# ---------------------------------------------------------------------------


def sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error message to prevent credential leaks.

    Strips passwords, tokens, API keys, IP addresses, cookies, and internal
    paths from error messages before they reach the LLM.
    """
    msg = str(error)

    patterns = [
        # Credentials and keys
        (r"(password|token|key|secret|credential|cookie)[\s:=]+\S+", r"\1=***"),
        (r"Bearer \S+", "Bearer ***"),
        (r"TOKEN=[^\s;]+", "TOKEN=***"),
        (r"(X-CSRF-Token|x-csrf-token)[\s:]+\S+", r"\1: ***"),
        (r"(X-API-Key|x-api-key)[\s:]+\S+", r"\1: ***"),
        # IP addresses in error messages
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b", "***CONSOLE_IP***"),
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
      - networks:       30
      - firewall:       20
      - vouchers:       20
      - info:           60
      - read (general): 60
      - write:          10
    """

    DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        # (capacity, refill_rate tokens/sec)
        "networks": (30, 30 / 60),
        "firewall": (20, 20 / 60),
        "vouchers": (20, 20 / 60),
        "info": (60, 60 / 60),
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
_AUDIT_LOG_FILE = _AUDIT_DIR / "network-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.network_mcp.audit")
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
        operation: Operation name (e.g. "list_networks", "create_voucher")
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
