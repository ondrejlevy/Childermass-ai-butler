"""Security and validation for Childermass Mapy.com MCP.

This module provides input validation, rate limiting, error sanitization,
and audit logging for the Mapy.com MCP server.
"""

import contextlib
import json
import logging
import re
import time
from pathlib import Path
from threading import Lock
from typing import Any


# Configuration
CONFIG_DIR = Path.home() / ".childermass"
AUDIT_LOG_FILE = CONFIG_DIR / "mapy-audit.log"


class SecurityError(Exception):
    """Raised when security validation fails."""


# ============================================================================
# Supported constants
# ============================================================================

SUPPORTED_LANGUAGES = {
    "cs",
    "sk",
    "en",
    "de",
    "pl",
    "fr",
    "it",
    "es",
    "pt",
    "nl",
    "ru",
    "uk",
    "hu",
    "ro",
    "bg",
    "hr",
    "sl",
    "sr",
    "da",
    "fi",
    "no",
    "sv",
    "el",
    "tr",
    "ja",
    "zh",
    "ko",
    "ar",
    "he",
}

SUPPORTED_ROUTE_TYPES = {
    "car_fast",
    "car_fast_traffic",
    "car_short",
    "foot_fast",
    "foot_hiking",
    "bike_road",
    "bike_mountain",
}

SUPPORTED_GEOCODE_TYPES = {
    "regional",
    "regional.country",
    "regional.region",
    "regional.municipality",
    "regional.municipality_part",
    "regional.street",
    "regional.address",
    "poi",
    "coordinate",
}

SUPPORTED_GEOMETRY_FORMATS = {"geojson", "polyline", "polyline6"}


# ============================================================================
# Input Validators
# ============================================================================


def validate_query(query: str) -> str:
    """Validate search query string.

    Args:
        query: Search expression for geocoding / suggest.

    Returns:
        str: Sanitized query.

    Raises:
        SecurityError: If query is invalid.
    """
    if not query or not isinstance(query, str):
        msg = "Query must be a non-empty string"
        raise SecurityError(msg)

    query = query.strip()

    if len(query) < 1:
        msg = "Query must not be empty"
        raise SecurityError(msg)

    if len(query) > 500:
        msg = "Query too long (maximum 500 characters)"
        raise SecurityError(msg)

    # Reject control characters
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", query):
        msg = "Query contains invalid control characters"
        raise SecurityError(msg)

    return query


def validate_coordinates(lat: float, lon: float) -> tuple[float, float]:
    """Validate geographic coordinates.

    Args:
        lat: Latitude (-90 to 90)
        lon: Longitude (-180 to 180)

    Returns:
        tuple: (latitude, longitude)

    Raises:
        SecurityError: If coordinates are invalid.
    """
    if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
        msg = "Latitude and longitude must be numbers"
        raise SecurityError(msg)

    if not -90 <= lat <= 90:
        msg = f"Invalid latitude: {lat} (must be between -90 and 90)"
        raise SecurityError(msg)

    if not -180 <= lon <= 180:
        msg = f"Invalid longitude: {lon} (must be between -180 and 180)"
        raise SecurityError(msg)

    return float(lat), float(lon)


def validate_language(lang: str) -> str:
    """Validate language code.

    Args:
        lang: ISO 639-1 language code (e.g., "cs", "en")

    Returns:
        str: Validated language code.

    Raises:
        SecurityError: If language code is invalid.
    """
    if not lang or not isinstance(lang, str):
        msg = "Language must be a non-empty string"
        raise SecurityError(msg)

    lang = lang.strip().lower()

    if lang not in SUPPORTED_LANGUAGES:
        msg = f"Unsupported language: {lang} (supported: {', '.join(sorted(SUPPORTED_LANGUAGES))})"
        raise SecurityError(msg)

    return lang


def validate_route_type(route_type: str) -> str:
    """Validate route planning type.

    Args:
        route_type: Route type (e.g., "car_fast", "foot_fast")

    Returns:
        str: Validated route type.

    Raises:
        SecurityError: If route type is invalid.
    """
    if not route_type or not isinstance(route_type, str):
        msg = "Route type must be a non-empty string"
        raise SecurityError(msg)

    route_type = route_type.strip().lower()

    if route_type not in SUPPORTED_ROUTE_TYPES:
        msg = (
            f"Invalid route type: {route_type} "
            f"(must be one of: {', '.join(sorted(SUPPORTED_ROUTE_TYPES))})"
        )
        raise SecurityError(msg)

    return route_type


def validate_geocode_type(geocode_type: str) -> str:
    """Validate geocode entity type filter.

    Args:
        geocode_type: Entity type (e.g., "regional", "poi", "regional.address")

    Returns:
        str: Validated geocode type.

    Raises:
        SecurityError: If geocode type is invalid.
    """
    if not geocode_type or not isinstance(geocode_type, str):
        msg = "Geocode type must be a non-empty string"
        raise SecurityError(msg)

    geocode_type = geocode_type.strip().lower()

    if geocode_type not in SUPPORTED_GEOCODE_TYPES:
        msg = (
            f"Invalid geocode type: {geocode_type} "
            f"(must be one of: {', '.join(sorted(SUPPORTED_GEOCODE_TYPES))})"
        )
        raise SecurityError(msg)

    return geocode_type


def validate_limit(limit: int, max_limit: int = 100) -> int:
    """Validate result limit.

    Args:
        limit: Maximum number of results.
        max_limit: Upper bound (default 100).

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

    if limit > max_limit:
        msg = f"Limit cannot exceed {max_limit}"
        raise SecurityError(msg)

    return limit


def validate_waypoints(waypoints: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """Validate list of route waypoints.

    Args:
        waypoints: List of (lat, lon) tuples.

    Returns:
        list: Validated waypoints.

    Raises:
        SecurityError: If waypoints are invalid.
    """
    if not isinstance(waypoints, (list, tuple)):
        msg = "Waypoints must be a list of coordinate pairs"
        raise SecurityError(msg)

    if len(waypoints) > 15:
        msg = "Maximum 15 waypoints allowed"
        raise SecurityError(msg)

    validated = []
    for i, wp in enumerate(waypoints):
        if not isinstance(wp, (list, tuple)) or len(wp) != 2:
            msg = f"Waypoint {i} must be a [lat, lon] pair"
            raise SecurityError(msg)
        lat, lon = validate_coordinates(wp[0], wp[1])
        validated.append((lat, lon))

    return validated


def validate_positions(positions: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """Validate list of positions for elevation lookup.

    Args:
        positions: List of (lat, lon) tuples.

    Returns:
        list: Validated positions.

    Raises:
        SecurityError: If positions are invalid.
    """
    if not isinstance(positions, (list, tuple)):
        msg = "Positions must be a list of coordinate pairs"
        raise SecurityError(msg)

    if len(positions) < 1:
        msg = "At least one position is required"
        raise SecurityError(msg)

    if len(positions) > 256:
        msg = "Maximum 256 positions allowed"
        raise SecurityError(msg)

    validated = []
    for i, pos in enumerate(positions):
        if not isinstance(pos, (list, tuple)) or len(pos) != 2:
            msg = f"Position {i} must be a [lat, lon] pair"
            raise SecurityError(msg)
        lat, lon = validate_coordinates(pos[0], pos[1])
        validated.append((lat, lon))

    return validated


def validate_departure(departure: str) -> str:
    """Validate ISO-8601 departure time string.

    Args:
        departure: ISO-8601 datetime (e.g., "2026-02-14T08:00:00.000")

    Returns:
        str: Validated departure string.

    Raises:
        SecurityError: If format is invalid.
    """
    if not departure or not isinstance(departure, str):
        msg = "Departure must be a non-empty string"
        raise SecurityError(msg)

    departure = departure.strip()

    # Basic ISO-8601 pattern
    if not re.match(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$",
        departure,
    ):
        msg = f"Invalid departure format: {departure} (expected ISO-8601, e.g. 2026-02-14T08:00:00)"
        raise SecurityError(msg)

    return departure


def validate_geometry_format(fmt: str) -> str:
    """Validate route geometry output format.

    Args:
        fmt: Format name ("geojson", "polyline", "polyline6")

    Returns:
        str: Validated format.

    Raises:
        SecurityError: If format is invalid.
    """
    if not fmt or not isinstance(fmt, str):
        msg = "Geometry format must be a non-empty string"
        raise SecurityError(msg)

    fmt = fmt.strip().lower()

    if fmt not in SUPPORTED_GEOMETRY_FORMATS:
        msg = (
            f"Invalid geometry format: {fmt} "
            f"(must be one of: {', '.join(sorted(SUPPORTED_GEOMETRY_FORMATS))})"
        )
        raise SecurityError(msg)

    return fmt


# ============================================================================
# Rate Limiter (Token Bucket Algorithm)
# ============================================================================


class RateLimiter:
    """Thread-safe token bucket rate limiter for API calls."""

    def __init__(self):
        """Initialize rate limiter with operation limits."""
        # Format: operation -> (tokens_per_minute, bucket_capacity)
        self.limits = {
            "geocode": (60, 60),
            "suggest": (60, 60),
            "rgeocode": (60, 60),
            "route": (30, 30),
            "matrix": (20, 20),
            "elevation": (40, 40),
            "timezone": (40, 40),
        }

        # State: operation -> {"tokens": float, "last_update": float}
        self.buckets: dict[str, dict[str, float]] = {}
        self._lock = Lock()

    def check(self, operation: str) -> None:
        """Check if operation is allowed under rate limit.

        Args:
            operation: Operation name (e.g., "geocode", "route")

        Raises:
            SecurityError: If rate limit exceeded.
        """
        if operation not in self.limits:
            operation = "geocode"

        rate, capacity = self.limits[operation]

        with self._lock:
            # Initialize bucket if first use (with full capacity)
            if operation not in self.buckets:
                self.buckets[operation] = {
                    "tokens": float(capacity),
                    "last_update": time.time(),
                }

            bucket = self.buckets[operation]

            # Refill tokens based on time elapsed
            now = time.time()
            elapsed = now - bucket["last_update"]
            tokens_to_add = elapsed * (rate / 60.0)
            bucket["tokens"] = min(capacity, bucket["tokens"] + tokens_to_add)
            bucket["last_update"] = now

            # Check if we have tokens available
            if bucket["tokens"] < 1.0:
                wait_time = (1.0 - bucket["tokens"]) / (rate / 60.0)
                msg = f"Rate limit exceeded for {operation}. Please wait {wait_time:.1f} seconds."
                raise SecurityError(msg)

            # Consume one token
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

    # Remove API keys from query params
    message = re.sub(r"apiKey=[^&\s]+", "apiKey=[API_KEY]", message, flags=re.IGNORECASE)

    # Remove API keys from headers
    message = re.sub(
        r"X-Mapy-Api-Key:\s*\S+",
        "X-Mapy-Api-Key: [API_KEY]",
        message,
        flags=re.IGNORECASE,
    )

    # Generic long hex/alphanum token patterns
    message = re.sub(r"\b[0-9a-f]{24,}\b", "[API_KEY]", message, flags=re.IGNORECASE)

    # Remove file paths
    message = re.sub(r"/[a-zA-Z0-9_\-./]+", "[PATH]", message)
    message = re.sub(r"[A-Z]:\\[a-zA-Z0-9_\-\\]+", "[PATH]", message)

    # Limit length
    if len(message) > 200:
        message = message[:197] + "..."

    return message


# ============================================================================
# Audit Logging
# ============================================================================


# Use `CONFIG_DIR` and `AUDIT_LOG_FILE` so tests can monkeypatch them at runtime
# Default values are defined above; keep them in module scope so tests can
# override `CONFIG_DIR` and `AUDIT_LOG_FILE` via monkeypatch.setattr().


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.mapy_mcp.audit")
    # If handlers exist but point to a different file (tests monkeypatch
    # `AUDIT_LOG_FILE` per-test), recreate handlers so logs go to the currently
    # configured file path.
    if logger.handlers:
        try:
            first = logger.handlers[0]
            base = getattr(first, "baseFilename", None)
            if base is not None and base != str(AUDIT_LOG_FILE):
                # Close and remove existing handlers
                for h in list(logger.handlers):
                    with contextlib.suppress(Exception):
                        h.close()
                    logger.removeHandler(h)
        except Exception:
            # If anything goes wrong, fall back to recreating handlers below
            for h in list(logger.handlers):
                with contextlib.suppress(Exception):
                    h.close()
                logger.removeHandler(h)

    if not logger.handlers:
        # Ensure the configured directory exists (tests may override CONFIG_DIR)
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            # If CONFIG_DIR is not a Path or cannot be created, fall back silently
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
        operation: Operation name (e.g., "geocode", "plan_route")
        account: Account or context identifier
        details: Additional context (sanitised - no credentials!)
        success: Whether the operation succeeded
    """
    # Support callers that pass `details` as the second positional argument
    # (common in tests): audit_log("op", {"k": "v"})
    if isinstance(account, dict) and details is None:
        details = account
        account = ""

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
