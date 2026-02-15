"""Security and validation for Childermass Weather MCP.

This module provides input validation, rate limiting, error sanitization,
and audit logging for the weather MCP server.
"""

import json
import logging
import re
import time
from pathlib import Path
from threading import Lock
from typing import Any


# Configuration
CONFIG_DIR = Path.home() / ".childermass"
AUDIT_LOG_FILE = CONFIG_DIR / "weather-audit.log"


class SecurityError(Exception):
    """Raised when security validation fails."""


# ============================================================================
# Input Validators
# ============================================================================


def validate_city_name(city: str, allow_digits: bool = False) -> str:
    """Validate and sanitize city name.

    Args:
        city: City name, optionally with country code (e.g., "London,UK")

    Returns:
        str: Sanitized city name.

    Raises:
        SecurityError: If city name is invalid.
    """
    if not city or not isinstance(city, str):
        msg = "City name must be a non-empty string"
        raise SecurityError(msg)

    city = city.strip()

    if len(city) < 2:
        msg = "City name too short (minimum 2 characters)"
        raise SecurityError(msg)

    if len(city) > 200:
        msg = "City name too long (maximum 200 characters)"
        raise SecurityError(msg)

    # Allow letters, spaces, hyphens, commas, periods, apostrophes
    # Optionally allow digits when callers explicitly request it.
    pattern = r"^[a-zA-Z0-9\s\-,.']+$" if allow_digits else r"^[a-zA-Z\s\-,.']+$"

    if not re.match(pattern, city):
        msg = (
            "City name contains invalid characters "
            "(only letters, spaces, hyphens, commas, periods, apostrophes allowed)"
        )
        raise SecurityError(msg)

    return city


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


def validate_units(units: str) -> str:
    """Validate temperature units parameter.

    Args:
        units: Temperature units ("metric", "imperial", or "standard")

    Returns:
        str: Validated units string.

    Raises:
        SecurityError: If units value is invalid.
    """
    valid_units = {"metric", "imperial", "standard"}

    if not units or not isinstance(units, str):
        msg = "Units must be a non-empty string"
        raise SecurityError(msg)

    units = units.lower().strip()

    if units not in valid_units:
        msg = f"Invalid units: {units} (must be one of: {', '.join(valid_units)})"
        raise SecurityError(msg)

    return units


def validate_days(days: int, max_days: int = 5) -> int:
    """Validate number of forecast days.

    Args:
        days: Number of days to forecast
        max_days: Maximum allowed days (default: 5 for OpenWeatherMap free tier)

    Returns:
        int: Validated days count.

    Raises:
        SecurityError: If days is invalid.
    """
    if not isinstance(days, int):
        msg = "Days must be an integer"
        raise SecurityError(msg)

    if days < 1:
        msg = "Days must be at least 1"
        raise SecurityError(msg)

    if days > max_days:
        msg = f"Days cannot exceed {max_days} (API limitation)"
        raise SecurityError(msg)

    return days


def validate_hours(hours: int, max_hours: int = 48) -> int:
    """Validate number of forecast hours.

    Args:
        hours: Number of hours to forecast
        max_hours: Maximum allowed hours (default: 48)

    Returns:
        int: Validated hours count.

    Raises:
        SecurityError: If hours is invalid.
    """
    if not isinstance(hours, int):
        msg = "Hours must be an integer"
        raise SecurityError(msg)

    if hours < 1:
        msg = "Hours must be at least 1"
        raise SecurityError(msg)

    if hours > max_hours:
        msg = f"Hours cannot exceed {max_hours}"
        raise SecurityError(msg)

    return hours


def validate_activity(activity: str) -> str:
    """Validate activity name.

    Args:
        activity: Activity name (e.g., "hiking", "running")

    Returns:
        str: Sanitized activity name.

    Raises:
        SecurityError: If activity is invalid.
    """
    if not activity or not isinstance(activity, str):
        msg = "Activity must be a non-empty string"
        raise SecurityError(msg)

    activity = activity.strip().lower()

    if len(activity) < 2:
        msg = "Activity name too short (minimum 2 characters)"
        raise SecurityError(msg)

    if len(activity) > 50:
        msg = "Activity name too long (maximum 50 characters)"
        raise SecurityError(msg)

    # Allow letters, spaces, hyphens
    if not re.match(r"^[a-z\s\-]+$", activity):
        msg = "Activity name contains invalid characters (only letters, spaces, hyphens allowed)"
        raise SecurityError(msg)

    return activity


def validate_date_string(date_str: str) -> str:
    """Validate date string format.

    Args:
        date_str: Date in YYYY-MM-DD format

    Returns:
        str: Validated date string.

    Raises:
        SecurityError: If date format is invalid.
    """
    if not date_str or not isinstance(date_str, str):
        msg = "Date must be a non-empty string"
        raise SecurityError(msg)

    date_str = date_str.strip()

    # Validate format YYYY-MM-DD
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        msg = f"Invalid date format: {date_str} (expected YYYY-MM-DD)"
        raise SecurityError(msg)

    # Validate actual date
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
    except ValueError:
        msg = f"Invalid date: {date_str}"
        raise SecurityError(msg)

    return date_str


# ============================================================================
# Rate Limiter (Token Bucket Algorithm)
# ============================================================================


class RateLimiter:
    """Thread-safe token bucket rate limiter for API calls."""

    def __init__(self):
        """Initialize rate limiter with operation limits."""
        # Format: operation -> (tokens_per_minute, bucket_capacity)
        self.limits = {
            "forecast": (30, 30),
            "current": (60, 60),
            "alerts": (30, 30),
            "hourly": (30, 30),
            "air_quality": (20, 20),
            "geocode": (40, 40),
            "historical": (10, 10),
        }

        # State: operation -> {"tokens": float, "last_update": float}
        self.buckets: dict[str, dict[str, float]] = {}
        self._lock = Lock()

    def check(self, operation: str) -> None:
        """Check if operation is allowed under rate limit.

        Args:
            operation: Operation name (e.g., "current", "forecast")

        Raises:
            SecurityError: If rate limit exceeded.
        """
        if operation not in self.limits:
            operation = "current"

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
        error: Exception to sanitize

    Returns:
        str: Sanitized error message.
    """
    message = str(error)

    # Remove API keys (hex/alphanumeric sequences >= 24 chars)
    message = re.sub(r"\b[0-9a-f]{24,}\b", "[API_KEY]", message, flags=re.IGNORECASE)

    # Remove file paths
    message = re.sub(r"/[a-zA-Z0-9_\-./]+", "[PATH]", message)
    message = re.sub(r"[A-Z]:\\[a-zA-Z0-9_\-\\]+", "[PATH]", message)

    # Remove URLs with API keys
    message = re.sub(r"appid=[^&\s]+", "appid=[API_KEY]", message, flags=re.IGNORECASE)

    # Limit length
    if len(message) > 200:
        message = message[:197] + "..."

    return message


# ============================================================================
# Audit Logging
# ============================================================================


_AUDIT_DIR = Path.home() / ".childermass"
_AUDIT_LOG_FILE = _AUDIT_DIR / "weather-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.weather_mcp.audit")
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
    """Write a structured audit log entry.

    Args:
        operation: Operation name (e.g., "get_current_weather")
        account: Account or location identifier
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


# ============================================================================
# Combined Validation Helpers
# ============================================================================


def validate_location(
    location: str | tuple[float, float],
) -> tuple[str, str | None, float | None, float | None]:
    """Validate location input (city name or coordinates).

    Args:
        location: Either city name string or (lat, lon) tuple

    Returns:
        tuple: (location_type, city_name, latitude, longitude)
               location_type is "city" or "coords"

    Raises:
        SecurityError: If location is invalid.
    """
    if isinstance(location, str):
        # For higher-level location parsing (used by client functions), allow
        # city names that include digits so API queries can be performed.
        city = validate_city_name(location, allow_digits=True)
        return ("city", city, None, None)
    if isinstance(location, (tuple, list)) and len(location) == 2:
        lat, lon = validate_coordinates(location[0], location[1])
        return ("coords", None, lat, lon)
    msg = "Location must be either a city name string or (latitude, longitude) tuple"
    raise SecurityError(msg)
