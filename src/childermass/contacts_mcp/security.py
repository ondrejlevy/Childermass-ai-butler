"""
Security utilities for Google Contacts MCP server.

Provides input validation, sanitization, rate limiting, and audit logging
for Google People API operations.
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

# Maximum lengths
MAX_NAME_LENGTH = 500
MAX_NOTES_LENGTH = 8192
MAX_QUERY_LENGTH = 500
MAX_ADDRESS_LENGTH = 1000
MAX_ORGANIZATION_LENGTH = 500
MAX_TITLE_LENGTH = 500
MAX_URL_LENGTH = 2000
MAX_PHONE_LENGTH = 50
MAX_GROUP_NAME_LENGTH = 500

# Valid person fields for the People API fieldMask
VALID_PERSON_FIELDS: set[str] = {
    "addresses",
    "ageRanges",
    "biographies",
    "birthdays",
    "calendarUrls",
    "clientData",
    "coverPhotos",
    "emailAddresses",
    "events",
    "externalIds",
    "genders",
    "imClients",
    "interests",
    "locales",
    "locations",
    "memberships",
    "metadata",
    "miscKeywords",
    "names",
    "nicknames",
    "occupations",
    "organizations",
    "phoneNumbers",
    "photos",
    "relations",
    "sipAddresses",
    "skills",
    "urls",
    "userDefined",
}

# Default fields to request from People API
DEFAULT_PERSON_FIELDS = (
    "names,emailAddresses,phoneNumbers,addresses,organizations,"
    "birthdays,biographies,memberships,photos,nicknames,events,"
    "urls,relations,occupations"
)

# Valid address types
VALID_ADDRESS_TYPES = {"home", "work", "other"}

# Valid email types
VALID_EMAIL_TYPES = {"home", "work", "other"}

# Valid phone types
VALID_PHONE_TYPES = {
    "home", "work", "mobile", "homeFax", "workFax", "otherFax",
    "pager", "workMobile", "workPager", "main", "googleVoice", "other",
}


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_resource_name(resource_name: str) -> str:
    """
    Validate a People API resource name.

    Resource names are in the form "people/{person_id}" or "people/me".
    Returns normalised resource name. Raises SecurityError on invalid input.
    """
    if not resource_name or not isinstance(resource_name, str):
        raise SecurityError("Resource name is required")

    resource_name = resource_name.strip()

    # Check for injection characters
    if any(char in resource_name for char in ["\n", "\r", "\0", "\t"]):
        raise SecurityError(
            "Resource name contains invalid control characters"
        )

    # Must match people/{id} or people/me
    if not re.match(r"^people/[a-zA-Z0-9]+$", resource_name):
        raise SecurityError(
            f"Invalid resource name format: {resource_name}. "
            "Expected format: people/{{person_id}} or people/me"
        )

    return resource_name


def validate_group_resource_name(resource_name: str) -> str:
    """
    Validate a contact group resource name.

    Format: "contactGroups/{contactGroupId}"
    """
    if not resource_name or not isinstance(resource_name, str):
        raise SecurityError("Contact group resource name is required")

    resource_name = resource_name.strip()

    if any(char in resource_name for char in ["\n", "\r", "\0", "\t"]):
        raise SecurityError(
            "Contact group resource name contains invalid control characters"
        )

    if not re.match(r"^contactGroups/[a-zA-Z0-9_-]+$", resource_name):
        raise SecurityError(
            f"Invalid contact group resource name: {resource_name}. "
            "Expected format: contactGroups/{{groupId}}"
        )

    return resource_name


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


def validate_phone_number(phone: str) -> str:
    """
    Validate phone number format.

    Accepts digits, spaces, dashes, parentheses, plus sign, and dots.
    """
    if not phone or not isinstance(phone, str):
        raise SecurityError("Phone number is required")

    phone = phone.strip()

    if any(char in phone for char in ["\n", "\r", "\0", "\t"]):
        raise SecurityError("Phone number contains invalid control characters")

    if len(phone) > MAX_PHONE_LENGTH:
        raise SecurityError(
            f"Phone number too long: {len(phone)} chars "
            f"(max {MAX_PHONE_LENGTH})"
        )

    # Allow digits, spaces, dashes, parens, dots, plus, hash, star
    if not re.match(r"^[0-9\s\-\(\)\+\.\#\*]+$", phone):
        raise SecurityError(
            f"Invalid phone number format: {phone}. "
            "Only digits, spaces, +, -, (, ), ., #, * are allowed."
        )

    return phone


def validate_contact_name(name: str) -> str:
    """
    Validate a contact name (given name, family name, etc.)

    Returns validated name. Raises SecurityError on invalid input.
    """
    if not name or not isinstance(name, str):
        raise SecurityError("Contact name is required")

    name = name.strip()
    if not name:
        raise SecurityError("Contact name cannot be empty")

    if any(c in name for c in ["\r", "\0"]):
        raise SecurityError(
            "Contact name contains invalid control characters"
        )

    if len(name) > MAX_NAME_LENGTH:
        raise SecurityError(
            f"Contact name too long: {len(name)} chars "
            f"(max {MAX_NAME_LENGTH})"
        )

    return name


def validate_notes(notes: str) -> str:
    """
    Validate contact notes / biography.

    Returns validated notes. Maximum length: 8192 characters.
    """
    if not notes:
        return ""

    if len(notes) > MAX_NOTES_LENGTH:
        raise SecurityError(
            f"Notes too long: {len(notes)} chars (max {MAX_NOTES_LENGTH})"
        )

    return notes


def validate_organization(org: str) -> str:
    """Validate organization name."""
    if not org:
        return ""

    org = org.strip()

    if any(c in org for c in ["\r", "\0"]):
        raise SecurityError(
            "Organization name contains invalid control characters"
        )

    if len(org) > MAX_ORGANIZATION_LENGTH:
        raise SecurityError(
            f"Organization name too long: {len(org)} chars "
            f"(max {MAX_ORGANIZATION_LENGTH})"
        )

    return org


def validate_job_title(title: str) -> str:
    """Validate job title."""
    if not title:
        return ""

    title = title.strip()

    if any(c in title for c in ["\r", "\0"]):
        raise SecurityError(
            "Job title contains invalid control characters"
        )

    if len(title) > MAX_TITLE_LENGTH:
        raise SecurityError(
            f"Job title too long: {len(title)} chars "
            f"(max {MAX_TITLE_LENGTH})"
        )

    return title


def validate_address(address: str) -> str:
    """Validate a street address."""
    if not address:
        return ""

    address = address.strip()

    if "\0" in address:
        raise SecurityError("Address contains null bytes")

    if len(address) > MAX_ADDRESS_LENGTH:
        raise SecurityError(
            f"Address too long: {len(address)} chars "
            f"(max {MAX_ADDRESS_LENGTH})"
        )

    return address


def validate_url(url: str) -> str:
    """Validate a URL."""
    if not url:
        return ""

    url = url.strip()

    if any(char in url for char in ["\n", "\r", "\0", "\t"]):
        raise SecurityError("URL contains invalid control characters")

    if len(url) > MAX_URL_LENGTH:
        raise SecurityError(
            f"URL too long: {len(url)} chars (max {MAX_URL_LENGTH})"
        )

    if not validators.url(url):
        raise SecurityError(f"Invalid URL format: {url}")

    return url


def validate_birthday(birthday: str) -> str:
    """
    Validate birthday date format.

    Accepts YYYY-MM-DD or MM-DD (without year).
    Returns the normalised string.
    """
    if not birthday or not isinstance(birthday, str):
        raise SecurityError("Birthday is required")

    birthday = birthday.strip()

    # Full date: YYYY-MM-DD
    if re.match(r"^\d{4}-\d{2}-\d{2}$", birthday):
        return birthday

    # Without year: MM-DD
    if re.match(r"^\d{2}-\d{2}$", birthday):
        return birthday

    raise SecurityError(
        f"Invalid birthday format: {birthday}. "
        "Expected YYYY-MM-DD or MM-DD"
    )


def validate_search_query(query: str) -> str:
    """Validate contact search query."""
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


def validate_person_fields(fields: str) -> str:
    """
    Validate Person fields mask.

    Accepts comma-separated field names from VALID_PERSON_FIELDS.
    Returns validated fields string.
    """
    if not fields:
        return DEFAULT_PERSON_FIELDS

    field_list = [f.strip() for f in fields.split(",") if f.strip()]

    invalid = [f for f in field_list if f not in VALID_PERSON_FIELDS]
    if invalid:
        raise SecurityError(
            f"Invalid person fields: {', '.join(invalid)}. "
            f"Valid fields: {', '.join(sorted(VALID_PERSON_FIELDS))}"
        )

    return ",".join(field_list)


def validate_group_name(name: str) -> str:
    """Validate contact group name."""
    if not name or not isinstance(name, str):
        raise SecurityError("Contact group name is required")

    name = name.strip()
    if not name:
        raise SecurityError("Contact group name cannot be empty")

    if any(c in name for c in ["\r", "\0"]):
        raise SecurityError(
            "Contact group name contains invalid control characters"
        )

    if len(name) > MAX_GROUP_NAME_LENGTH:
        raise SecurityError(
            f"Contact group name too long: {len(name)} chars "
            f"(max {MAX_GROUP_NAME_LENGTH})"
        )

    return name


def validate_max_results(max_results: int, limit: int = 1000) -> int:
    """Validate max_results parameter."""
    if max_results < 1:
        raise SecurityError("max_results must be at least 1")
    if max_results > limit:
        raise SecurityError(f"max_results cannot exceed {limit}")
    return max_results


def validate_etag(etag: str) -> str:
    """Validate etag for optimistic concurrency."""
    if not etag or not isinstance(etag, str):
        raise SecurityError(
            "etag is required for update operations. "
            "Get it from contacts_get first."
        )
    etag = etag.strip()
    if not etag:
        raise SecurityError("etag cannot be empty")
    return etag


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
      - search:                    30
      - list/get:                  60
      - create/update:             20
      - delete:                    10
      - group operations:          30
    """

    DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        # (capacity, refill_rate tokens/sec)
        "search": (30, 30 / 60),
        "list": (60, 60 / 60),
        "get": (60, 60 / 60),
        "create": (20, 20 / 60),
        "update": (20, 20 / 60),
        "delete": (10, 10 / 60),
        "list_groups": (30, 30 / 60),
        "get_group": (30, 30 / 60),
        "create_group": (20, 20 / 60),
        "modify_group_members": (20, 20 / 60),
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
_AUDIT_LOG_FILE = _AUDIT_DIR / "contacts-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.contacts_mcp.audit")
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
        operation: Operation name (e.g. "create_contact", "search_contacts")
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
