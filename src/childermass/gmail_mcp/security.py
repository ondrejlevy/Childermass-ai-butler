"""
Security utilities for Gmail MCP server.

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
# MIME type whitelist
# ---------------------------------------------------------------------------

ALLOWED_MIME_TYPES: set[str] = {
    # Documents
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/rtf",
    # Text
    "text/plain",
    "text/csv",
    "text/html",
    "text/markdown",
    # Images
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/svg+xml",
    "image/bmp",
    "image/tiff",
    # Audio
    "audio/mpeg",
    "audio/wav",
    "audio/ogg",
    # Video
    "video/mp4",
    "video/mpeg",
    "video/webm",
    # Archives
    "application/zip",
    "application/x-tar",
    "application/gzip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    # Code / data
    "application/json",
    "application/xml",
    "text/javascript",
    "text/css",
    "text/xml",
    # Calendar
    "text/calendar",
    # Generic fallback (allowed but logged)
    "application/octet-stream",
}

DANGEROUS_MIME_TYPES: set[str] = {
    "application/x-executable",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-sh",
    "application/x-bat",
    "application/x-csh",
    "application/vnd.microsoft.portable-executable",
    "text/x-shellscript",
}

# Maximum attachment size: 25 MB (Gmail limit)
MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024

# Maximum total size for all attachments in one email: 35 MB
MAX_TOTAL_ATTACHMENT_SIZE = 35 * 1024 * 1024

# Maximum email body length
MAX_BODY_LENGTH = 500_000  # ~500 KB

# Maximum number of recipients per email
MAX_RECIPIENTS = 100


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_email(email: str) -> str:
    """
    Validate email address format.

    Returns normalised email address. Raises SecurityError on invalid input.
    """
    if not email or not isinstance(email, str):
        msg = "Email address is required"
        raise SecurityError(msg)

    email = email.strip()

    # Extract email from "Name <email@example.com>" format
    if "<" in email and ">" in email:
        match = re.search(r"<([^>]+)>", email)
        if match:
            email = match.group(1).strip()

    email_lower = email.lower()

    # Check for injection characters
    if any(char in email_lower for char in ["\n", "\r", "\0", "\t"]):
        msg = "Email contains invalid control characters"
        raise SecurityError(msg)

    if not validators.email(email_lower):
        msg = f"Invalid email address format: {email}"
        raise SecurityError(msg)

    return email_lower


def validate_email_list(emails: str) -> list[str]:
    """
    Validate comma-separated list of emails.

    Returns list of validated email addresses.
    """
    if not emails:
        return []

    validated = []
    for email in emails.split(","):
        email = email.strip()
        if email:
            validated.append(validate_email(email))

    if len(validated) > MAX_RECIPIENTS:
        msg = f"Too many recipients: {len(validated)} (max {MAX_RECIPIENTS})"
        raise SecurityError(msg)

    return validated


def validate_file_path(
    file_path: str,
    check_exists: bool = True,
    allowed_base_dirs: list[Path] | None = None,
) -> Path:
    """
    Validate file path for attachment upload/download.

    Prevents path traversal attacks and ensures file exists.
    """
    if not file_path or not isinstance(file_path, str):
        msg = "File path is required"
        raise SecurityError(msg)

    # Reject null bytes
    if "\0" in file_path:
        msg = "File path contains null bytes"
        raise SecurityError(msg)

    try:
        path = Path(file_path).expanduser().resolve()
    except (ValueError, OSError) as e:
        msg = f"Invalid file path: {file_path}"
        raise SecurityError(msg) from e

    # Check against allowed base directories if specified
    if allowed_base_dirs and not any(
        _is_subpath(path, base.resolve()) for base in allowed_base_dirs
    ):
        msg = f"File path outside allowed directories: {file_path}"
        raise SecurityError(msg)

    if check_exists and not path.exists():
        msg = f"File not found: {file_path}"
        raise SecurityError(msg)

    if check_exists and not path.is_file():
        msg = f"Path is not a file: {file_path}"
        raise SecurityError(msg)

    return path


def _is_subpath(path: Path, base: Path) -> bool:
    """Check if path is under base directory."""
    try:
        path.relative_to(base)
    except ValueError:
        return False
    else:
        return True


def validate_save_path(save_path: str) -> Path:
    """
    Validate download save path.

    Ensures the target directory exists.
    """
    path = validate_file_path(save_path, check_exists=False)

    # Ensure parent directory exists
    if not path.parent.exists():
        msg = f"Directory does not exist: {path.parent}"
        raise SecurityError(msg)

    return path


def validate_mime_type(mime_type: str, strict: bool = False) -> str:
    """
    Validate MIME type against whitelist.

    Returns normalised mime_type. Raises SecurityError for dangerous types.
    """
    mime_type = mime_type.lower().strip()

    if mime_type in DANGEROUS_MIME_TYPES:
        msg = f"Dangerous MIME type blocked: {mime_type}"
        raise SecurityError(msg)

    if strict and mime_type not in ALLOWED_MIME_TYPES:
        msg = f"MIME type not in whitelist: {mime_type}. Add to ALLOWED_MIME_TYPES if safe."
        raise SecurityError(msg)

    return mime_type


def validate_attachment_size(size: int, filename: str = "") -> None:
    """Validate attachment size against Gmail limits."""
    if size <= 0:
        msg = f"Invalid file size: {size}"
        raise SecurityError(msg)

    if size > MAX_ATTACHMENT_SIZE:
        size_mb = size / (1024 * 1024)
        limit_mb = MAX_ATTACHMENT_SIZE / (1024 * 1024)
        msg = f"Attachment {filename!r} too large: {size_mb:.1f} MB (limit: {limit_mb:.0f} MB)"
        raise SecurityError(msg)


def validate_total_attachment_size(sizes: list[int], filenames: list[str] | None = None) -> None:
    """Validate combined size of all attachments."""
    total = sum(sizes)
    if total > MAX_TOTAL_ATTACHMENT_SIZE:
        total_mb = total / (1024 * 1024)
        limit_mb = MAX_TOTAL_ATTACHMENT_SIZE / (1024 * 1024)
        msg = f"Total attachments too large: {total_mb:.1f} MB (limit: {limit_mb:.0f} MB)"
        raise SecurityError(msg)


def validate_body(body: str) -> str:
    """Validate email body length."""
    if body and len(body) > MAX_BODY_LENGTH:
        msg = f"Email body too long: {len(body)} chars (max {MAX_BODY_LENGTH})"
        raise SecurityError(msg)
    return body or ""


def validate_subject(subject: str) -> str:
    """Validate email subject – reject header injection."""
    if not subject:
        return ""
    # Reject newlines (header injection)
    if any(c in subject for c in ["\n", "\r"]):
        msg = "Subject contains invalid newline characters"
        raise SecurityError(msg)
    # Reasonable length
    if len(subject) > 998:  # RFC 5322 line length limit
        msg = "Subject too long (max 998 chars)"
        raise SecurityError(msg)
    return subject


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage."""
    if not filename:
        return "attachment"

    # Remove path components
    filename = Path(filename).name

    # Remove dangerous characters (keep unicode letters)
    filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", filename)

    # Prevent hidden files on Unix
    filename = filename.lstrip(".")

    # Limit length
    if len(filename) > 255:
        name_part, _, ext = filename.rpartition(".")
        filename = name_part[: 250 - len(ext)] + "." + ext if name_part else filename[:255]

    return filename or "attachment"


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


def validate_gmail_query(query: str) -> str:
    """Validate Gmail search query."""
    if not query:
        return ""

    # Reject control characters
    suspicious = ["\0", "\r", chr(0x1B)]
    if any(char in query for char in suspicious):
        msg = "Query contains invalid control characters"
        raise SecurityError(msg)

    if len(query) > 1000:
        msg = "Query too long (max 1000 characters)"
        raise SecurityError(msg)

    return query


def validate_message_id(message_id: str) -> str:
    """Validate Gmail message ID format."""
    if not message_id or not isinstance(message_id, str):
        msg = "Message ID is required"
        raise SecurityError(msg)
    message_id = message_id.strip()
    # Gmail message IDs are hex strings
    if not re.match(r"^[a-zA-Z0-9]+$", message_id):
        msg = f"Invalid message ID format: {message_id}"
        raise SecurityError(msg)
    return message_id


def validate_label_id(label_id: str) -> str:
    """Validate Gmail label ID."""
    if not label_id or not isinstance(label_id, str):
        msg = "Label ID is required"
        raise SecurityError(msg)
    label_id = label_id.strip()
    # Gmail label IDs: system labels (INBOX, UNREAD, etc.) or custom (Label_xxx)
    if not re.match(r"^[A-Za-z0-9_-]+$", label_id):
        msg = f"Invalid label ID format: {label_id}"
        raise SecurityError(msg)
    return label_id


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
      - send/forward/reply: 10
      - draft:              20
      - search/modify:      30
      - list/read:          60
      - download:           30
    """

    DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        # (capacity, refill_rate tokens/sec)
        "send": (10, 10 / 60),
        "forward": (10, 10 / 60),
        "reply": (10, 10 / 60),
        "draft": (20, 20 / 60),
        "search": (30, 30 / 60),
        "list": (60, 60 / 60),
        "read": (60, 60 / 60),
        "modify": (30, 30 / 60),
        "download": (30, 30 / 60),
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
            msg = f"Rate limit exceeded for {operation}. Please wait before retrying."
            raise SecurityError(msg)


# Module-level singleton
rate_limiter = RateLimiter()


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------

_AUDIT_DIR = Path.home() / ".childermass"
_AUDIT_LOG_FILE = _AUDIT_DIR / "gmail-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    logger = logging.getLogger("childermass.gmail_mcp.audit")
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
        operation: Operation name (e.g. "send_email", "download_attachment")
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
