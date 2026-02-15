"""
Tests for tasks_mcp security module.

Covers all validators, sanitizers, rate limiter, and audit logging.
"""

import json
import logging

import pytest

from childermass.tasks_mcp.security import (
    MAX_NOTES_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_TITLE_LENGTH,
    RateLimiter,
    SecurityError,
    audit_log,
    sanitize_error_message,
    validate_due_date,
    validate_max_results,
    validate_search_query,
    validate_task_id,
    validate_task_notes,
    validate_task_status,
    validate_task_title,
    validate_tasklist_id,
    validate_tasklist_title,
)


# ===========================================================================
# validate_tasklist_id
# ===========================================================================


class TestValidateTasklistId:
    def test_valid_id(self):
        assert validate_tasklist_id("MTczNjQ0OTk") == "MTczNjQ0OTk"

    def test_valid_with_hyphens(self):
        assert validate_tasklist_id("abc-def_123") == "abc-def_123"

    def test_strips_whitespace(self):
        assert validate_tasklist_id("  abc123  ") == "abc123"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="Task list ID is required"):
            validate_tasklist_id("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="Task list ID is required"):
            validate_tasklist_id(None)

    def test_newline_injection(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_tasklist_id("abc\ndef")

    def test_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_tasklist_id("abc\0def")

    def test_tab_injection(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_tasklist_id("abc\tdef")

    def test_invalid_chars(self):
        with pytest.raises(SecurityError, match="Invalid task list ID"):
            validate_tasklist_id("abc def!@#")

    def test_slash_rejected(self):
        with pytest.raises(SecurityError, match="Invalid task list ID"):
            validate_tasklist_id("abc/def")


# ===========================================================================
# validate_task_id
# ===========================================================================


class TestValidateTaskId:
    def test_valid_id(self):
        assert validate_task_id("dGFzazE") == "dGFzazE"

    def test_valid_with_hyphens_underscores(self):
        assert validate_task_id("abc-def_123") == "abc-def_123"

    def test_strips_whitespace(self):
        assert validate_task_id("  abc123  ") == "abc123"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="Task ID is required"):
            validate_task_id("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="Task ID is required"):
            validate_task_id(None)

    def test_newline_injection(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_task_id("abc\ndef")

    def test_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_task_id("abc\0def")

    def test_invalid_chars(self):
        with pytest.raises(SecurityError, match="Invalid task ID"):
            validate_task_id("abc def!@#")

    def test_special_chars_rejected(self):
        with pytest.raises(SecurityError, match="Invalid task ID"):
            validate_task_id("abc;DROP TABLE")


# ===========================================================================
# validate_task_title
# ===========================================================================


class TestValidateTaskTitle:
    def test_valid(self):
        assert validate_task_title("Buy groceries") == "Buy groceries"

    def test_strips_whitespace(self):
        assert validate_task_title("  Buy milk  ") == "Buy milk"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="Task title is required"):
            validate_task_title("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="Task title is required"):
            validate_task_title(None)

    def test_whitespace_only_raises(self):
        with pytest.raises(SecurityError, match="cannot be empty"):
            validate_task_title("   ")

    def test_carriage_return_raises(self):
        with pytest.raises(SecurityError, match="carriage return"):
            validate_task_title("Bad\rTitle")

    def test_newline_allowed(self):
        # Tasks API allows newlines in titles
        result = validate_task_title("Line 1\nLine 2")
        assert result == "Line 1\nLine 2"

    def test_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_task_title("x" * (MAX_TITLE_LENGTH + 1))

    def test_max_length_ok(self):
        title = "x" * MAX_TITLE_LENGTH
        assert validate_task_title(title) == title

    def test_unicode_allowed(self):
        result = validate_task_title("Nákup v Albertu 🛒")
        assert result == "Nákup v Albertu 🛒"


# ===========================================================================
# validate_tasklist_title
# ===========================================================================


class TestValidateTasklistTitle:
    def test_valid(self):
        assert validate_tasklist_title("Shopping") == "Shopping"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="Task title is required"):
            validate_tasklist_title("")

    def test_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_tasklist_title("x" * (MAX_TITLE_LENGTH + 1))


# ===========================================================================
# validate_task_notes
# ===========================================================================


class TestValidateTaskNotes:
    def test_valid(self):
        assert validate_task_notes("Some notes here") == "Some notes here"

    def test_empty(self):
        assert validate_task_notes("") == ""

    def test_none(self):
        assert validate_task_notes(None) == ""

    def test_multiline(self):
        notes = "Line 1\nLine 2\nLine 3"
        assert validate_task_notes(notes) == notes

    def test_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_task_notes("x" * (MAX_NOTES_LENGTH + 1))

    def test_max_length_ok(self):
        notes = "x" * MAX_NOTES_LENGTH
        assert validate_task_notes(notes) == notes


# ===========================================================================
# validate_task_status
# ===========================================================================


class TestValidateTaskStatus:
    def test_needs_action(self):
        assert validate_task_status("needsAction") == "needsAction"

    def test_completed(self):
        assert validate_task_status("completed") == "completed"

    def test_strips_whitespace(self):
        assert validate_task_status("  needsAction  ") == "needsAction"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="Task status is required"):
            validate_task_status("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="Task status is required"):
            validate_task_status(None)

    def test_invalid_status(self):
        with pytest.raises(SecurityError, match="Invalid task status"):
            validate_task_status("in_progress")

    def test_case_sensitive(self):
        with pytest.raises(SecurityError, match="Invalid task status"):
            validate_task_status("Completed")

    def test_pending_rejected(self):
        with pytest.raises(SecurityError, match="Invalid task status"):
            validate_task_status("pending")


# ===========================================================================
# validate_due_date
# ===========================================================================


class TestValidateDueDate:
    def test_date_only(self):
        result = validate_due_date("2024-01-15")
        assert result == "2024-01-15T00:00:00.000Z"

    def test_datetime_utc(self):
        result = validate_due_date("2024-01-15T00:00:00Z")
        assert result == "2024-01-15T00:00:00Z"

    def test_datetime_utc_with_millis(self):
        result = validate_due_date("2024-01-15T00:00:00.000Z")
        assert result == "2024-01-15T00:00:00.000Z"

    def test_datetime_with_offset(self):
        result = validate_due_date("2024-01-15T10:00:00+01:00")
        assert result == "2024-01-15T10:00:00+01:00"

    def test_strips_whitespace(self):
        result = validate_due_date("  2024-01-15  ")
        assert result == "2024-01-15T00:00:00.000Z"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="Due date is required"):
            validate_due_date("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="Due date is required"):
            validate_due_date(None)

    def test_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid due date"):
            validate_due_date("January 15, 2024")

    def test_no_timezone_raises(self):
        with pytest.raises(SecurityError, match="Invalid due date"):
            validate_due_date("2024-01-15T10:00:00")

    def test_partial_date_raises(self):
        with pytest.raises(SecurityError, match="Invalid due date"):
            validate_due_date("2024-01")

    def test_text_raises(self):
        with pytest.raises(SecurityError, match="Invalid due date"):
            validate_due_date("tomorrow")


# ===========================================================================
# validate_max_results
# ===========================================================================


class TestValidateMaxResults:
    def test_valid(self):
        assert validate_max_results(50) == 50

    def test_one(self):
        assert validate_max_results(1) == 1

    def test_max(self):
        assert validate_max_results(100) == 100

    def test_zero_raises(self):
        with pytest.raises(SecurityError, match="at least 1"):
            validate_max_results(0)

    def test_negative_raises(self):
        with pytest.raises(SecurityError, match="at least 1"):
            validate_max_results(-1)

    def test_too_large_raises(self):
        with pytest.raises(SecurityError, match="cannot exceed 100"):
            validate_max_results(101)


# ===========================================================================
# validate_search_query
# ===========================================================================


class TestValidateSearchQuery:
    def test_valid(self):
        assert validate_search_query("groceries") == "groceries"

    def test_empty(self):
        assert validate_search_query("") == ""

    def test_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_search_query("query\0injection")

    def test_escape_char(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_search_query("query\x1binjection")

    def test_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_search_query("x" * (MAX_QUERY_LENGTH + 1))


# ===========================================================================
# sanitize_error_message
# ===========================================================================


class TestSanitizeErrorMessage:
    def test_bearer_token(self):
        err = Exception("Unauthorized: Bearer ya29.abcdefghijk123")
        result = sanitize_error_message(err)
        assert "ya29." not in result
        assert "***" in result

    def test_access_token(self):
        err = Exception("token=ya29.longaccesstokenhere")
        result = sanitize_error_message(err)
        assert "ya29.longaccesstokenhere" not in result

    def test_refresh_token(self):
        err = Exception("refresh: 1//0abcDEF_ghiJKL")
        result = sanitize_error_message(err)
        assert "0abcDEF_ghiJKL" not in result

    def test_password(self):
        err = Exception("password=supersecret123")
        result = sanitize_error_message(err)
        assert "supersecret123" not in result

    def test_file_paths(self):
        err = Exception("Error reading /home/user/credentials.json")
        result = sanitize_error_message(err)
        assert "credentials.json" in result  # sanitized path
        assert "/home/user" not in result

    def test_safe_message_unchanged(self):
        err = Exception("Task not found")
        result = sanitize_error_message(err)
        assert result == "Task not found"


# ===========================================================================
# RateLimiter
# ===========================================================================


class TestRateLimiter:
    def test_within_limit(self):
        limiter = RateLimiter()
        for _ in range(29):
            assert limiter.allow("test@gmail.com", "create_task") is True

    def test_over_limit(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("test@gmail.com", "create_task")
        assert limiter.allow("test@gmail.com", "create_task") is False

    def test_refill(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("test@gmail.com", "create_task")
        assert limiter.allow("test@gmail.com", "create_task") is False

        # Manually advance bucket time
        key = limiter._key("test@gmail.com", "create_task")
        bucket = limiter._buckets[key]
        bucket.last_refill -= 60  # Back 60 seconds

        assert limiter.allow("test@gmail.com", "create_task") is True

    def test_per_account_isolation(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("account1@gmail.com", "create_task")

        # Different account should not be affected
        assert limiter.allow("account2@gmail.com", "create_task") is True

    def test_per_operation_isolation(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("test@gmail.com", "create_task")

        # Different operation should not be affected
        assert limiter.allow("test@gmail.com", "list_tasks") is True

    def test_check_raises(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("test@gmail.com", "create_task")

        with pytest.raises(SecurityError, match="Rate limit exceeded"):
            limiter.check("test@gmail.com", "create_task")

    def test_delete_lower_limit(self):
        limiter = RateLimiter()
        for _ in range(10):
            limiter.allow("test@gmail.com", "delete_task")
        assert limiter.allow("test@gmail.com", "delete_task") is False

    def test_list_higher_limit(self):
        limiter = RateLimiter()
        for _ in range(59):
            assert limiter.allow("test@gmail.com", "list_tasks") is True


# ===========================================================================
# Audit Logging
# ===========================================================================


class TestAuditLog:
    def test_audit_entry_json(self, tmp_path, monkeypatch):
        log_file = tmp_path / "test-audit.log"
        monkeypatch.setattr("childermass.tasks_mcp.security._AUDIT_LOG_FILE", log_file)
        monkeypatch.setattr("childermass.tasks_mcp.security._AUDIT_DIR", tmp_path)

        # Clear any cached logger handlers
        logger = logging.getLogger("childermass.tasks_mcp.audit")
        logger.handlers.clear()

        audit_log(
            operation="create_task",
            account="test@gmail.com",
            details={"task_id": "abc123", "title": "Buy milk"},
            success=True,
        )

        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["operation"] == "create_task"
        assert entry["account"] == "test@gmail.com"
        assert entry["success"] is True
        assert entry["details"]["task_id"] == "abc123"

    def test_audit_failure_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "test-audit.log"
        monkeypatch.setattr("childermass.tasks_mcp.security._AUDIT_LOG_FILE", log_file)
        monkeypatch.setattr("childermass.tasks_mcp.security._AUDIT_DIR", tmp_path)

        logger = logging.getLogger("childermass.tasks_mcp.audit")
        logger.handlers.clear()

        audit_log(
            operation="delete_task",
            account="test@gmail.com",
            success=False,
        )

        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["operation"] == "delete_task"
        assert entry["success"] is False


# ===========================================================================
# Auth module basic checks
# ===========================================================================


class TestAuthBasics:
    def test_keyring_service_name(self):
        from childermass.tasks_mcp.auth import KEYRING_SERVICE

        assert KEYRING_SERVICE == "childermass-tasks-mcp"
        # Must differ from Gmail and Calendar
        assert KEYRING_SERVICE != "childermass-gmail-mcp"
        assert KEYRING_SERVICE != "childermass-calendar-mcp"

    def test_credentials_path(self):
        from childermass.tasks_mcp.auth import DEFAULT_CREDENTIALS_PATH

        assert "tasks-credentials.json" in str(DEFAULT_CREDENTIALS_PATH)
        assert "gmail-credentials.json" not in str(DEFAULT_CREDENTIALS_PATH)
        assert "calendar-credentials.json" not in str(DEFAULT_CREDENTIALS_PATH)

    def test_token_path(self):
        from childermass.tasks_mcp.auth import get_token_path

        path = get_token_path("user@gmail.com")
        assert "tasks-tokens-user@gmail.com.json" in str(path)

    def test_scopes(self):
        from childermass.tasks_mcp.auth import SCOPES

        assert any("tasks" in s for s in SCOPES)
        assert not any("gmail" in s for s in SCOPES)
        assert not any("calendar" in s for s in SCOPES)


# ===========================================================================
# Client validation integration
# ===========================================================================


class TestClientValidation:
    """Test that client functions properly validate inputs."""

    def test_create_task_validates_title(self):
        """Empty title should be rejected."""
        with pytest.raises(SecurityError, match="Task title is required"):
            from childermass.tasks_mcp.client import create_task

            create_task(tasklist_id="abc123", title="")

    def test_create_task_validates_tasklist_id(self):
        """Invalid tasklist ID should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.tasks_mcp.client import create_task

            create_task(tasklist_id="", title="Test")

    def test_get_task_validates_ids(self):
        """Invalid IDs should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.tasks_mcp.client import get_task

            get_task(tasklist_id="", task_id="abc")

    def test_delete_task_validates_ids(self):
        """Invalid IDs should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.tasks_mcp.client import delete_task

            delete_task(tasklist_id="", task_id="abc")

    def test_complete_task_validates_ids(self):
        """Invalid IDs should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.tasks_mcp.client import complete_task

            complete_task(tasklist_id="", task_id="abc")

    def test_create_tasklist_validates_title(self):
        """Empty tasklist title should be rejected."""
        with pytest.raises(SecurityError, match="Task title is required"):
            from childermass.tasks_mcp.client import create_tasklist

            create_tasklist(title="")

    def test_list_tasks_validates_tasklist_id(self):
        """Control chars in tasklist ID should be rejected."""
        with pytest.raises(SecurityError, match="control characters"):
            from childermass.tasks_mcp.client import list_tasks

            list_tasks(tasklist_id="abc\ndef")

    def test_move_task_validates_ids(self):
        """Invalid IDs should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.tasks_mcp.client import move_task

            move_task(tasklist_id="", task_id="abc")

    def test_update_task_validates_ids(self):
        """Invalid IDs should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.tasks_mcp.client import update_task

            update_task(tasklist_id="", task_id="abc")
