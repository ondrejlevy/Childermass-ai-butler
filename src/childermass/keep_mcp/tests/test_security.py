"""
Comprehensive test suite for Childermass Keep MCP security layer.

Tests cover:
- Input validation (note title, text, IDs, colors, labels, emails)
- Sanitization (error messages)
- Rate limiting (token bucket)
- Audit logging
- Auth keyring integration

Run with:
    pytest src/childermass/keep_mcp/tests/ -v
"""

import json

import pytest

from childermass.keep_mcp.security import (
    MAX_LABEL_LENGTH,
    MAX_LIST_ITEM_LENGTH,
    MAX_TEXT_LENGTH,
    MAX_TITLE_LENGTH,
    VALID_COLORS,
    RateLimiter,
    SecurityError,
    audit_log,
    sanitize_error_message,
    validate_color,
    validate_email,
    validate_item_id,
    validate_label_name,
    validate_list_item_text,
    validate_max_results,
    validate_note_id,
    validate_note_text,
    validate_note_title,
    validate_note_type,
    validate_query,
)


# =========================================================================
# Note title validation
# =========================================================================


class TestValidateNoteTitle:
    def test_valid_title(self):
        assert validate_note_title("My Note") == "My Note"

    def test_none_returns_empty(self):
        assert validate_note_title(None) == ""

    def test_empty_returns_empty(self):
        assert validate_note_title("") == ""

    def test_rejects_null_bytes(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_note_title("Title\0")

    def test_rejects_escape_chars(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_note_title("Title\x1b[31m")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_note_title("x" * (MAX_TITLE_LENGTH + 1))

    def test_allows_unicode(self):
        assert validate_note_title("Nákupní seznam 🛒") == "Nákupní seznam 🛒"

    def test_allows_newlines(self):
        # Newlines are valid in titles
        assert validate_note_title("Line 1\nLine 2") == "Line 1\nLine 2"


# =========================================================================
# Note text validation
# =========================================================================


class TestValidateNoteText:
    def test_valid_text(self):
        assert validate_note_text("Hello world") == "Hello world"

    def test_none_returns_empty(self):
        assert validate_note_text(None) == ""

    def test_empty_returns_empty(self):
        assert validate_note_text("") == ""

    def test_rejects_null_bytes(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_note_text("Text\0content")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_note_text("x" * (MAX_TEXT_LENGTH + 1))

    def test_allows_long_text(self):
        text = "x" * MAX_TEXT_LENGTH
        assert validate_note_text(text) == text


# =========================================================================
# List item text validation
# =========================================================================


class TestValidateListItemText:
    def test_valid_item(self):
        assert validate_list_item_text("Buy milk") == "Buy milk"

    def test_strips_whitespace(self):
        assert validate_list_item_text("  Buy milk  ") == "Buy milk"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_list_item_text("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_list_item_text(None)  # type: ignore

    def test_rejects_null_bytes(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_list_item_text("Item\0")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_list_item_text("x" * (MAX_LIST_ITEM_LENGTH + 1))


# =========================================================================
# Note ID validation
# =========================================================================


class TestValidateNoteId:
    def test_valid_id(self):
        assert validate_note_id("abc123") == "abc123"

    def test_valid_id_with_special(self):
        assert validate_note_id("note-123_v2.0") == "note-123_v2.0"

    def test_strips_whitespace(self):
        assert validate_note_id("  abc123  ") == "abc123"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_note_id("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_note_id(None)  # type: ignore

    def test_rejects_path_traversal(self):
        with pytest.raises(SecurityError, match="Invalid note ID"):
            validate_note_id("../../../etc/passwd")

    def test_rejects_control_chars(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_note_id("id\nmore")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_note_id("a" * 201)

    def test_rejects_spaces(self):
        with pytest.raises(SecurityError, match="Invalid note ID"):
            validate_note_id("note with spaces")


# =========================================================================
# Item ID validation
# =========================================================================


class TestValidateItemId:
    def test_valid_id(self):
        assert validate_item_id("item123") == "item123"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_item_id("")

    def test_rejects_special_chars(self):
        with pytest.raises(SecurityError, match="Invalid item ID"):
            validate_item_id("item/../../etc")


# =========================================================================
# Color validation
# =========================================================================


class TestValidateColor:
    def test_valid_colors(self):
        for color in VALID_COLORS:
            assert validate_color(color) == color

    def test_case_insensitive(self):
        assert validate_color("RED") == "red"

    def test_strips_whitespace(self):
        assert validate_color("  blue  ") == "blue"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Invalid color"):
            validate_color("neon")

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_color("")


# =========================================================================
# Note type validation
# =========================================================================


class TestValidateNoteType:
    def test_valid_text(self):
        assert validate_note_type("text") == "text"

    def test_valid_list(self):
        assert validate_note_type("list") == "list"

    def test_case_insensitive(self):
        assert validate_note_type("LIST") == "list"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Invalid note type"):
            validate_note_type("document")

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_note_type("")


# =========================================================================
# Label name validation
# =========================================================================


class TestValidateLabelName:
    def test_valid_label(self):
        assert validate_label_name("TODO") == "TODO"

    def test_strips_whitespace(self):
        assert validate_label_name("  Shopping  ") == "Shopping"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_label_name("")

    def test_rejects_null_bytes(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_label_name("label\0")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_label_name("x" * (MAX_LABEL_LENGTH + 1))

    def test_allows_unicode(self):
        assert validate_label_name("Domácnost") == "Domácnost"


# =========================================================================
# Email validation
# =========================================================================


class TestValidateEmail:
    def test_valid_email(self):
        assert validate_email("user@example.com") == "user@example.com"

    def test_valid_email_with_name(self):
        assert validate_email("John Doe <john@example.com>") == "john@example.com"

    def test_normalizes_to_lowercase(self):
        assert validate_email("USER@EXAMPLE.COM") == "user@example.com"

    def test_strips_whitespace(self):
        assert validate_email("  user@example.com  ") == "user@example.com"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_email("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_email(None)  # type: ignore

    def test_rejects_newline_injection(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_email("user@example.com\nBcc: attacker@evil.com")

    def test_rejects_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid email"):
            validate_email("not-an-email")


# =========================================================================
# Query validation
# =========================================================================


class TestValidateQuery:
    def test_valid_query(self):
        assert validate_query("nákupní seznam") == "nákupní seznam"

    def test_empty_returns_empty(self):
        assert validate_query("") == ""

    def test_rejects_null_bytes(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_query("search\0term")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_query("x" * 1001)


# =========================================================================
# Max results validation
# =========================================================================


class TestValidateMaxResults:
    def test_valid_value(self):
        assert validate_max_results(50) == 50

    def test_clamps_to_min(self):
        assert validate_max_results(0) == 1
        assert validate_max_results(-5) == 1

    def test_clamps_to_max(self):
        assert validate_max_results(1000) == 500


# =========================================================================
# Error message sanitization
# =========================================================================


class TestSanitizeErrorMessage:
    def test_removes_bearer_token(self):
        msg = sanitize_error_message(Exception("Bearer ya29.abc123xyz"))
        assert "ya29.abc123xyz" not in msg
        assert "***" in msg

    def test_removes_google_access_token(self):
        msg = sanitize_error_message(Exception("got ya29.longtoken123 in response"))
        assert "ya29.***" in msg

    def test_removes_refresh_token(self):
        msg = sanitize_error_message(Exception("refresh 1//abc_def-ghi"))
        assert "1//***" in msg

    def test_removes_master_token(self):
        msg = sanitize_error_message(Exception("master_token: aas_et/abc123_xyz"))
        # The password/token pattern matches first, redacting the whole value
        assert "abc123_xyz" not in msg

    def test_removes_password(self):
        msg = sanitize_error_message(Exception("password: supersecret123"))
        assert "supersecret123" not in msg

    def test_removes_file_paths(self):
        msg = sanitize_error_message(
            Exception("Error reading /home/user/keep-token.json")
        )
        assert "keep-token.json" not in msg

    def test_preserves_safe_messages(self):
        msg = sanitize_error_message(Exception("Connection timed out"))
        assert msg == "Connection timed out"


# =========================================================================
# Rate Limiting
# =========================================================================


class TestRateLimiter:
    def test_allows_within_limit(self):
        rl = RateLimiter()
        for _ in range(20):
            assert rl.allow("user@test.com", "create") is True

    def test_rejects_over_limit(self):
        rl = RateLimiter()
        # create limit is 20
        for _ in range(20):
            rl.allow("user@test.com", "create")
        assert rl.allow("user@test.com", "create") is False

    def test_refills_over_time(self):
        rl = RateLimiter()
        for _ in range(20):
            rl.allow("user@test.com", "create")

        # Simulate time passing
        key = rl._key("user@test.com", "create")
        rl._buckets[key].last_refill -= 60  # 60 seconds ago

        assert rl.allow("user@test.com", "create") is True

    def test_different_accounts_independent(self):
        rl = RateLimiter()
        for _ in range(20):
            rl.allow("user1@test.com", "create")

        assert rl.allow("user2@test.com", "create") is True

    def test_different_operations_independent(self):
        rl = RateLimiter()
        for _ in range(20):
            rl.allow("user@test.com", "create")

        assert rl.allow("user@test.com", "list") is True

    def test_check_raises_on_limit(self):
        rl = RateLimiter()
        for _ in range(20):
            rl.allow("user@test.com", "create")

        with pytest.raises(SecurityError, match="Rate limit"):
            rl.check("user@test.com", "create")

    def test_share_limit_is_10(self):
        rl = RateLimiter()
        for _ in range(10):
            assert rl.allow("user@test.com", "share") is True
        assert rl.allow("user@test.com", "share") is False

    def test_list_limit_is_60(self):
        rl = RateLimiter()
        for _ in range(60):
            assert rl.allow("user@test.com", "list") is True
        assert rl.allow("user@test.com", "list") is False


# =========================================================================
# Audit Logging
# =========================================================================


class TestAuditLog:
    def test_writes_json_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "audit.log"
        monkeypatch.setattr(
            "childermass.keep_mcp.security._AUDIT_LOG_FILE", log_file
        )
        monkeypatch.setattr(
            "childermass.keep_mcp.security._AUDIT_DIR", tmp_path
        )
        # Reset logger handlers
        import logging

        logger = logging.getLogger("childermass.keep_mcp.audit")
        logger.handlers.clear()

        audit_log("create_note", "user@test.com", {"title": "Test Note"})

        for h in logger.handlers:
            h.flush()

        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["operation"] == "create_note"
        assert entry["account"] == "user@test.com"
        assert entry["success"] is True
        assert entry["details"]["title"] == "Test Note"

    def test_failure_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "audit.log"
        monkeypatch.setattr(
            "childermass.keep_mcp.security._AUDIT_LOG_FILE", log_file
        )
        monkeypatch.setattr(
            "childermass.keep_mcp.security._AUDIT_DIR", tmp_path
        )
        import logging

        logger = logging.getLogger("childermass.keep_mcp.audit")
        logger.handlers.clear()

        audit_log("share_note", "user@test.com", success=False)

        for h in logger.handlers:
            h.flush()

        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["success"] is False


# =========================================================================
# Auth module tests
# =========================================================================


class TestAuthKeyring:
    def test_keyring_detection(self):
        """Test that keyring availability detection works."""
        from childermass.keep_mcp.auth import _is_keyring_available

        result = _is_keyring_available()
        assert isinstance(result, bool)

    def test_list_authenticated_accounts_empty(self, tmp_path, monkeypatch):
        """With no tokens, should return empty list."""
        monkeypatch.setattr(
            "childermass.keep_mcp.auth.DEFAULT_TOKEN_DIR", tmp_path / "empty"
        )
        monkeypatch.setattr(
            "childermass.keep_mcp.auth._keyring_available", False
        )

        from childermass.keep_mcp.auth import list_authenticated_accounts

        accounts = list_authenticated_accounts()
        assert accounts == []

    def test_token_path_with_account(self):
        from childermass.keep_mcp.auth import get_token_path

        path = get_token_path("user@example.com")
        assert "user@example.com" in path.name

    def test_cache_path(self):
        from childermass.keep_mcp.auth import _get_cache_path

        path = _get_cache_path("user@example.com")
        assert "keep-cache-user@example.com" in path.name

    def test_save_and_load_master_token(self, tmp_path, monkeypatch):
        """Test file-based token save/load round-trip."""
        monkeypatch.setattr(
            "childermass.keep_mcp.auth.DEFAULT_TOKEN_DIR", tmp_path
        )
        monkeypatch.setattr(
            "childermass.keep_mcp.auth._keyring_available", False
        )

        from childermass.keep_mcp.auth import load_master_token, save_master_token

        save_master_token("test_token_123", "test@example.com", "test@example.com")

        token = load_master_token("test@example.com")
        assert token == "test_token_123"

    def test_load_nonexistent_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "childermass.keep_mcp.auth.DEFAULT_TOKEN_DIR", tmp_path
        )
        monkeypatch.setattr(
            "childermass.keep_mcp.auth._keyring_available", False
        )

        from childermass.keep_mcp.auth import load_master_token

        assert load_master_token("nonexistent@example.com") is None


# =========================================================================
# Client validation tests (mocked gkeepapi)
# =========================================================================


class TestClientInputValidation:
    """Test that client functions properly validate inputs."""

    def test_create_note_validates_title_length(self):
        """Title over limit should be rejected before hitting API."""
        from childermass.keep_mcp.client import create_note

        with pytest.raises(SecurityError, match="too long"):
            create_note(title="x" * (MAX_TITLE_LENGTH + 1))

    def test_create_note_validates_text_length(self):
        from childermass.keep_mcp.client import create_note

        with pytest.raises(SecurityError, match="too long"):
            create_note(title="Test", content="x" * (MAX_TEXT_LENGTH + 1))

    def test_create_note_validates_note_type(self):
        from childermass.keep_mcp.client import create_note

        with pytest.raises(SecurityError, match="Invalid note type"):
            create_note(title="Test", note_type="document")

    def test_get_note_validates_id(self):
        from childermass.keep_mcp.client import get_note

        with pytest.raises(SecurityError, match="Invalid note ID"):
            get_note("../../../etc/passwd")

    def test_delete_note_validates_id(self):
        from childermass.keep_mcp.client import delete_note

        with pytest.raises(SecurityError, match="Invalid note ID"):
            delete_note("!!!invalid")

    def test_share_note_validates_email(self):
        from childermass.keep_mcp.client import share_note

        with pytest.raises(SecurityError, match="Invalid email"):
            share_note("abc123", "not-an-email")

    def test_share_note_validates_note_id(self):
        from childermass.keep_mcp.client import share_note

        with pytest.raises(SecurityError, match="Invalid note ID"):
            share_note("../invalid", "valid@email.com")

    def test_add_list_item_validates_text(self):
        from childermass.keep_mcp.client import add_list_item

        with pytest.raises(SecurityError, match="required"):
            add_list_item("abc123", "")

    def test_add_list_item_validates_text_length(self):
        from childermass.keep_mcp.client import add_list_item

        with pytest.raises(SecurityError, match="too long"):
            add_list_item("abc123", "x" * (MAX_LIST_ITEM_LENGTH + 1))

    def test_update_list_item_validates_ids(self):
        from childermass.keep_mcp.client import update_list_item

        with pytest.raises(SecurityError, match="Invalid note ID"):
            update_list_item("../invalid", "item1")

    def test_create_label_validates_name(self):
        from childermass.keep_mcp.client import create_label

        with pytest.raises(SecurityError, match="required"):
            create_label("")

    def test_search_validates_query(self):
        from childermass.keep_mcp.client import search_notes

        with pytest.raises(SecurityError, match="required"):
            search_notes("")

    def test_set_color_validates_color(self):
        from childermass.keep_mcp.client import set_note_color

        with pytest.raises(SecurityError, match="Invalid color"):
            set_note_color("abc123", "neon")

    def test_validate_color_in_update(self):
        from childermass.keep_mcp.client import update_note

        with pytest.raises(SecurityError, match="Invalid color"):
            update_note("abc123", color="rainbow")
