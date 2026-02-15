"""
Comprehensive test suite for Childermass Gmail MCP security layer.

Tests cover:
- Input validation (email, paths, MIME, queries, message IDs)
- Sanitization (filenames, error messages)
- Rate limiting (token bucket)
- Audit logging
- Auth keyring integration

Run with:
    pytest src/childermass/gmail_mcp/tests/ -v
"""

import json

import pytest

from childermass.gmail_mcp.security import (
    MAX_ATTACHMENT_SIZE,
    MAX_BODY_LENGTH,
    MAX_TOTAL_ATTACHMENT_SIZE,
    RateLimiter,
    SecurityError,
    audit_log,
    sanitize_error_message,
    sanitize_filename,
    validate_attachment_size,
    validate_body,
    validate_email,
    validate_email_list,
    validate_file_path,
    validate_gmail_query,
    validate_label_id,
    validate_message_id,
    validate_mime_type,
    validate_save_path,
    validate_subject,
    validate_total_attachment_size,
)


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

    def test_rejects_carriage_return(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_email("user\r@example.com")

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_email("user@example.com\0")

    def test_rejects_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid email"):
            validate_email("not-an-email")

    def test_rejects_no_domain(self):
        with pytest.raises(SecurityError, match="Invalid email"):
            validate_email("user@")


class TestValidateEmailList:
    def test_empty_returns_empty(self):
        assert validate_email_list("") == []

    def test_single_email(self):
        assert validate_email_list("a@b.com") == ["a@b.com"]

    def test_multiple_emails(self):
        result = validate_email_list("a@b.com, c@d.com, e@f.org")
        assert result == ["a@b.com", "c@d.com", "e@f.org"]

    def test_rejects_invalid_in_list(self):
        with pytest.raises(SecurityError):
            validate_email_list("valid@email.com, invalid, other@test.com")

    def test_rejects_too_many_recipients(self):
        emails = ", ".join(f"user{i}@example.com" for i in range(101))
        with pytest.raises(SecurityError, match="Too many recipients"):
            validate_email_list(emails)


# =========================================================================
# File path validation
# =========================================================================


class TestValidateFilePath:
    def test_valid_existing_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        result = validate_file_path(str(f))
        assert result == f.resolve()

    def test_rejects_nonexistent(self, tmp_path):
        with pytest.raises(SecurityError, match="not found"):
            validate_file_path(str(tmp_path / "nope.txt"))

    def test_rejects_directory(self, tmp_path):
        d = tmp_path / "subdir"
        d.mkdir()
        with pytest.raises(SecurityError, match="not a file"):
            validate_file_path(str(d))

    def test_rejects_null_bytes(self):
        with pytest.raises(SecurityError, match="null bytes"):
            validate_file_path("/etc/passwd\0.txt")

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_file_path("")

    def test_allows_nonexistent_when_unchecked(self, tmp_path):
        path = validate_file_path(str(tmp_path / "new_file.txt"), check_exists=False)
        assert path.name == "new_file.txt"

    def test_restricted_base_dirs(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("x")
        other = tmp_path / "other"
        other.mkdir()

        with pytest.raises(SecurityError, match="outside allowed"):
            validate_file_path(str(f), allowed_base_dirs=[other])


class TestValidateSavePath:
    def test_valid_save_path(self, tmp_path):
        result = validate_save_path(str(tmp_path / "output.pdf"))
        assert result.name == "output.pdf"

    def test_rejects_nonexistent_parent(self):
        with pytest.raises(SecurityError, match="does not exist"):
            validate_save_path("/nonexistent/dir/file.txt")


# =========================================================================
# MIME type validation
# =========================================================================


class TestValidateMimeType:
    def test_allowed_pdf(self):
        assert validate_mime_type("application/pdf") == "application/pdf"

    def test_allowed_image(self):
        assert validate_mime_type("image/jpeg") == "image/jpeg"

    def test_normalizes_case(self):
        assert validate_mime_type("IMAGE/PNG") == "image/png"

    def test_blocks_executable(self):
        with pytest.raises(SecurityError, match="Dangerous"):
            validate_mime_type("application/x-executable")

    def test_blocks_msdownload(self):
        with pytest.raises(SecurityError, match="Dangerous"):
            validate_mime_type("application/x-msdownload")

    def test_blocks_shell(self):
        with pytest.raises(SecurityError, match="Dangerous"):
            validate_mime_type("application/x-sh")

    def test_strict_rejects_unknown(self):
        with pytest.raises(SecurityError, match="not in whitelist"):
            validate_mime_type("application/x-custom-weird", strict=True)

    def test_non_strict_allows_unknown(self):
        result = validate_mime_type("application/x-custom", strict=False)
        assert result == "application/x-custom"


# =========================================================================
# Attachment size validation
# =========================================================================


class TestValidateAttachmentSize:
    def test_valid_size(self):
        validate_attachment_size(1024)  # 1 KB

    def test_rejects_too_large(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_attachment_size(MAX_ATTACHMENT_SIZE + 1, "huge.zip")

    def test_rejects_zero(self):
        with pytest.raises(SecurityError, match="Invalid file size"):
            validate_attachment_size(0)

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="Invalid file size"):
            validate_attachment_size(-1)


class TestValidateTotalAttachmentSize:
    def test_valid_total(self):
        validate_total_attachment_size([1024, 2048, 4096])

    def test_rejects_over_limit(self):
        with pytest.raises(SecurityError, match="Total attachments"):
            validate_total_attachment_size([MAX_TOTAL_ATTACHMENT_SIZE // 2 + 1] * 2)


# =========================================================================
# Body / Subject validation
# =========================================================================


class TestValidateBody:
    def test_valid_body(self):
        assert validate_body("Hello world") == "Hello world"

    def test_empty_returns_empty(self):
        assert validate_body("") == ""

    def test_none_returns_empty(self):
        assert validate_body(None) == ""  # type: ignore

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_body("x" * (MAX_BODY_LENGTH + 1))


class TestValidateSubject:
    def test_valid_subject(self):
        assert validate_subject("Hello") == "Hello"

    def test_empty_returns_empty(self):
        assert validate_subject("") == ""

    def test_rejects_newline(self):
        with pytest.raises(SecurityError, match="newline"):
            validate_subject("Subject\nBcc: attacker@evil.com")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_subject("x" * 999)


# =========================================================================
# Gmail query validation
# =========================================================================


class TestValidateGmailQuery:
    def test_valid_query(self):
        assert validate_gmail_query("from:boss@company.com") == "from:boss@company.com"

    def test_empty_returns_empty(self):
        assert validate_gmail_query("") == ""

    def test_rejects_null_bytes(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_gmail_query("search\0term")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_gmail_query("x" * 1001)


# =========================================================================
# Message ID / Label ID validation
# =========================================================================


class TestValidateMessageId:
    def test_valid_hex_id(self):
        assert validate_message_id("18a3b2c4d5e6f7") == "18a3b2c4d5e6f7"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_message_id("")

    def test_rejects_special_chars(self):
        with pytest.raises(SecurityError, match="Invalid message ID"):
            validate_message_id("../../../etc/passwd")


class TestValidateLabelId:
    def test_valid_system_label(self):
        assert validate_label_id("INBOX") == "INBOX"

    def test_valid_custom_label(self):
        assert validate_label_id("Label_123") == "Label_123"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_label_id("")

    def test_rejects_special_chars(self):
        with pytest.raises(SecurityError, match="Invalid label ID"):
            validate_label_id("label with spaces")


# =========================================================================
# Sanitization
# =========================================================================


class TestSanitizeFilename:
    def test_normal_filename(self):
        assert sanitize_filename("report.pdf") == "report.pdf"

    def test_removes_path_components(self):
        assert sanitize_filename("/etc/passwd") == "passwd"

    def test_removes_dangerous_chars(self):
        result = sanitize_filename('file<>:"/\\|?*.txt')
        assert "<" not in result
        assert ">" not in result

    def test_prevents_hidden_files(self):
        result = sanitize_filename(".bashrc")
        assert not result.startswith(".")

    def test_empty_returns_default(self):
        assert sanitize_filename("") == "attachment"

    def test_truncates_long_names(self):
        result = sanitize_filename("a" * 300 + ".pdf")
        assert len(result) <= 255


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

    def test_removes_password(self):
        msg = sanitize_error_message(Exception("password: supersecret123"))
        assert "supersecret123" not in msg

    def test_removes_file_paths(self):
        msg = sanitize_error_message(Exception("Error reading /home/user/gmail-credentials.json"))
        assert "gmail-credentials.json" not in msg

    def test_preserves_safe_messages(self):
        msg = sanitize_error_message(Exception("Connection timed out"))
        assert msg == "Connection timed out"


# =========================================================================
# Rate Limiting
# =========================================================================


class TestRateLimiter:
    def test_allows_within_limit(self):
        rl = RateLimiter()
        for _ in range(10):
            assert rl.allow("user@test.com", "send") is True

    def test_rejects_over_limit(self):
        rl = RateLimiter()
        # send limit is 10
        for _ in range(10):
            rl.allow("user@test.com", "send")
        assert rl.allow("user@test.com", "send") is False

    def test_refills_over_time(self):
        rl = RateLimiter()
        for _ in range(10):
            rl.allow("user@test.com", "send")

        # Simulate time passing (manipulate internal state)
        key = rl._key("user@test.com", "send")
        rl._buckets[key].last_refill -= 60  # 60 seconds ago

        assert rl.allow("user@test.com", "send") is True

    def test_different_accounts_independent(self):
        rl = RateLimiter()
        for _ in range(10):
            rl.allow("user1@test.com", "send")

        # user2 should still be allowed
        assert rl.allow("user2@test.com", "send") is True

    def test_different_operations_independent(self):
        rl = RateLimiter()
        for _ in range(10):
            rl.allow("user@test.com", "send")

        # list should still work
        assert rl.allow("user@test.com", "list") is True

    def test_check_raises_on_limit(self):
        rl = RateLimiter()
        for _ in range(10):
            rl.allow("user@test.com", "send")

        with pytest.raises(SecurityError, match="Rate limit"):
            rl.check("user@test.com", "send")


# =========================================================================
# Audit Logging
# =========================================================================


class TestAuditLog:
    def test_writes_json_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "audit.log"
        monkeypatch.setattr("childermass.gmail_mcp.security._AUDIT_LOG_FILE", log_file)
        monkeypatch.setattr("childermass.gmail_mcp.security._AUDIT_DIR", tmp_path)
        # Reset logger handlers
        import logging

        logger = logging.getLogger("childermass.gmail_mcp.audit")
        logger.handlers.clear()

        audit_log("send_email", "user@test.com", {"to": "recipient@test.com"})

        # Flush handlers
        for h in logger.handlers:
            h.flush()

        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["operation"] == "send_email"
        assert entry["account"] == "user@test.com"
        assert entry["success"] is True
        assert entry["details"]["to"] == "recipient@test.com"

    def test_failure_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "audit.log"
        monkeypatch.setattr("childermass.gmail_mcp.security._AUDIT_LOG_FILE", log_file)
        monkeypatch.setattr("childermass.gmail_mcp.security._AUDIT_DIR", tmp_path)
        import logging

        logger = logging.getLogger("childermass.gmail_mcp.audit")
        logger.handlers.clear()

        audit_log("send_email", "user@test.com", success=False)

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
        from childermass.gmail_mcp.auth import _is_keyring_available

        # Should return bool (may be True or False depending on environment)
        result = _is_keyring_available()
        assert isinstance(result, bool)

    def test_list_authenticated_accounts_empty(self, tmp_path, monkeypatch):
        """With no tokens, should return empty list."""
        monkeypatch.setattr("childermass.gmail_mcp.auth.DEFAULT_TOKEN_DIR", tmp_path / "empty")
        monkeypatch.setattr("childermass.gmail_mcp.auth._keyring_available", False)

        from childermass.gmail_mcp.auth import list_authenticated_accounts

        accounts = list_authenticated_accounts()
        assert accounts == []

    def test_credentials_path_default(self):
        from childermass.gmail_mcp.auth import get_credentials_path

        path = get_credentials_path()
        assert path.name == "gmail-credentials.json"

    def test_token_path_with_account(self):
        from childermass.gmail_mcp.auth import get_token_path

        path = get_token_path("user@example.com")
        assert "user@example.com" in path.name


# =========================================================================
# Integration tests (mocked Gmail API)
# =========================================================================


class TestClientValidation:
    """Test that client functions properly validate inputs."""

    def test_send_email_validates_recipient(self):
        from childermass.gmail_mcp.client import send_email

        with pytest.raises(SecurityError, match="Invalid email"):
            send_email(
                to="not-an-email",
                subject="Test",
                body="Hello",
            )

    def test_send_email_validates_subject_injection(self):
        from childermass.gmail_mcp.client import send_email

        with pytest.raises(SecurityError, match="newline"):
            send_email(
                to="valid@email.com",
                subject="Subject\nBcc: attacker@evil.com",
                body="Hello",
            )

    def test_send_email_validates_body_length(self):
        from childermass.gmail_mcp.client import send_email

        with pytest.raises(SecurityError, match="too long"):
            send_email(
                to="valid@email.com",
                subject="Test",
                body="x" * (MAX_BODY_LENGTH + 1),
            )

    def test_forward_validates_recipient(self):
        from childermass.gmail_mcp.client import forward_email

        with pytest.raises(SecurityError, match="Invalid email"):
            forward_email(
                message_id="abc123",
                to="not-valid",
            )

    def test_forward_validates_message_id(self):
        from childermass.gmail_mcp.client import forward_email

        with pytest.raises(SecurityError, match="Invalid message ID"):
            forward_email(
                message_id="../../../etc",
                to="valid@email.com",
            )

    def test_reply_validates_message_id(self):
        from childermass.gmail_mcp.client import reply_to_email

        with pytest.raises(SecurityError, match="Invalid message ID"):
            reply_to_email(
                message_id="!!!invalid",
                body="Hello",
            )

    def test_get_email_validates_message_id(self):
        from childermass.gmail_mcp.client import get_email

        with pytest.raises(SecurityError, match="Invalid message ID"):
            get_email("../../passwd")

    def test_search_validates_query(self):
        from childermass.gmail_mcp.client import search_emails

        with pytest.raises(SecurityError, match="control characters"):
            search_emails(query="search\0term")

    def test_modify_labels_validates_ids(self):
        from childermass.gmail_mcp.client import modify_labels

        with pytest.raises(SecurityError, match="Invalid message ID"):
            modify_labels("../invalid", add_label_ids=["INBOX"])

    def test_modify_labels_validates_label_ids(self):
        from childermass.gmail_mcp.client import modify_labels

        with pytest.raises(SecurityError, match="Invalid label ID"):
            modify_labels("abc123", add_label_ids=["label with spaces!"])
