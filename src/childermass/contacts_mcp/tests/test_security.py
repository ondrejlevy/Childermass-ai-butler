"""
Comprehensive test suite for Childermass Contacts MCP security layer.

Tests cover:
- Input validation (resource names, emails, phones, names, orgs, etc.)
- Sanitization (error messages)
- Rate limiting (token bucket)
- Audit logging

Run with:
    PYTHONPATH=src pytest src/childermass/contacts_mcp/tests/ -v
"""

import json
from unittest.mock import patch

import pytest

from childermass.contacts_mcp.security import (
    DEFAULT_PERSON_FIELDS,
    MAX_ADDRESS_LENGTH,
    MAX_GROUP_NAME_LENGTH,
    MAX_NAME_LENGTH,
    MAX_NOTES_LENGTH,
    MAX_ORGANIZATION_LENGTH,
    MAX_PHONE_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_TITLE_LENGTH,
    MAX_URL_LENGTH,
    VALID_PERSON_FIELDS,
    RateLimiter,
    SecurityError,
    audit_log,
    sanitize_error_message,
    validate_address,
    validate_birthday,
    validate_contact_name,
    validate_email,
    validate_etag,
    validate_group_name,
    validate_group_resource_name,
    validate_job_title,
    validate_max_results,
    validate_notes,
    validate_organization,
    validate_person_fields,
    validate_phone_number,
    validate_resource_name,
    validate_search_query,
    validate_url,
)


# =========================================================================
# Resource name validation
# =========================================================================


class TestValidateResourceName:
    def test_valid_resource_name(self):
        assert validate_resource_name("people/c1234567890") == "people/c1234567890"

    def test_valid_resource_name_me(self):
        assert validate_resource_name("people/me") == "people/me"

    def test_strips_whitespace(self):
        assert validate_resource_name("  people/c123  ") == "people/c123"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_resource_name("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_resource_name(None)  # type: ignore

    def test_rejects_newline_injection(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_resource_name("people/c123\nmalicious")

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_resource_name("people/c123\0")

    def test_rejects_carriage_return_embedded(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_resource_name("people/c1\r23")

    def test_rejects_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid resource name"):
            validate_resource_name("invalid/format/extra")

    def test_rejects_no_prefix(self):
        with pytest.raises(SecurityError, match="Invalid resource name"):
            validate_resource_name("c1234567890")

    def test_rejects_wrong_prefix(self):
        with pytest.raises(SecurityError, match="Invalid resource name"):
            validate_resource_name("contacts/c123")

    def test_rejects_empty_id(self):
        with pytest.raises(SecurityError, match="Invalid resource name"):
            validate_resource_name("people/")

    def test_rejects_special_chars(self):
        with pytest.raises(SecurityError, match="Invalid resource name"):
            validate_resource_name("people/c123!@#")


class TestValidateGroupResourceName:
    def test_valid_group_name(self):
        result = validate_group_resource_name("contactGroups/abc123")
        assert result == "contactGroups/abc123"

    def test_valid_with_hyphens_underscores(self):
        result = validate_group_resource_name("contactGroups/my-group_1")
        assert result == "contactGroups/my-group_1"

    def test_strips_whitespace(self):
        result = validate_group_resource_name("  contactGroups/abc  ")
        assert result == "contactGroups/abc"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_group_resource_name("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_group_resource_name(None)  # type: ignore

    def test_rejects_control_chars(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_group_resource_name("contactGroups/ab\nc")

    def test_rejects_wrong_prefix(self):
        with pytest.raises(SecurityError, match="Invalid contact group"):
            validate_group_resource_name("people/abc")

    def test_rejects_empty_id(self):
        with pytest.raises(SecurityError, match="Invalid contact group"):
            validate_group_resource_name("contactGroups/")


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


# =========================================================================
# Phone number validation
# =========================================================================


class TestValidatePhoneNumber:
    def test_valid_simple(self):
        assert validate_phone_number("123456789") == "123456789"

    def test_valid_international(self):
        assert validate_phone_number("+420 123 456 789") == "+420 123 456 789"

    def test_valid_with_parens(self):
        assert validate_phone_number("(123) 456-7890") == "(123) 456-7890"

    def test_valid_with_dots(self):
        assert validate_phone_number("123.456.7890") == "123.456.7890"

    def test_valid_with_hash(self):
        assert validate_phone_number("+1 800 555 1234 #5") == "+1 800 555 1234 #5"

    def test_strips_whitespace(self):
        assert validate_phone_number("  +420 123  ") == "+420 123"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_phone_number("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_phone_number(None)  # type: ignore

    def test_rejects_control_chars(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_phone_number("123\n456")

    def test_rejects_letters(self):
        with pytest.raises(SecurityError, match="Invalid phone"):
            validate_phone_number("abc-phone")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_phone_number("1" * (MAX_PHONE_LENGTH + 1))


# =========================================================================
# Contact name validation
# =========================================================================


class TestValidateContactName:
    def test_valid_name(self):
        assert validate_contact_name("John") == "John"

    def test_valid_with_spaces(self):
        assert validate_contact_name("John Doe") == "John Doe"

    def test_valid_unicode(self):
        assert validate_contact_name("Ondřej Lévy") == "Ondřej Lévy"

    def test_strips_whitespace(self):
        assert validate_contact_name("  John  ") == "John"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_contact_name("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_contact_name(None)  # type: ignore

    def test_rejects_only_whitespace(self):
        with pytest.raises(SecurityError, match="empty"):
            validate_contact_name("   ")

    def test_rejects_carriage_return(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_contact_name("John\rDoe")

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_contact_name("John\0")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_contact_name("A" * (MAX_NAME_LENGTH + 1))


# =========================================================================
# Notes validation
# =========================================================================


class TestValidateNotes:
    def test_valid_notes(self):
        assert validate_notes("Some notes about contact") == "Some notes about contact"

    def test_empty_returns_empty(self):
        assert validate_notes("") == ""

    def test_none_returns_empty(self):
        assert validate_notes(None) == ""  # type: ignore

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_notes("A" * (MAX_NOTES_LENGTH + 1))


# =========================================================================
# Organization validation
# =========================================================================


class TestValidateOrganization:
    def test_valid_org(self):
        assert validate_organization("Google LLC") == "Google LLC"

    def test_empty_returns_empty(self):
        assert validate_organization("") == ""

    def test_strips_whitespace(self):
        assert validate_organization("  Acme  ") == "Acme"

    def test_rejects_carriage_return(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_organization("Acme\rCorp")

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_organization("Acme\0")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_organization("A" * (MAX_ORGANIZATION_LENGTH + 1))


# =========================================================================
# Job title validation
# =========================================================================


class TestValidateJobTitle:
    def test_valid_title(self):
        assert validate_job_title("Software Engineer") == "Software Engineer"

    def test_empty_returns_empty(self):
        assert validate_job_title("") == ""

    def test_strips_whitespace(self):
        assert validate_job_title("  CEO  ") == "CEO"

    def test_rejects_carriage_return(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_job_title("CEO\rFake")

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_job_title("CEO\0")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_job_title("A" * (MAX_TITLE_LENGTH + 1))


# =========================================================================
# Address validation
# =========================================================================


class TestValidateAddress:
    def test_valid_address(self):
        assert validate_address("123 Main St") == "123 Main St"

    def test_empty_returns_empty(self):
        assert validate_address("") == ""

    def test_strips_whitespace(self):
        assert validate_address("  123 Main  ") == "123 Main"

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="null bytes"):
            validate_address("123 Main\0St")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_address("A" * (MAX_ADDRESS_LENGTH + 1))


# =========================================================================
# URL validation
# =========================================================================


class TestValidateUrl:
    def test_valid_url(self):
        assert validate_url("https://example.com") == "https://example.com"

    def test_valid_http(self):
        assert validate_url("http://example.com/page") == "http://example.com/page"

    def test_empty_returns_empty(self):
        assert validate_url("") == ""

    def test_strips_whitespace(self):
        assert validate_url("  https://example.com  ") == "https://example.com"

    def test_rejects_control_chars(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_url("https://exam\nple.com")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_url("https://example.com/" + "a" * MAX_URL_LENGTH)

    def test_rejects_invalid_url(self):
        with pytest.raises(SecurityError, match="Invalid URL"):
            validate_url("not-a-url")


# =========================================================================
# Birthday validation
# =========================================================================


class TestValidateBirthday:
    def test_valid_full_date(self):
        assert validate_birthday("1990-03-15") == "1990-03-15"

    def test_valid_without_year(self):
        assert validate_birthday("03-15") == "03-15"

    def test_strips_whitespace(self):
        assert validate_birthday("  1990-03-15  ") == "1990-03-15"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_birthday("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_birthday(None)  # type: ignore

    def test_rejects_wrong_format_slash(self):
        with pytest.raises(SecurityError, match="Invalid birthday"):
            validate_birthday("15/03/1990")

    def test_rejects_wrong_format_text(self):
        with pytest.raises(SecurityError, match="Invalid birthday"):
            validate_birthday("March 15, 1990")

    def test_rejects_invalid_single_digit(self):
        with pytest.raises(SecurityError, match="Invalid birthday"):
            validate_birthday("3-15")


# =========================================================================
# Search query validation
# =========================================================================


class TestValidateSearchQuery:
    def test_valid_query(self):
        assert validate_search_query("John") == "John"

    def test_empty_returns_empty(self):
        assert validate_search_query("") == ""

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_search_query("John\0")

    def test_rejects_escape_char(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_search_query("John\x1b")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_search_query("A" * (MAX_QUERY_LENGTH + 1))


# =========================================================================
# Person fields validation
# =========================================================================


class TestValidatePersonFields:
    def test_valid_single_field(self):
        assert validate_person_fields("names") == "names"

    def test_valid_multiple_fields(self):
        result = validate_person_fields("names,emailAddresses,phoneNumbers")
        assert result == "names,emailAddresses,phoneNumbers"

    def test_empty_returns_default(self):
        assert validate_person_fields("") == DEFAULT_PERSON_FIELDS

    def test_none_returns_default(self):
        assert validate_person_fields(None) == DEFAULT_PERSON_FIELDS  # type: ignore

    def test_strips_whitespace_from_fields(self):
        result = validate_person_fields(" names , emailAddresses ")
        assert result == "names,emailAddresses"

    def test_rejects_invalid_field(self):
        with pytest.raises(SecurityError, match="Invalid person fields"):
            validate_person_fields("names,invalidField")

    def test_rejects_all_invalid(self):
        with pytest.raises(SecurityError, match="Invalid person fields"):
            validate_person_fields("foo,bar")


# =========================================================================
# Group name validation
# =========================================================================


class TestValidateGroupName:
    def test_valid_name(self):
        assert validate_group_name("Family") == "Family"

    def test_valid_with_spaces(self):
        assert validate_group_name("Work Contacts") == "Work Contacts"

    def test_strips_whitespace(self):
        assert validate_group_name("  Friends  ") == "Friends"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_group_name("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_group_name(None)  # type: ignore

    def test_rejects_only_whitespace(self):
        with pytest.raises(SecurityError, match="empty"):
            validate_group_name("   ")

    def test_rejects_carriage_return(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_group_name("Family\rEvil")

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_group_name("Family\0")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_group_name("A" * (MAX_GROUP_NAME_LENGTH + 1))


# =========================================================================
# Max results validation
# =========================================================================


class TestValidateMaxResults:
    def test_valid_value(self):
        assert validate_max_results(10) == 10

    def test_minimum_value(self):
        assert validate_max_results(1) == 1

    def test_maximum_value(self):
        assert validate_max_results(1000) == 1000

    def test_custom_limit(self):
        assert validate_max_results(30, limit=30) == 30

    def test_rejects_zero(self):
        with pytest.raises(SecurityError, match="at least 1"):
            validate_max_results(0)

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="at least 1"):
            validate_max_results(-1)

    def test_rejects_over_limit(self):
        with pytest.raises(SecurityError, match="cannot exceed"):
            validate_max_results(1001)

    def test_rejects_custom_limit_exceeded(self):
        with pytest.raises(SecurityError, match="cannot exceed 30"):
            validate_max_results(31, limit=30)


# =========================================================================
# Etag validation
# =========================================================================


class TestValidateEtag:
    def test_valid_etag(self):
        result = validate_etag("abc123def")
        assert result == "abc123def"

    def test_strips_whitespace(self):
        assert validate_etag("  abc123  ") == "abc123"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="etag is required"):
            validate_etag("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="etag is required"):
            validate_etag(None)  # type: ignore

    def test_rejects_only_whitespace(self):
        with pytest.raises(SecurityError, match="empty"):
            validate_etag("   ")


# =========================================================================
# Error message sanitization
# =========================================================================


class TestSanitizeErrorMessage:
    def test_basic_error_passthrough(self):
        err = Exception("Something went wrong")
        assert sanitize_error_message(err) == "Something went wrong"

    def test_redacts_bearer_token(self):
        err = Exception("Auth failed: Bearer ya29.abc123xyz")
        result = sanitize_error_message(err)
        assert "ya29.abc123xyz" not in result
        assert "Bearer ***" in result

    def test_redacts_google_access_token(self):
        err = Exception("Got ya29.long_access_token_value failed")
        result = sanitize_error_message(err)
        assert "long_access_token_value" not in result
        assert "ya29.***" in result

    def test_redacts_google_refresh_token(self):
        err = Exception("Refresh 1//0abc123DEF-ghijkl expired")
        result = sanitize_error_message(err)
        assert "0abc123DEF" not in result
        assert "1//***" in result

    def test_redacts_password(self):
        err = Exception("password=secret123 was used")
        result = sanitize_error_message(err)
        assert "secret123" not in result

    def test_redacts_credential_path(self):
        err = Exception("File /users/me/secret.json not found")
        result = sanitize_error_message(err)
        assert "secret.json" not in result
        assert "credentials.json" in result

    def test_multiple_redactions(self):
        err = Exception(
            "Bearer ya29.token123 and password=secret "
            "at /home/user/creds.json"
        )
        result = sanitize_error_message(err)
        assert "ya29.token123" not in result
        assert "secret" not in result


# =========================================================================
# Rate limiting
# =========================================================================


class TestRateLimiter:
    def test_allows_first_request(self):
        limiter = RateLimiter()
        assert limiter.allow("test@example.com", "search") is True

    def test_allows_multiple_within_limit(self):
        limiter = RateLimiter()
        for _ in range(29):
            assert limiter.allow("test@example.com", "search") is True

    def test_denies_when_exhausted(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("test@example.com", "search")
        assert limiter.allow("test@example.com", "search") is False

    def test_separate_accounts(self):
        limiter = RateLimiter()
        # Exhaust account A
        for _ in range(30):
            limiter.allow("a@example.com", "search")
        # Account B should still work
        assert limiter.allow("b@example.com", "search") is True

    def test_separate_operations(self):
        limiter = RateLimiter()
        # Exhaust search
        for _ in range(30):
            limiter.allow("test@example.com", "search")
        # List should still work
        assert limiter.allow("test@example.com", "list") is True

    def test_check_raises_on_limit(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("test@example.com", "search")
        with pytest.raises(SecurityError, match="Rate limit exceeded"):
            limiter.check("test@example.com", "search")

    def test_check_passes_within_limit(self):
        limiter = RateLimiter()
        limiter.check("test@example.com", "search")  # Should not raise

    def test_tokens_refill_over_time(self):
        limiter = RateLimiter()
        # Exhaust tokens
        for _ in range(30):
            limiter.allow("test@example.com", "search")
        assert limiter.allow("test@example.com", "search") is False

        # Manually advance bucket's last_refill time to simulate passage
        key = "test@example.com:search"
        bucket = limiter._buckets[key]
        bucket.last_refill -= 10  # Simulate 10 seconds passing

        assert limiter.allow("test@example.com", "search") is True

    def test_delete_has_lower_limit(self):
        limiter = RateLimiter()
        for _ in range(10):
            limiter.allow("test@example.com", "delete")
        assert limiter.allow("test@example.com", "delete") is False

    def test_unknown_operation_uses_default(self):
        limiter = RateLimiter()
        # Unknown ops get (60, 1.0) default
        assert limiter.allow("test@example.com", "unknown_op") is True


# =========================================================================
# Audit logging
# =========================================================================


class TestAuditLog:
    def test_writes_log_entry(self, tmp_path):
        """Test that audit_log writes a valid JSON entry."""
        log_file = tmp_path / "test-audit.log"

        with patch(
            "childermass.contacts_mcp.security._AUDIT_LOG_FILE", log_file
        ), patch(
            "childermass.contacts_mcp.security._AUDIT_DIR", tmp_path
        ):
            # Force re-creation of logger by clearing handlers
            import logging

            logger = logging.getLogger("childermass.contacts_mcp.audit")
            logger.handlers.clear()

            audit_log(
                operation="search_contacts",
                account="test@example.com",
                details={"query": "John"},
                success=True,
            )

            content = log_file.read_text()
            entry = json.loads(content.strip())

            assert entry["operation"] == "search_contacts"
            assert entry["account"] == "test@example.com"
            assert entry["success"] is True
            assert entry["details"]["query"] == "John"
            assert "timestamp" in entry

    def test_logs_failure(self, tmp_path):
        log_file = tmp_path / "test-audit.log"

        with patch(
            "childermass.contacts_mcp.security._AUDIT_LOG_FILE", log_file
        ), patch(
            "childermass.contacts_mcp.security._AUDIT_DIR", tmp_path
        ):
            import logging

            logger = logging.getLogger("childermass.contacts_mcp.audit")
            logger.handlers.clear()

            audit_log(
                operation="delete_contact",
                account="test@example.com",
                success=False,
            )

            content = log_file.read_text()
            entry = json.loads(content.strip())
            assert entry["success"] is False
            assert entry["operation"] == "delete_contact"


# =========================================================================
# Constants validation
# =========================================================================


class TestConstants:
    def test_valid_person_fields_not_empty(self):
        assert len(VALID_PERSON_FIELDS) > 10

    def test_default_person_fields_all_valid(self):
        for field in DEFAULT_PERSON_FIELDS.split(","):
            assert field in VALID_PERSON_FIELDS, f"{field} not in VALID_PERSON_FIELDS"

    def test_max_lengths_positive(self):
        assert MAX_NAME_LENGTH > 0
        assert MAX_NOTES_LENGTH > 0
        assert MAX_QUERY_LENGTH > 0
        assert MAX_ADDRESS_LENGTH > 0
        assert MAX_ORGANIZATION_LENGTH > 0
        assert MAX_TITLE_LENGTH > 0
        assert MAX_URL_LENGTH > 0
        assert MAX_PHONE_LENGTH > 0
        assert MAX_GROUP_NAME_LENGTH > 0
