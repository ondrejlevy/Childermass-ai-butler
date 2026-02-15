"""
Tests for calendar_mcp security module.

Covers all validators, sanitizers, rate limiter, and audit logging.
"""

import json
import logging

import pytest

from childermass.calendar_mcp.security import (
    MAX_ATTENDEES,
    MAX_DESCRIPTION_LENGTH,
    MAX_LOCATION_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_SUMMARY_LENGTH,
    RateLimiter,
    SecurityError,
    audit_log,
    sanitize_error_message,
    validate_attendees,
    validate_calendar_id,
    validate_color_id,
    validate_date_range,
    validate_datetime,
    validate_email,
    validate_event_description,
    validate_event_id,
    validate_event_summary,
    validate_location,
    validate_max_results,
    validate_quick_add_text,
    validate_recurrence,
    validate_search_query,
    validate_send_updates,
    validate_timezone,
)


# ===========================================================================
# validate_calendar_id
# ===========================================================================


class TestValidateCalendarId:
    def test_primary(self):
        assert validate_calendar_id("primary") == "primary"

    def test_primary_case_insensitive(self):
        assert validate_calendar_id("PRIMARY") == "primary"
        assert validate_calendar_id("Primary") == "primary"

    def test_email_format(self):
        result = validate_calendar_id("user@gmail.com")
        assert result == "user@gmail.com"

    def test_group_calendar(self):
        result = validate_calendar_id(
            "company.com_abc123@group.calendar.google.com"
        )
        assert "group.calendar.google.com" in result

    def test_strips_whitespace(self):
        assert validate_calendar_id("  primary  ") == "primary"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="Calendar ID is required"):
            validate_calendar_id("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="Calendar ID is required"):
            validate_calendar_id(None)

    def test_newline_injection(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_calendar_id("user@gmail.com\ninjection")

    def test_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_calendar_id("user\0@gmail.com")

    def test_invalid_chars(self):
        with pytest.raises(SecurityError, match="Invalid calendar ID"):
            validate_calendar_id("user@gmail.com; DROP TABLE")


# ===========================================================================
# validate_event_id
# ===========================================================================


class TestValidateEventId:
    def test_valid_hex(self):
        result = validate_event_id("abc123def456")
        assert result == "abc123def456"

    def test_valid_long(self):
        event_id = "a" * 100
        assert validate_event_id(event_id) == event_id

    def test_strips_whitespace(self):
        assert validate_event_id("  abc123  ") == "abc123"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="Event ID is required"):
            validate_event_id("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="Event ID is required"):
            validate_event_id(None)

    def test_special_chars_raises(self):
        with pytest.raises(SecurityError, match="Invalid event ID"):
            validate_event_id("abc-123!@#")

    def test_too_short_raises(self):
        with pytest.raises(SecurityError, match="length must be 5-1024"):
            validate_event_id("abcd")

    def test_too_long_raises(self):
        with pytest.raises(SecurityError, match="length must be 5-1024"):
            validate_event_id("a" * 1025)

    def test_underscore_allowed(self):
        result = validate_event_id("abc_123_def")
        assert result == "abc_123_def"


# ===========================================================================
# validate_datetime
# ===========================================================================


class TestValidateDatetime:
    def test_date_only(self):
        assert validate_datetime("2024-01-15") == "2024-01-15"

    def test_datetime_utc(self):
        assert (
            validate_datetime("2024-01-15T10:00:00Z")
            == "2024-01-15T10:00:00Z"
        )

    def test_datetime_positive_offset(self):
        result = validate_datetime("2024-01-15T10:00:00+01:00")
        assert result == "2024-01-15T10:00:00+01:00"

    def test_datetime_negative_offset(self):
        result = validate_datetime("2024-01-15T10:00:00-05:00")
        assert result == "2024-01-15T10:00:00-05:00"

    def test_strips_whitespace(self):
        result = validate_datetime("  2024-01-15  ")
        assert result == "2024-01-15"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="DateTime value is required"):
            validate_datetime("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="DateTime value is required"):
            validate_datetime(None)

    def test_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid datetime format"):
            validate_datetime("January 15, 2024")

    def test_no_timezone_raises(self):
        with pytest.raises(SecurityError, match="Invalid datetime format"):
            validate_datetime("2024-01-15T10:00:00")

    def test_partial_date_raises(self):
        with pytest.raises(SecurityError, match="Invalid datetime format"):
            validate_datetime("2024-01")


# ===========================================================================
# validate_timezone
# ===========================================================================


class TestValidateTimezone:
    def test_utc(self):
        assert validate_timezone("UTC") == "UTC"

    def test_utc_lowercase(self):
        assert validate_timezone("utc") == "UTC"

    def test_europe_prague(self):
        assert validate_timezone("Europe/Prague") == "Europe/Prague"

    def test_america_new_york(self):
        assert validate_timezone("America/New_York") == "America/New_York"

    def test_etc_gmt(self):
        assert validate_timezone("Etc/GMT+1") == "Etc/GMT+1"

    def test_etc_gmt_negative(self):
        assert validate_timezone("Etc/GMT-5") == "Etc/GMT-5"

    def test_strips_whitespace(self):
        assert validate_timezone("  Europe/Prague  ") == "Europe/Prague"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="Timezone is required"):
            validate_timezone("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="Timezone is required"):
            validate_timezone(None)

    def test_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid timezone format"):
            validate_timezone("CET")

    def test_no_slash_raises(self):
        with pytest.raises(SecurityError, match="Invalid timezone format"):
            validate_timezone("Prague")


# ===========================================================================
# validate_recurrence
# ===========================================================================


class TestValidateRecurrence:
    def test_empty_list(self):
        assert validate_recurrence([]) == []

    def test_none(self):
        assert validate_recurrence(None) == []

    def test_valid_rrule(self):
        rules = ["RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=10"]
        result = validate_recurrence(rules)
        assert result == rules

    def test_valid_exdate(self):
        rules = ["EXDATE:20240115T100000Z"]
        result = validate_recurrence(rules)
        assert result == rules

    def test_valid_rdate(self):
        rules = ["RDATE:20240115T100000Z"]
        result = validate_recurrence(rules)
        assert result == rules

    def test_multiple_rules(self):
        rules = [
            "RRULE:FREQ=DAILY;COUNT=5",
            "EXDATE:20240116T100000Z",
        ]
        result = validate_recurrence(rules)
        assert len(result) == 2

    def test_invalid_prefix(self):
        with pytest.raises(SecurityError, match="Invalid recurrence rule"):
            validate_recurrence(["INVALID:SOMETHING"])

    def test_dtstart_rejected(self):
        with pytest.raises(SecurityError, match="Invalid recurrence rule"):
            validate_recurrence(["DTSTART:20240115T100000Z"])

    def test_dtend_rejected(self):
        with pytest.raises(SecurityError, match="Invalid recurrence rule"):
            validate_recurrence(["DTEND:20240115T110000Z"])

    def test_null_byte_rejected(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_recurrence(["RRULE:FREQ=DAILY\0"])

    def test_strips_empty_rules(self):
        rules = ["RRULE:FREQ=DAILY", "", "  ", "RRULE:FREQ=WEEKLY"]
        result = validate_recurrence(rules)
        assert len(result) == 2


# ===========================================================================
# validate_attendees
# ===========================================================================


class TestValidateAttendees:
    def test_empty_string(self):
        assert validate_attendees("") == []

    def test_single_email(self):
        result = validate_attendees("user@example.com")
        assert result == ["user@example.com"]

    def test_multiple_emails(self):
        result = validate_attendees("a@b.com, c@d.com, e@f.com")
        assert len(result) == 3
        assert result == ["a@b.com", "c@d.com", "e@f.com"]

    def test_invalid_email_in_list(self):
        with pytest.raises(SecurityError, match="Invalid email"):
            validate_attendees("valid@example.com, not-an-email")

    def test_too_many_attendees(self):
        emails = ", ".join(
            [f"user{i}@example.com" for i in range(MAX_ATTENDEES + 1)]
        )
        with pytest.raises(SecurityError, match="Too many attendees"):
            validate_attendees(emails)


# ===========================================================================
# validate_email
# ===========================================================================


class TestValidateEmail:
    def test_valid_email(self):
        assert validate_email("user@example.com") == "user@example.com"

    def test_name_format(self):
        result = validate_email("John Doe <john@example.com>")
        assert result == "john@example.com"

    def test_uppercase_normalised(self):
        assert validate_email("User@EXAMPLE.COM") == "user@example.com"

    def test_strips_whitespace(self):
        assert validate_email("  user@example.com  ") == "user@example.com"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="Email address is required"):
            validate_email("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="Email address is required"):
            validate_email(None)

    def test_injection_chars(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_email("not\nan\nemail")

    def test_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid email"):
            validate_email("not-an-email")


# ===========================================================================
# validate_event_summary
# ===========================================================================


class TestValidateEventSummary:
    def test_valid(self):
        assert validate_event_summary("Team Meeting") == "Team Meeting"

    def test_empty(self):
        assert validate_event_summary("") == ""

    def test_newline_raises(self):
        with pytest.raises(SecurityError, match="newline"):
            validate_event_summary("Title\nInjection")

    def test_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_event_summary("x" * (MAX_SUMMARY_LENGTH + 1))


# ===========================================================================
# validate_event_description
# ===========================================================================


class TestValidateEventDescription:
    def test_valid(self):
        assert validate_event_description("Details here") == "Details here"

    def test_empty(self):
        assert validate_event_description("") == ""

    def test_html_allowed(self):
        html = "<b>Bold</b> and <a href='x'>link</a>"
        assert validate_event_description(html) == html

    def test_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_event_description("x" * (MAX_DESCRIPTION_LENGTH + 1))


# ===========================================================================
# validate_location
# ===========================================================================


class TestValidateLocation:
    def test_valid(self):
        assert validate_location("Prague Office") == "Prague Office"

    def test_empty(self):
        assert validate_location("") == ""

    def test_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_location("x" * (MAX_LOCATION_LENGTH + 1))


# ===========================================================================
# validate_color_id
# ===========================================================================


class TestValidateColorId:
    def test_valid_ids(self):
        for i in range(1, 12):
            assert validate_color_id(str(i)) == str(i)

    def test_empty(self):
        assert validate_color_id("") == ""

    def test_invalid_zero(self):
        with pytest.raises(SecurityError, match="Invalid color ID"):
            validate_color_id("0")

    def test_invalid_twelve(self):
        with pytest.raises(SecurityError, match="Invalid color ID"):
            validate_color_id("12")

    def test_invalid_text(self):
        with pytest.raises(SecurityError, match="Invalid color ID"):
            validate_color_id("red")


# ===========================================================================
# validate_date_range
# ===========================================================================


class TestValidateDateRange:
    def test_valid_range(self):
        t_min, t_max = validate_date_range(
            "2024-01-15T00:00:00Z", "2024-01-31T23:59:59Z"
        )
        assert t_min == "2024-01-15T00:00:00Z"
        assert t_max == "2024-01-31T23:59:59Z"

    def test_date_only_range(self):
        t_min, t_max = validate_date_range("2024-01-15", "2024-01-31")
        assert t_min == "2024-01-15"
        assert t_max == "2024-01-31"

    def test_invalid_min_raises(self):
        with pytest.raises(SecurityError):
            validate_date_range("invalid", "2024-01-31T23:59:59Z")

    def test_invalid_max_raises(self):
        with pytest.raises(SecurityError):
            validate_date_range("2024-01-15T00:00:00Z", "invalid")


# ===========================================================================
# validate_search_query
# ===========================================================================


class TestValidateSearchQuery:
    def test_valid(self):
        assert validate_search_query("team meeting") == "team meeting"

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
# validate_max_results
# ===========================================================================


class TestValidateMaxResults:
    def test_valid(self):
        assert validate_max_results(50) == 50

    def test_one(self):
        assert validate_max_results(1) == 1

    def test_max(self):
        assert validate_max_results(2500) == 2500

    def test_zero_raises(self):
        with pytest.raises(SecurityError, match="at least 1"):
            validate_max_results(0)

    def test_negative_raises(self):
        with pytest.raises(SecurityError, match="at least 1"):
            validate_max_results(-1)

    def test_too_large_raises(self):
        with pytest.raises(SecurityError, match="cannot exceed 2500"):
            validate_max_results(2501)


# ===========================================================================
# validate_send_updates
# ===========================================================================


class TestValidateSendUpdates:
    def test_all(self):
        assert validate_send_updates("all") == "all"

    def test_external_only(self):
        assert validate_send_updates("externalOnly") == "externalOnly"

    def test_none(self):
        assert validate_send_updates("none") == "none"

    def test_invalid(self):
        with pytest.raises(SecurityError, match="Invalid sendUpdates"):
            validate_send_updates("invalid")


# ===========================================================================
# validate_quick_add_text
# ===========================================================================


class TestValidateQuickAddText:
    def test_valid(self):
        result = validate_quick_add_text("Meeting tomorrow at 3pm")
        assert result == "Meeting tomorrow at 3pm"

    def test_strips_whitespace(self):
        result = validate_quick_add_text("  Meeting  ")
        assert result == "Meeting"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="required"):
            validate_quick_add_text("")

    def test_none_raises(self):
        with pytest.raises(SecurityError, match="required"):
            validate_quick_add_text(None)

    def test_whitespace_only_raises(self):
        with pytest.raises(SecurityError, match="cannot be empty"):
            validate_quick_add_text("   ")

    def test_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_quick_add_text("x" * (MAX_SUMMARY_LENGTH + 1))

    def test_control_chars_rejected(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_quick_add_text("Meeting\x00tomorrow")


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
        err = Exception("Event not found")
        result = sanitize_error_message(err)
        assert result == "Event not found"


# ===========================================================================
# RateLimiter
# ===========================================================================


class TestRateLimiter:
    def test_within_limit(self):
        limiter = RateLimiter()
        for _ in range(19):
            assert limiter.allow("test@gmail.com", "create") is True

    def test_over_limit(self):
        limiter = RateLimiter()
        for _ in range(20):
            limiter.allow("test@gmail.com", "create")
        assert limiter.allow("test@gmail.com", "create") is False

    def test_refill(self):
        limiter = RateLimiter()
        for _ in range(20):
            limiter.allow("test@gmail.com", "create")
        assert limiter.allow("test@gmail.com", "create") is False

        # Manually advance bucket time
        key = limiter._key("test@gmail.com", "create")
        bucket = limiter._buckets[key]
        bucket.last_refill -= 60  # Back 60 seconds

        assert limiter.allow("test@gmail.com", "create") is True

    def test_per_account_isolation(self):
        limiter = RateLimiter()
        for _ in range(20):
            limiter.allow("account1@gmail.com", "create")

        # Different account should not be affected
        assert limiter.allow("account2@gmail.com", "create") is True

    def test_per_operation_isolation(self):
        limiter = RateLimiter()
        for _ in range(20):
            limiter.allow("test@gmail.com", "create")

        # Different operation should not be affected
        assert limiter.allow("test@gmail.com", "list_events") is True

    def test_check_raises(self):
        limiter = RateLimiter()
        for _ in range(20):
            limiter.allow("test@gmail.com", "create")

        with pytest.raises(SecurityError, match="Rate limit exceeded"):
            limiter.check("test@gmail.com", "create")


# ===========================================================================
# Audit Logging
# ===========================================================================


class TestAuditLog:
    def test_audit_entry_json(self, tmp_path, monkeypatch):
        log_file = tmp_path / "test-audit.log"
        monkeypatch.setattr(
            "childermass.calendar_mcp.security._AUDIT_LOG_FILE", log_file
        )
        monkeypatch.setattr(
            "childermass.calendar_mcp.security._AUDIT_DIR", tmp_path
        )

        # Clear any cached logger handlers
        logger = logging.getLogger("childermass.calendar_mcp.audit")
        logger.handlers.clear()

        audit_log(
            operation="create_event",
            account="test@gmail.com",
            details={"event_id": "abc123", "summary": "Test"},
            success=True,
        )

        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["operation"] == "create_event"
        assert entry["account"] == "test@gmail.com"
        assert entry["success"] is True
        assert entry["details"]["event_id"] == "abc123"

    def test_audit_failure_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "test-audit.log"
        monkeypatch.setattr(
            "childermass.calendar_mcp.security._AUDIT_LOG_FILE", log_file
        )
        monkeypatch.setattr(
            "childermass.calendar_mcp.security._AUDIT_DIR", tmp_path
        )

        logger = logging.getLogger("childermass.calendar_mcp.audit")
        logger.handlers.clear()

        audit_log(
            operation="delete_event",
            account="test@gmail.com",
            success=False,
        )

        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["operation"] == "delete_event"
        assert entry["success"] is False


# ===========================================================================
# Auth module basic checks
# ===========================================================================


class TestAuthBasics:
    def test_keyring_service_name(self):
        from childermass.calendar_mcp.auth import KEYRING_SERVICE

        assert KEYRING_SERVICE == "childermass-calendar-mcp"
        # Must differ from Gmail
        assert KEYRING_SERVICE != "childermass-gmail-mcp"

    def test_credentials_path(self):
        from childermass.calendar_mcp.auth import DEFAULT_CREDENTIALS_PATH

        assert "calendar-credentials.json" in str(DEFAULT_CREDENTIALS_PATH)
        # Must differ from Gmail
        assert "gmail-credentials.json" not in str(DEFAULT_CREDENTIALS_PATH)

    def test_token_path(self):
        from childermass.calendar_mcp.auth import get_token_path

        path = get_token_path("user@gmail.com")
        assert "calendar-tokens-user@gmail.com.json" in str(path)

    def test_scopes(self):
        from childermass.calendar_mcp.auth import SCOPES

        assert any("calendar" in s for s in SCOPES)
        assert not any("gmail" in s for s in SCOPES)


# ===========================================================================
# Client validation integration
# ===========================================================================


class TestClientValidation:
    """Test that client functions properly validate inputs."""

    def test_create_event_validates_summary(self):
        """Event summary with newlines should be rejected."""
        with pytest.raises(SecurityError, match="newline"):
            from childermass.calendar_mcp.client import create_event

            create_event(
                summary="Bad\nTitle",
                start="2024-01-15T10:00:00Z",
                end="2024-01-15T11:00:00Z",
            )

    def test_create_event_validates_datetime(self):
        """Invalid datetime should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.calendar_mcp.client import create_event

            create_event(
                summary="Test",
                start="not-a-date",
                end="2024-01-15T11:00:00Z",
            )

    def test_get_event_validates_event_id(self):
        """Invalid event ID should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.calendar_mcp.client import get_event

            get_event(calendar_id="primary", event_id="ab")  # too short

    def test_delete_event_validates_send_updates(self):
        """Invalid sendUpdates value should be rejected."""
        with pytest.raises(SecurityError, match="Invalid sendUpdates"):
            from childermass.calendar_mcp.client import delete_event

            delete_event(
                calendar_id="primary",
                event_id="abcde12345",
                send_updates="invalid",
            )

    def test_quick_add_validates_text(self):
        """Empty quick-add text should be rejected."""
        with pytest.raises(SecurityError, match="required"):
            from childermass.calendar_mcp.client import quick_add_event

            quick_add_event(text="")

    def test_move_event_validates_calendar_ids(self):
        """Invalid calendar IDs should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.calendar_mcp.client import move_event

            move_event(
                calendar_id="",
                event_id="abcde12345",
                destination_calendar_id="primary",
            )

    def test_update_event_validates_event_id(self):
        """Invalid event ID should be rejected before API call."""
        with pytest.raises(SecurityError):
            from childermass.calendar_mcp.client import update_event

            update_event(
                calendar_id="primary",
                event_id="ab",  # too short
            )

    def test_list_events_validates_calendar_id(self):
        """Control chars in calendar ID should be rejected."""
        with pytest.raises(SecurityError, match="control characters"):
            from childermass.calendar_mcp.client import list_events

            list_events(calendar_id="primary\ninject")

    def test_list_recurring_validates_event_id(self):
        """Invalid event ID should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.calendar_mcp.client import list_recurring_instances

            list_recurring_instances(
                calendar_id="primary", event_id="ab"
            )

    def test_query_freebusy_validates_datetime(self):
        """Invalid datetime should be rejected."""
        with pytest.raises(SecurityError):
            from childermass.calendar_mcp.client import query_free_busy

            query_free_busy(
                calendar_ids=["primary"],
                time_min="invalid",
                time_max="2024-01-31T23:59:59Z",
            )
