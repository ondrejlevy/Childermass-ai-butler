"""
Comprehensive test suite for Childermass Tracking MCP security layer.

Tests cover:
- Input validation (URLs, tracking numbers, carriers, statuses, etc.)
- Error message sanitization
- Rate limiting (token bucket)
- Audit logging

Run with:
    pytest src/childermass/tracking_mcp/tests/test_security.py -v
"""

import json

import pytest

from childermass.tracking_mcp.security import (
    ALLOWED_CARRIERS,
    ALLOWED_STATUSES,
    MAX_EMAIL_BODY_LENGTH,
    MAX_METADATA_LENGTH,
    MAX_ORDER_NUMBER_LENGTH,
    MAX_TRACKING_NUMBER_LENGTH,
    MAX_URL_LENGTH,
    RateLimiter,
    SecurityError,
    audit_log,
    sanitize_error_message,
    validate_carrier,
    validate_email_body,
    validate_email_from,
    validate_email_subject,
    validate_metadata,
    validate_order_number,
    validate_shipment_id,
    validate_status,
    validate_tracking_number,
    validate_url,
)


# =========================================================================
# URL Validation
# =========================================================================


class TestValidateUrl:
    def test_valid_https(self):
        assert (
            validate_url("https://tracking.zasilkovna.cz/Z1234")
            == "https://tracking.zasilkovna.cz/Z1234"
        )

    def test_valid_http(self):
        assert (
            validate_url("http://www.ppl.cz/vyhledat-zasilku?id=123")
            == "http://www.ppl.cz/vyhledat-zasilku?id=123"
        )

    def test_strips_whitespace(self):
        assert validate_url("  https://example.com  ") == "https://example.com"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_url("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_url(None)

    def test_rejects_no_scheme(self):
        with pytest.raises(SecurityError, match="http"):
            validate_url("tracking.zasilkovna.cz/Z1234")

    def test_rejects_ftp_scheme(self):
        with pytest.raises(SecurityError, match="http"):
            validate_url("ftp://tracking.zasilkovna.cz")

    def test_rejects_newline(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_url("https://example.com\n/evil")

    def test_rejects_carriage_return(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_url("https://example.com\r/evil")

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_url("https://example.com\0")

    def test_rejects_tab(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_url("https://example.com\t/evil")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_url("https://example.com/" + "x" * MAX_URL_LENGTH)

    def test_custom_field_name(self):
        with pytest.raises(SecurityError, match="Tracking URL"):
            validate_url("", field_name="Tracking URL")


# =========================================================================
# Tracking Number Validation
# =========================================================================


class TestValidateTrackingNumber:
    def test_valid_zasilkovna(self):
        assert validate_tracking_number("Z1234567890") == "Z1234567890"

    def test_valid_ppl(self):
        assert validate_tracking_number("12345678901") == "12345678901"

    def test_valid_with_hyphens(self):
        assert validate_tracking_number("ABC-123-DEF") == "ABC-123-DEF"

    def test_strips_whitespace(self):
        assert validate_tracking_number("  Z1234  ") == "Z1234"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_tracking_number("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_tracking_number(None)

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_tracking_number("A" * (MAX_TRACKING_NUMBER_LENGTH + 1))

    def test_rejects_special_chars(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_tracking_number("Z1234@#$%")

    def test_rejects_sql_injection(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_tracking_number("Z1234'; DROP TABLE--")


# =========================================================================
# Order Number Validation
# =========================================================================


class TestValidateOrderNumber:
    def test_valid_order(self):
        assert validate_order_number("OBJ-123456") == "OBJ-123456"

    def test_valid_with_dots(self):
        assert validate_order_number("ORD.2025.001") == "ORD.2025.001"

    def test_valid_with_underscore(self):
        assert validate_order_number("order_123") == "order_123"

    def test_strips_whitespace(self):
        assert validate_order_number("  OBJ-123  ") == "OBJ-123"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_order_number("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_order_number(None)

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_order_number("A" * (MAX_ORDER_NUMBER_LENGTH + 1))

    def test_rejects_special_chars(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_order_number("OBJ@123/456")


# =========================================================================
# Carrier Validation
# =========================================================================


class TestValidateCarrier:
    @pytest.mark.parametrize("carrier", sorted(ALLOWED_CARRIERS))
    def test_valid_carriers(self, carrier):
        assert validate_carrier(carrier) == carrier

    def test_normalizes_case(self):
        assert validate_carrier("ZASILKOVNA") == "zasilkovna"
        assert validate_carrier("PPL") == "ppl"

    def test_strips_whitespace(self):
        assert validate_carrier("  dpd  ") == "dpd"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_carrier("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_carrier(None)

    def test_rejects_unknown_carrier(self):
        with pytest.raises(SecurityError, match="Unknown carrier"):
            validate_carrier("fedex")


# =========================================================================
# Status Validation
# =========================================================================


class TestValidateStatus:
    @pytest.mark.parametrize("status", sorted(ALLOWED_STATUSES))
    def test_valid_statuses(self, status):
        assert validate_status(status) == status

    def test_normalizes_case(self):
        assert validate_status("IN_TRANSIT") == "in_transit"
        assert validate_status("DELIVERED") == "delivered"

    def test_strips_whitespace(self):
        assert validate_status("  delivered  ") == "delivered"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_status("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_status(None)

    def test_rejects_unknown_status(self):
        with pytest.raises(SecurityError, match="Unknown status"):
            validate_status("lost")


# =========================================================================
# Shipment ID Validation
# =========================================================================


class TestValidateShipmentId:
    def test_valid_uuid(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_shipment_id(uuid) == uuid

    def test_normalizes_to_lowercase(self):
        uuid = "550E8400-E29B-41D4-A716-446655440000"
        assert validate_shipment_id(uuid) == uuid.lower()

    def test_strips_whitespace(self):
        uuid = "  550e8400-e29b-41d4-a716-446655440000  "
        assert validate_shipment_id(uuid) == "550e8400-e29b-41d4-a716-446655440000"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_shipment_id("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_shipment_id(None)

    def test_rejects_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid shipment ID"):
            validate_shipment_id("not-a-uuid")

    def test_rejects_path_traversal(self):
        with pytest.raises(SecurityError, match="Invalid shipment ID"):
            validate_shipment_id("../../../etc/passwd")


# =========================================================================
# Email Body Validation
# =========================================================================


class TestValidateEmailBody:
    def test_valid_body(self):
        assert validate_email_body("Your shipment has been sent") == "Your shipment has been sent"

    def test_none_returns_empty(self):
        assert validate_email_body(None) == ""

    def test_empty_returns_empty(self):
        assert validate_email_body("") == ""

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_email_body("x" * (MAX_EMAIL_BODY_LENGTH + 1))


# =========================================================================
# Email Subject Validation
# =========================================================================


class TestValidateEmailSubject:
    def test_valid_subject(self):
        assert validate_email_subject("Zásilka odeslána") == "Zásilka odeslána"

    def test_none_returns_empty(self):
        assert validate_email_subject(None) == ""

    def test_empty_returns_empty(self):
        assert validate_email_subject("") == ""

    def test_rejects_newline(self):
        with pytest.raises(SecurityError, match="newline"):
            validate_email_subject("Subject\nBcc: evil@attacker.com")

    def test_rejects_carriage_return(self):
        with pytest.raises(SecurityError, match="newline"):
            validate_email_subject("Subject\rEvil")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_email_subject("x" * 999)


# =========================================================================
# Email From Validation
# =========================================================================


class TestValidateEmailFrom:
    def test_valid_address(self):
        assert validate_email_from("info@zasilkovna.cz") == "info@zasilkovna.cz"

    def test_strips_whitespace(self):
        assert validate_email_from("  info@ppl.cz  ") == "info@ppl.cz"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_email_from("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_email_from(None)

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_email_from("a" * 501)

    def test_rejects_newline(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_email_from("info@ppl.cz\nBcc: evil@attacker.com")

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_email_from("info@ppl.cz\0")


# =========================================================================
# Metadata Validation
# =========================================================================


class TestValidateMetadata:
    def test_valid_json(self):
        result = validate_metadata('{"items": ["phone case"]}')
        assert '"items"' in result

    def test_none_returns_empty_object(self):
        assert validate_metadata(None) == "{}"

    def test_empty_returns_empty_object(self):
        assert validate_metadata("") == "{}"

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_metadata("x" * (MAX_METADATA_LENGTH + 1))

    def test_rejects_invalid_json(self):
        with pytest.raises(SecurityError, match="Invalid JSON"):
            validate_metadata("not valid json {{{")


# =========================================================================
# Error Sanitization
# =========================================================================


class TestSanitizeErrorMessage:
    def test_removes_bearer_token(self):
        msg = sanitize_error_message(Exception("Bearer ya29.abc123xyz"))
        assert "ya29.abc123xyz" not in msg

    def test_removes_password(self):
        msg = sanitize_error_message(Exception("password: supersecret123"))
        assert "supersecret123" not in msg

    def test_removes_file_paths(self):
        msg = sanitize_error_message(Exception("Error in /Users/user/.childermass/tracking.db"))
        assert "/Users/" not in msg

    def test_removes_ip_addresses(self):
        msg = sanitize_error_message(Exception("Connection to 192.168.1.1:8080 refused"))
        assert "192.168.1.1" not in msg

    def test_preserves_safe_messages(self):
        msg = sanitize_error_message(Exception("Connection timed out"))
        assert msg == "Connection timed out"

    def test_truncates_long_messages(self):
        msg = sanitize_error_message(Exception("x" * 1000))
        assert len(msg) <= 500


# =========================================================================
# Rate Limiting
# =========================================================================


class TestRateLimiter:
    def test_allows_within_limit(self):
        rl = RateLimiter()
        for _ in range(5):
            assert rl.allow("batch") is True

    def test_rejects_over_limit(self):
        rl = RateLimiter()
        # batch has capacity=5
        for _ in range(5):
            assert rl.allow("batch") is True
        assert rl.allow("batch") is False

    def test_refills_over_time(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.allow("batch")

        # Simulate time passing by adjusting last_refill
        bucket = rl._buckets["batch"]
        bucket.last_refill -= 120  # Go back 2 minutes

        assert rl.allow("batch") is True

    def test_different_operations_independent(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.allow("batch")
        # batch is exhausted, but read should work
        assert rl.allow("read") is True

    def test_check_raises_on_limit(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.allow("batch")

        with pytest.raises(SecurityError, match="Rate limit"):
            rl.check("batch")

    def test_check_passes_within_limit(self):
        rl = RateLimiter()
        # Should not raise
        rl.check("scrape")

    def test_default_limit_for_unknown_op(self):
        rl = RateLimiter()
        # Unknown operations get default (60, 1.0)
        assert rl.allow("completely_unknown_operation") is True

    def test_all_known_operations(self):
        rl = RateLimiter()
        for op in ("scrape", "register", "read", "parse", "batch", "archive"):
            assert rl.allow(op) is True


# =========================================================================
# Audit Logging
# =========================================================================


class TestAuditLog:
    def test_writes_json_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "audit.log"
        import childermass.tracking_mcp.security as sec

        monkeypatch.setattr(sec, "_AUDIT_LOG_FILE", log_file)
        monkeypatch.setattr(sec, "_AUDIT_DIR", tmp_path)

        import logging

        logger = logging.getLogger("childermass.tracking_mcp.audit")
        logger.handlers.clear()

        audit_log("register_shipment", details={"shipment_id": "test-123"})

        for h in logger.handlers:
            h.flush()

        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["operation"] == "register_shipment"
        assert entry["success"] is True
        assert entry["details"]["shipment_id"] == "test-123"

    def test_failure_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "audit.log"
        import childermass.tracking_mcp.security as sec

        monkeypatch.setattr(sec, "_AUDIT_LOG_FILE", log_file)
        monkeypatch.setattr(sec, "_AUDIT_DIR", tmp_path)

        import logging

        logger = logging.getLogger("childermass.tracking_mcp.audit")
        logger.handlers.clear()

        audit_log("scrape_status", success=False)

        for h in logger.handlers:
            h.flush()

        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["success"] is False
        assert entry["operation"] == "scrape_status"
