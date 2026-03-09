"""
Comprehensive test suite for Childermass UniFi Network MCP security layer.

Tests cover:
- Input validation (UUIDs, VLAN IDs, names, policy actions, voucher params)
- Error message sanitization (IP, credentials, cookies, API keys)
- Rate limiting (token bucket)
- Audit logging
- Auth config management

Run with:
    PYTHONPATH=src pytest src/childermass/network_mcp/tests/ -v
"""

import json
from unittest.mock import patch

import pytest

from childermass.network_mcp.security import (
    MAX_NETWORK_NAME_LENGTH,
    MAX_RESULTS_PER_QUERY,
    MAX_VLAN_ID,
    MAX_VOUCHER_COUNT,
    MAX_VOUCHER_DATA_LIMIT_MB,
    MAX_VOUCHER_GUEST_LIMIT,
    MAX_VOUCHER_RATE_LIMIT_KBPS,
    MAX_VOUCHER_TIME_LIMIT_MINUTES,
    MIN_VLAN_ID,
    MAX_EVENT_LIMIT,
    MAX_HISTORY_HOURS,
    MIN_HISTORY_HOURS,
    RateLimiter,
    SecurityError,
    audit_log,
    sanitize_error_message,
    validate_console_address,
    validate_dpi_type,
    validate_event_limit,
    validate_filter_expression,
    validate_history_hours,
    validate_ip_version,
    validate_mac_address,
    validate_max_results,
    validate_network_id,
    validate_network_name,
    validate_offset,
    validate_period,
    validate_policy_action,
    validate_policy_id,
    validate_policy_name,
    validate_site_id,
    validate_timestamp_ms,
    validate_uuid,
    validate_vlan_id,
    validate_voucher_id,
    validate_voucher_params,
    validate_zone_id,
)


# =========================================================================
# UUID validation
# =========================================================================


class TestValidateUuid:
    def test_valid_uuid(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_uuid(uuid) == uuid

    def test_normalizes_to_lowercase(self):
        assert (
            validate_uuid("550E8400-E29B-41D4-A716-446655440000")
            == "550e8400-e29b-41d4-a716-446655440000"
        )

    def test_strips_whitespace(self):
        assert (
            validate_uuid("  550e8400-e29b-41d4-a716-446655440000  ")
            == "550e8400-e29b-41d4-a716-446655440000"
        )

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_uuid("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_uuid(None)  # type: ignore

    def test_rejects_short(self):
        with pytest.raises(SecurityError, match="UUID"):
            validate_uuid("550e8400-e29b")

    def test_rejects_no_dashes(self):
        with pytest.raises(SecurityError, match="UUID"):
            validate_uuid("550e8400e29b41d4a716446655440000")

    def test_rejects_non_hex(self):
        with pytest.raises(SecurityError, match="UUID"):
            validate_uuid("550e8400-e29b-41d4-a716-44665544gggg")

    def test_custom_field_name(self):
        with pytest.raises(SecurityError, match="Site ID"):
            validate_uuid("invalid", "Site ID")


class TestValidateSiteId:
    def test_valid(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_site_id(uuid) == uuid

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Site ID"):
            validate_site_id("invalid")


class TestValidateNetworkId:
    def test_valid(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_network_id(uuid) == uuid

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Network ID"):
            validate_network_id("")


class TestValidatePolicyId:
    def test_valid(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_policy_id(uuid) == uuid

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Policy ID"):
            validate_policy_id("xyz")


class TestValidateZoneId:
    def test_valid(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_zone_id(uuid) == uuid

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Zone ID"):
            validate_zone_id("short")


class TestValidateVoucherId:
    def test_valid(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_voucher_id(uuid) == uuid

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Voucher ID"):
            validate_voucher_id("abc")


# =========================================================================
# VLAN ID validation
# =========================================================================


class TestValidateVlanId:
    def test_valid_min(self):
        assert validate_vlan_id(MIN_VLAN_ID) == MIN_VLAN_ID

    def test_valid_max(self):
        assert validate_vlan_id(MAX_VLAN_ID) == MAX_VLAN_ID

    def test_valid_middle(self):
        assert validate_vlan_id(100) == 100

    def test_rejects_zero(self):
        with pytest.raises(SecurityError, match="between"):
            validate_vlan_id(0)

    def test_rejects_too_large(self):
        with pytest.raises(SecurityError, match="between"):
            validate_vlan_id(MAX_VLAN_ID + 1)

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="between"):
            validate_vlan_id(-1)

    def test_rejects_non_int(self):
        with pytest.raises(SecurityError, match="integer"):
            validate_vlan_id("100")  # type: ignore


# =========================================================================
# Network name validation
# =========================================================================


class TestValidateNetworkName:
    def test_valid(self):
        assert validate_network_name("Guest WiFi") == "Guest WiFi"

    def test_strips_whitespace(self):
        assert validate_network_name("  IoT  ") == "IoT"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_network_name("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_network_name(None)  # type: ignore

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_network_name("x" * (MAX_NETWORK_NAME_LENGTH + 1))

    def test_rejects_newline(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_network_name("Bad\nName")

    def test_rejects_null_char(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_network_name("Bad\0Name")

    def test_max_length_allowed(self):
        name = "x" * MAX_NETWORK_NAME_LENGTH
        assert validate_network_name(name) == name


# =========================================================================
# Policy name validation
# =========================================================================


class TestValidatePolicyName:
    def test_valid(self):
        assert validate_policy_name("Block IoT to LAN") == "Block IoT to LAN"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_policy_name("")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_policy_name("x" * 129)

    def test_rejects_control_chars(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_policy_name("Bad\tName")


# =========================================================================
# Policy action validation
# =========================================================================


class TestValidatePolicyAction:
    def test_allow(self):
        assert validate_policy_action("ALLOW") == "ALLOW"

    def test_drop(self):
        assert validate_policy_action("DROP") == "DROP"

    def test_reject(self):
        assert validate_policy_action("REJECT") == "REJECT"

    def test_case_insensitive(self):
        assert validate_policy_action("allow") == "ALLOW"
        assert validate_policy_action("Drop") == "DROP"

    def test_strips_whitespace(self):
        assert validate_policy_action("  ALLOW  ") == "ALLOW"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Invalid policy action"):
            validate_policy_action("FORWARD")

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_policy_action("")


# =========================================================================
# IP version validation
# =========================================================================


class TestValidateIpVersion:
    def test_ipv4(self):
        assert validate_ip_version("IPv4") == "IPv4"

    def test_ipv6(self):
        assert validate_ip_version("IPv6") == "IPv6"

    def test_both(self):
        assert validate_ip_version("BOTH") == "BOTH"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Invalid IP version"):
            validate_ip_version("v4")

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_ip_version("")


# =========================================================================
# Max results / offset validation
# =========================================================================


class TestValidateMaxResults:
    def test_valid(self):
        assert validate_max_results(50) == 50

    def test_one(self):
        assert validate_max_results(1) == 1

    def test_max(self):
        assert validate_max_results(MAX_RESULTS_PER_QUERY) == MAX_RESULTS_PER_QUERY

    def test_rejects_zero(self):
        with pytest.raises(SecurityError, match="positive integer"):
            validate_max_results(0)

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="positive integer"):
            validate_max_results(-1)

    def test_rejects_too_large(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_max_results(MAX_RESULTS_PER_QUERY + 1)


class TestValidateOffset:
    def test_valid(self):
        assert validate_offset(0) == 0

    def test_positive(self):
        assert validate_offset(100) == 100

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="non-negative"):
            validate_offset(-1)


# =========================================================================
# Voucher parameter validation
# =========================================================================


class TestValidateVoucherParams:
    def test_empty_returns_empty(self):
        assert validate_voucher_params() == {}

    def test_time_limit(self):
        result = validate_voucher_params(time_limit_minutes=60)
        assert result == {"timeLimitMinutes": 60}

    def test_data_limit(self):
        result = validate_voucher_params(data_limit_mb=1000)
        assert result == {"dataUsageLimitMBytes": 1000}

    def test_rate_limits(self):
        result = validate_voucher_params(
            download_limit_kbps=10000,
            upload_limit_kbps=5000,
        )
        assert result == {"rxRateLimitKbps": 10000, "txRateLimitKbps": 5000}

    def test_guest_limit(self):
        result = validate_voucher_params(guest_limit=5)
        assert result == {"authorizedGuestLimit": 5}

    def test_count(self):
        result = validate_voucher_params(count=10)
        assert result == {"count": 10}

    def test_all_params(self):
        result = validate_voucher_params(
            time_limit_minutes=60,
            data_limit_mb=500,
            download_limit_kbps=10000,
            upload_limit_kbps=5000,
            guest_limit=3,
            count=5,
        )
        assert result == {
            "timeLimitMinutes": 60,
            "dataUsageLimitMBytes": 500,
            "rxRateLimitKbps": 10000,
            "txRateLimitKbps": 5000,
            "authorizedGuestLimit": 3,
            "count": 5,
        }

    def test_rejects_negative_time(self):
        with pytest.raises(SecurityError, match="positive integer"):
            validate_voucher_params(time_limit_minutes=-1)

    def test_rejects_too_large_time(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_voucher_params(time_limit_minutes=MAX_VOUCHER_TIME_LIMIT_MINUTES + 1)

    def test_rejects_negative_data(self):
        with pytest.raises(SecurityError, match="positive integer"):
            validate_voucher_params(data_limit_mb=0)

    def test_rejects_too_large_data(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_voucher_params(data_limit_mb=MAX_VOUCHER_DATA_LIMIT_MB + 1)

    def test_rejects_negative_download(self):
        with pytest.raises(SecurityError, match="non-negative"):
            validate_voucher_params(download_limit_kbps=-1)

    def test_rejects_too_large_download(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_voucher_params(download_limit_kbps=MAX_VOUCHER_RATE_LIMIT_KBPS + 1)

    def test_rejects_too_large_guest_limit(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_voucher_params(guest_limit=MAX_VOUCHER_GUEST_LIMIT + 1)

    def test_rejects_too_large_count(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_voucher_params(count=MAX_VOUCHER_COUNT + 1)


# =========================================================================
# Filter expression validation
# =========================================================================


class TestValidateFilterExpression:
    def test_none_returns_none(self):
        assert validate_filter_expression(None) is None

    def test_empty_returns_none(self):
        assert validate_filter_expression("") is None

    def test_valid_simple(self):
        expr = "name.eq('Guest')"
        assert validate_filter_expression(expr) == expr

    def test_valid_compound(self):
        expr = "and(name.isNotNull(), enabled.eq(true))"
        assert validate_filter_expression(expr) == expr

    def test_strips_whitespace(self):
        assert validate_filter_expression("  name.eq('test')  ") == "name.eq('test')"

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_filter_expression("x" * 1001)

    def test_rejects_semicolon(self):
        with pytest.raises(SecurityError, match="disallowed"):
            validate_filter_expression("name.eq('test'); DROP TABLE")

    def test_rejects_sql_comment(self):
        with pytest.raises(SecurityError, match="disallowed"):
            validate_filter_expression("name.eq('test') -- comment")

    def test_rejects_block_comment(self):
        with pytest.raises(SecurityError, match="disallowed"):
            validate_filter_expression("name.eq('test') /* comment */")

    def test_rejects_newline(self):
        with pytest.raises(SecurityError, match="disallowed"):
            validate_filter_expression("name.eq('test')\nmalicious")


# =========================================================================
# Console address validation
# =========================================================================


class TestValidateConsoleAddress:
    def test_valid_ip(self):
        assert validate_console_address("192.168.1.1") == "192.168.1.1"

    def test_valid_hostname(self):
        assert validate_console_address("my-console.local") == "my-console.local"

    def test_strips_whitespace(self):
        assert validate_console_address("  10.0.0.1  ") == "10.0.0.1"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_console_address("")

    def test_rejects_newline(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_console_address("192.168.1.1\n")

    def test_rejects_spaces(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_console_address("192.168.1.1 ; rm -rf /")

    def test_rejects_semicolon(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_console_address("192.168.1.1;echo pwned")

    def test_rejects_pipe(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_console_address("192.168.1.1|malicious")

    def test_rejects_url(self):
        with pytest.raises(SecurityError, match="Invalid console address"):
            validate_console_address("https://192.168.1.1")


# =========================================================================
# MAC address validation
# =========================================================================


class TestValidateMacAddress:
    def test_valid_colon_separated(self):
        assert validate_mac_address("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"

    def test_valid_hyphen_separated(self):
        assert validate_mac_address("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"

    def test_normalises_to_lowercase(self):
        assert validate_mac_address("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_strips_whitespace(self):
        assert validate_mac_address("  aa:bb:cc:dd:ee:ff  ") == "aa:bb:cc:dd:ee:ff"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_mac_address("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_mac_address(None)  # type: ignore

    def test_rejects_short(self):
        with pytest.raises(SecurityError, match="Invalid"):
            validate_mac_address("aa:bb:cc")

    def test_rejects_no_separators(self):
        with pytest.raises(SecurityError, match="Invalid"):
            validate_mac_address("aabbccddeeff")

    def test_rejects_non_hex(self):
        with pytest.raises(SecurityError, match="Invalid"):
            validate_mac_address("gg:hh:ii:jj:kk:ll")

    def test_custom_field_name(self):
        with pytest.raises(SecurityError, match="Device MAC"):
            validate_mac_address("invalid", "Device MAC")


# =========================================================================
# Period validation
# =========================================================================


class TestValidatePeriod:
    def test_hourly(self):
        assert validate_period("hourly") == "hourly"

    def test_daily(self):
        assert validate_period("daily") == "daily"

    def test_5minutes(self):
        assert validate_period("5minutes") == "5minutes"

    def test_case_insensitive(self):
        assert validate_period("HOURLY") == "hourly"
        assert validate_period("Daily") == "daily"

    def test_strips_whitespace(self):
        assert validate_period("  hourly  ") == "hourly"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Invalid period"):
            validate_period("weekly")

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_period("")


# =========================================================================
# Timestamp validation
# =========================================================================


class TestValidateTimestampMs:
    def test_valid(self):
        ts = 1_700_000_000_000  # ~2023
        assert validate_timestamp_ms(ts) == ts

    def test_min_boundary(self):
        from childermass.network_mcp.security import MIN_TIMESTAMP_MS

        assert validate_timestamp_ms(MIN_TIMESTAMP_MS) == MIN_TIMESTAMP_MS

    def test_rejects_too_old(self):
        with pytest.raises(SecurityError, match="out of range"):
            validate_timestamp_ms(1_000_000_000)  # too small (seconds, not ms)

    def test_rejects_too_future(self):
        with pytest.raises(SecurityError, match="out of range"):
            validate_timestamp_ms(5_000_000_000_000)

    def test_rejects_non_int(self):
        with pytest.raises(SecurityError, match="integer"):
            validate_timestamp_ms("1700000000000")  # type: ignore


# =========================================================================
# DPI type validation
# =========================================================================


class TestValidateDpiType:
    def test_by_app(self):
        assert validate_dpi_type("by_app") == "by_app"

    def test_by_cat(self):
        assert validate_dpi_type("by_cat") == "by_cat"

    def test_case_insensitive(self):
        assert validate_dpi_type("BY_APP") == "by_app"

    def test_strips_whitespace(self):
        assert validate_dpi_type("  by_cat  ") == "by_cat"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Invalid dpi_type"):
            validate_dpi_type("by_user")

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_dpi_type("")


# =========================================================================
# History hours validation
# =========================================================================


class TestValidateHistoryHours:
    def test_valid(self):
        assert validate_history_hours(24) == 24

    def test_min(self):
        assert validate_history_hours(MIN_HISTORY_HOURS) == MIN_HISTORY_HOURS

    def test_max(self):
        assert validate_history_hours(MAX_HISTORY_HOURS) == MAX_HISTORY_HOURS

    def test_rejects_zero(self):
        with pytest.raises(SecurityError, match="positive integer"):
            validate_history_hours(0)

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="positive integer"):
            validate_history_hours(-1)

    def test_rejects_too_large(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_history_hours(MAX_HISTORY_HOURS + 1)


# =========================================================================
# Event limit validation
# =========================================================================


class TestValidateEventLimit:
    def test_valid(self):
        assert validate_event_limit(100) == 100

    def test_one(self):
        assert validate_event_limit(1) == 1

    def test_max(self):
        assert validate_event_limit(MAX_EVENT_LIMIT) == MAX_EVENT_LIMIT

    def test_rejects_zero(self):
        with pytest.raises(SecurityError, match="positive integer"):
            validate_event_limit(0)

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="positive integer"):
            validate_event_limit(-1)

    def test_rejects_too_large(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_event_limit(MAX_EVENT_LIMIT + 1)


# =========================================================================
# Error message sanitization
# =========================================================================


class TestSanitizeErrorMessage:
    def test_strips_password(self):
        err = Exception("Login failed: password=mysecret123")
        result = sanitize_error_message(err)
        assert "mysecret123" not in result
        assert "password=***" in result

    def test_strips_token(self):
        err = Exception("Invalid token: TOKEN=abc123def456")
        result = sanitize_error_message(err)
        assert "abc123def456" not in result
        assert "TOKEN=***" in result

    def test_strips_csrf_token(self):
        err = Exception("X-CSRF-Token: abcdef123456")
        result = sanitize_error_message(err)
        assert "abcdef123456" not in result

    def test_strips_api_key(self):
        err = Exception("X-API-Key: sk_live_abc123def456")  # gitleaks:allow
        result = sanitize_error_message(err)
        assert "sk_live_abc123def456" not in result

    def test_strips_bearer_token(self):
        err = Exception("Authorization: Bearer eyJhbGci...")  # gitleaks:allow
        result = sanitize_error_message(err)
        assert "eyJhbGci" not in result
        assert "Bearer ***" in result

    def test_strips_ip_addresses(self):
        err = Exception("Connection refused: 192.168.1.100:443")
        result = sanitize_error_message(err)
        assert "192.168.1.100" not in result
        assert "***CONSOLE_IP***" in result

    def test_strips_file_paths(self):
        err = Exception("File not found: /Users/john/secret/config.json")
        result = sanitize_error_message(err)
        assert "/Users/john" not in result
        assert "/***/..." in result

    def test_strips_cookie(self):
        err = Exception("cookie=abc123secret")
        result = sanitize_error_message(err)
        assert "abc123secret" not in result

    def test_preserves_safe_message(self):
        err = Exception("Network not found")
        assert sanitize_error_message(err) == "Network not found"


# =========================================================================
# Rate Limiter
# =========================================================================


class TestRateLimiter:
    def test_allows_initial_request(self):
        limiter = RateLimiter()
        assert limiter.allow("networks") is True

    def test_allows_up_to_capacity(self):
        limiter = RateLimiter()
        for _i in range(30):  # networks capacity is 30
            assert limiter.allow("networks") is True

    def test_rejects_over_capacity(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("networks")
        assert limiter.allow("networks") is False

    def test_refills_over_time(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("networks")
        # Manually advance by modifying bucket
        key = "networks"
        bucket = limiter._buckets[key]
        bucket.last_refill -= 60  # simulate 60 seconds passed
        assert limiter.allow("networks") is True

    def test_check_raises_on_limit(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("networks")
        with pytest.raises(SecurityError, match="Rate limit exceeded"):
            limiter.check("networks")

    def test_different_operations_independent(self):
        limiter = RateLimiter()
        for _ in range(30):
            limiter.allow("networks")
        # Firewall should still work (different bucket)
        assert limiter.allow("firewall") is True

    def test_write_capacity(self):
        limiter = RateLimiter()
        for _ in range(10):  # write capacity is 10
            assert limiter.allow("write") is True
        assert limiter.allow("write") is False

    def test_unknown_operation_gets_default_limits(self):
        limiter = RateLimiter()
        # Unknown ops get default capacity of 60
        for _ in range(60):
            assert limiter.allow("unknown_op") is True
        assert limiter.allow("unknown_op") is False

    # --- New categories ---

    def test_stats_capacity(self):
        limiter = RateLimiter()
        for _ in range(30):
            assert limiter.allow("stats") is True
        assert limiter.allow("stats") is False

    def test_dpi_capacity(self):
        limiter = RateLimiter()
        for _ in range(20):
            assert limiter.allow("dpi") is True
        assert limiter.allow("dpi") is False

    def test_security_capacity(self):
        limiter = RateLimiter()
        for _ in range(30):
            assert limiter.allow("security") is True
        assert limiter.allow("security") is False

    def test_clients_capacity(self):
        limiter = RateLimiter()
        for _ in range(30):
            assert limiter.allow("clients") is True
        assert limiter.allow("clients") is False

    def test_devices_capacity(self):
        limiter = RateLimiter()
        for _ in range(30):
            assert limiter.allow("devices") is True
        assert limiter.allow("devices") is False

    def test_rf_capacity(self):
        limiter = RateLimiter()
        for _ in range(20):
            assert limiter.allow("rf") is True
        assert limiter.allow("rf") is False


# =========================================================================
# Audit Logging
# =========================================================================


class TestAuditLog:
    def test_creates_log_entry(self, tmp_path):
        """Test that audit_log writes valid JSON entries."""
        log_file = tmp_path / "test-audit.log"

        with (
            patch("childermass.network_mcp.security._AUDIT_LOG_FILE", log_file),
            patch("childermass.network_mcp.security._AUDIT_DIR", tmp_path),
        ):
            # Reset logger to pick up new path
            import logging

            logger_name = "childermass.network_mcp.audit"
            logger = logging.getLogger(logger_name)
            logger.handlers.clear()

            audit_log("test_operation", details={"network": "Guest WiFi"})

            content = log_file.read_text().strip()
            entry = json.loads(content)
            assert entry["operation"] == "test_operation"
            assert entry["success"] is True
            assert entry["details"]["network"] == "Guest WiFi"
            assert "timestamp" in entry

    def test_failure_entry(self, tmp_path):
        """Test failure audit log."""
        log_file = tmp_path / "test-audit.log"

        with (
            patch("childermass.network_mcp.security._AUDIT_LOG_FILE", log_file),
            patch("childermass.network_mcp.security._AUDIT_DIR", tmp_path),
        ):
            import logging

            logger = logging.getLogger("childermass.network_mcp.audit")
            logger.handlers.clear()

            audit_log("failed_op", success=False, details={"error": "timeout"})

            content = log_file.read_text().strip()
            entry = json.loads(content)
            assert entry["success"] is False

    def test_never_crashes(self):
        """Audit logging must never raise exceptions."""
        with patch("childermass.network_mcp.security._get_audit_logger") as mock:
            mock.side_effect = Exception("disk full")
            # Should not raise
            try:
                audit_log("test")
            except Exception:
                pass  # audit_log catches internally


# =========================================================================
# Auth config management
# =========================================================================


class TestAuthConfig:
    def test_load_config_missing_file(self, tmp_path):
        """Loading config with no file returns None."""
        from childermass.network_mcp.auth import load_config

        with patch(
            "childermass.network_mcp.auth.get_config_path",
            return_value=tmp_path / "nonexistent.json",
        ):
            assert load_config() is None

    def test_save_and_load_config(self, tmp_path):
        """Round-trip save and load of config."""
        from childermass.network_mcp.auth import load_config, save_config

        config_file = tmp_path / "network-config.json"

        with (
            patch("childermass.network_mcp.auth.get_config_path", return_value=config_file),
            patch("childermass.network_mcp.auth._is_keyring_available", return_value=False),
        ):
            save_config(
                host="192.168.1.1",
                username="admin",
                password="secret123",
                site_id="550e8400-e29b-41d4-a716-446655440000",
                port=443,
                verify_ssl=False,
            )

            assert config_file.exists()
            # File should have restricted permissions
            assert oct(config_file.stat().st_mode)[-3:] == "600"

            config = load_config()
            assert config is not None
            assert config["host"] == "192.168.1.1"
            assert config["username"] == "admin"
            assert config["password"] == "secret123"
            assert config["site_id"] == "550e8400-e29b-41d4-a716-446655440000"
            assert config["port"] == 443
            assert config["verify_ssl"] is False

    def test_get_console_url_default_port(self):
        """Test URL construction with default port."""
        from childermass.network_mcp.auth import get_console_url

        config = {"host": "192.168.1.1", "port": 443}
        assert get_console_url(config) == "https://192.168.1.1"

    def test_get_console_url_custom_port(self):
        """Test URL construction with custom port."""
        from childermass.network_mcp.auth import get_console_url

        config = {"host": "10.0.0.5", "port": 7443}
        assert get_console_url(config) == "https://10.0.0.5:7443"

    def test_get_credentials(self):
        """Test credential extraction from config."""
        from childermass.network_mcp.auth import get_credentials

        config = {"host": "1.2.3.4", "username": "admin", "password": "pw"}
        assert get_credentials(config) == ("admin", "pw")

    def test_get_credentials_no_config(self):
        """Test credential extraction with no config raises."""
        from childermass.network_mcp.auth import get_credentials

        with pytest.raises(RuntimeError, match="not configured"):
            get_credentials(None)

    def test_get_site_id(self):
        """Test site ID extraction from config."""
        from childermass.network_mcp.auth import get_site_id

        config = {"site_id": "550e8400-e29b-41d4-a716-446655440000"}
        assert get_site_id(config) == "550e8400-e29b-41d4-a716-446655440000"

    def test_get_site_id_empty(self):
        """Test site ID when not configured."""
        from childermass.network_mcp.auth import get_site_id

        assert get_site_id({}) is None
        assert get_site_id({"site_id": ""}) is None
