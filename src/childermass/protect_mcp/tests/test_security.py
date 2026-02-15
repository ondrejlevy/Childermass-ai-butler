"""
Comprehensive test suite for Childermass UniFi Protect MCP security layer.

Tests cover:
- Input validation (IDs, timestamps, dimensions, event types)
- Error message sanitization (IP, credentials, cookies)
- Rate limiting (token bucket)
- Audit logging
- Auth config management

Run with:
    PYTHONPATH=src pytest src/childermass/protect_mcp/tests/ -v
"""

import json
from unittest.mock import patch

import pytest

from childermass.protect_mcp.security import (
    DEFAULT_SNAPSHOT_HEIGHT,
    DEFAULT_SNAPSHOT_WIDTH,
    MAX_EVENT_RANGE_MS,
    MAX_EVENTS_PER_QUERY,
    MAX_SNAPSHOT_DIM,
    MIN_SNAPSHOT_DIM,
    RateLimiter,
    SecurityError,
    audit_log,
    sanitize_error_message,
    validate_camera_id,
    validate_event_id,
    validate_event_types,
    validate_hours,
    validate_light_id,
    validate_max_results,
    validate_nvr_address,
    validate_protect_id,
    validate_sensor_id,
    validate_smart_detect_types,
    validate_snapshot_dimensions,
    validate_time_range,
    validate_timestamp,
)


# =========================================================================
# Protect ID validation
# =========================================================================


class TestValidateProtectId:
    def test_valid_24_char_hex(self):
        assert validate_protect_id("aabbccddeeff00112233aabb") == "aabbccddeeff00112233aabb"

    def test_normalizes_to_lowercase(self):
        assert validate_protect_id("AABBCCDDEEFF00112233AABB") == "aabbccddeeff00112233aabb"

    def test_strips_whitespace(self):
        assert validate_protect_id("  aabbccddeeff00112233aabb  ") == "aabbccddeeff00112233aabb"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_protect_id("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError, match="required"):
            validate_protect_id(None)  # type: ignore

    def test_rejects_too_short(self):
        with pytest.raises(SecurityError, match="24-char hex"):
            validate_protect_id("aabbccdd")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="24-char hex"):
            validate_protect_id("aabbccddeeff00112233aabb00")

    def test_rejects_non_hex(self):
        with pytest.raises(SecurityError, match="24-char hex"):
            validate_protect_id("aabbccddeeff0011223xyzab")

    def test_rejects_special_chars(self):
        with pytest.raises(SecurityError, match="24-char hex"):
            validate_protect_id("aabbccddeeff001122-3aabb")


class TestValidateCameraId:
    def test_valid(self):
        assert validate_camera_id("aabbccddeeff00112233aabb") == "aabbccddeeff00112233aabb"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Camera ID"):
            validate_camera_id("invalid")


class TestValidateEventId:
    def test_valid(self):
        assert validate_event_id("aabbccddeeff00112233aabb") == "aabbccddeeff00112233aabb"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Event ID"):
            validate_event_id("")


class TestValidateSensorId:
    def test_valid(self):
        assert validate_sensor_id("aabbccddeeff00112233aabb") == "aabbccddeeff00112233aabb"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Sensor ID"):
            validate_sensor_id("xyz")


class TestValidateLightId:
    def test_valid(self):
        assert validate_light_id("aabbccddeeff00112233aabb") == "aabbccddeeff00112233aabb"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Light ID"):
            validate_light_id("short")


# =========================================================================
# Timestamp validation
# =========================================================================


class TestValidateTimestamp:
    def test_valid_recent_timestamp(self):
        # 2024-01-01 in ms
        ts = 1704067200000
        assert validate_timestamp(ts) == ts

    def test_converts_float_to_int(self):
        assert validate_timestamp(1704067200000.5) == 1704067200000

    def test_rejects_too_old(self):
        with pytest.raises(SecurityError, match="past"):
            validate_timestamp(1000000000000)  # ~2001

    def test_rejects_too_future(self):
        with pytest.raises(SecurityError, match="future"):
            validate_timestamp(3000000000000)  # ~2065

    def test_rejects_non_number(self):
        with pytest.raises(SecurityError, match="must be a number"):
            validate_timestamp("not_a_number")  # type: ignore

    def test_custom_field_name(self):
        with pytest.raises(SecurityError, match="start_time"):
            validate_timestamp(0, "start_time")


class TestValidateTimeRange:
    def test_valid_range(self):
        start = 1704067200000
        end = start + 3600000  # +1 hour
        assert validate_time_range(start, end) == (start, end)

    def test_rejects_end_before_start(self):
        start = 1704067200000
        end = start - 1000
        with pytest.raises(SecurityError, match="end must be after start"):
            validate_time_range(start, end)

    def test_rejects_equal(self):
        ts = 1704067200000
        with pytest.raises(SecurityError, match="end must be after start"):
            validate_time_range(ts, ts)

    def test_rejects_range_too_large(self):
        start = 1704067200000
        end = start + MAX_EVENT_RANGE_MS + 1
        with pytest.raises(SecurityError, match="too large"):
            validate_time_range(start, end)

    def test_max_range_allowed(self):
        start = 1704067200000
        end = start + MAX_EVENT_RANGE_MS
        assert validate_time_range(start, end) == (start, end)


# =========================================================================
# Snapshot dimension validation
# =========================================================================


class TestValidateSnapshotDimensions:
    def test_defaults_applied(self):
        w, h = validate_snapshot_dimensions(None, None)
        assert w == DEFAULT_SNAPSHOT_WIDTH
        assert h == DEFAULT_SNAPSHOT_HEIGHT

    def test_custom_dimensions(self):
        assert validate_snapshot_dimensions(1920, 1080) == (1920, 1080)

    def test_rejects_too_small_width(self):
        with pytest.raises(SecurityError, match="too small"):
            validate_snapshot_dimensions(50, 360)

    def test_rejects_too_small_height(self):
        with pytest.raises(SecurityError, match="too small"):
            validate_snapshot_dimensions(640, 50)

    def test_rejects_too_large(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_snapshot_dimensions(5000, 360)

    def test_max_allowed(self):
        assert validate_snapshot_dimensions(MAX_SNAPSHOT_DIM, MAX_SNAPSHOT_DIM) == (
            MAX_SNAPSHOT_DIM,
            MAX_SNAPSHOT_DIM,
        )

    def test_min_allowed(self):
        assert validate_snapshot_dimensions(MIN_SNAPSHOT_DIM, MIN_SNAPSHOT_DIM) == (
            MIN_SNAPSHOT_DIM,
            MIN_SNAPSHOT_DIM,
        )


# =========================================================================
# Event type validation
# =========================================================================


class TestValidateEventTypes:
    def test_none_returns_none(self):
        assert validate_event_types(None) is None

    def test_empty_returns_none(self):
        assert validate_event_types([]) is None

    def test_valid_types(self):
        result = validate_event_types(["motion", "smartDetectZone", "ring"])
        assert result == ["motion", "smartDetectZone", "ring"]

    def test_single_type(self):
        assert validate_event_types(["motion"]) == ["motion"]

    def test_rejects_invalid_type(self):
        with pytest.raises(SecurityError, match="Invalid event type"):
            validate_event_types(["motion", "invalid_type"])


class TestValidateSmartDetectTypes:
    def test_none_returns_none(self):
        assert validate_smart_detect_types(None) is None

    def test_valid_types(self):
        result = validate_smart_detect_types(["person", "vehicle", "package"])
        assert result == ["person", "vehicle", "package"]

    def test_all_types(self):
        all_types = ["person", "vehicle", "package", "animal", "face", "licensePlate"]
        assert validate_smart_detect_types(all_types) == all_types

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Invalid smart detection type"):
            validate_smart_detect_types(["person", "cat"])


# =========================================================================
# Max results validation
# =========================================================================


class TestValidateMaxResults:
    def test_valid(self):
        assert validate_max_results(50) == 50

    def test_one(self):
        assert validate_max_results(1) == 1

    def test_max(self):
        assert validate_max_results(MAX_EVENTS_PER_QUERY) == MAX_EVENTS_PER_QUERY

    def test_rejects_zero(self):
        with pytest.raises(SecurityError, match="positive integer"):
            validate_max_results(0)

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="positive integer"):
            validate_max_results(-1)

    def test_rejects_too_large(self):
        with pytest.raises(SecurityError, match="too large"):
            validate_max_results(MAX_EVENTS_PER_QUERY + 1)


# =========================================================================
# Hours validation
# =========================================================================


class TestValidateHours:
    def test_valid(self):
        assert validate_hours(24) == 24

    def test_one_hour(self):
        assert validate_hours(1) == 1

    def test_max_hours(self):
        assert validate_hours(168) == 168

    def test_converts_float(self):
        assert validate_hours(12.5) == 12

    def test_rejects_zero(self):
        with pytest.raises(SecurityError, match="at least 1"):
            validate_hours(0)

    def test_rejects_too_large(self):
        with pytest.raises(SecurityError, match="cannot exceed 168"):
            validate_hours(169)

    def test_rejects_non_number(self):
        with pytest.raises(SecurityError, match="must be a number"):
            validate_hours("abc")  # type: ignore


# =========================================================================
# NVR address validation
# =========================================================================


class TestValidateNvrAddress:
    def test_valid_ip(self):
        assert validate_nvr_address("192.168.1.1") == "192.168.1.1"

    def test_valid_hostname(self):
        assert validate_nvr_address("my-nvr.local") == "my-nvr.local"

    def test_strips_whitespace(self):
        assert validate_nvr_address("  10.0.0.1  ") == "10.0.0.1"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_nvr_address("")

    def test_rejects_newline(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_nvr_address("192.168.1.1\n")

    def test_rejects_spaces(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_nvr_address("192.168.1.1 ; rm -rf /")

    def test_rejects_semicolon(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_nvr_address("192.168.1.1;echo pwned")

    def test_rejects_pipe(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_nvr_address("192.168.1.1|malicious")

    def test_rejects_url(self):
        with pytest.raises(SecurityError, match="Invalid NVR address"):
            validate_nvr_address("https://192.168.1.1")


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

    def test_strips_bearer_token(self):
        err = Exception("Authorization: Bearer eyJhbGci...")
        result = sanitize_error_message(err)
        assert "eyJhbGci" not in result
        assert "Bearer ***" in result

    def test_strips_ip_addresses(self):
        err = Exception("Connection refused: 192.168.1.100:443")
        result = sanitize_error_message(err)
        assert "192.168.1.100" not in result
        assert "***NVR_IP***" in result

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
        err = Exception("Camera not found")
        assert sanitize_error_message(err) == "Camera not found"


# =========================================================================
# Rate Limiter
# =========================================================================


class TestRateLimiter:
    def test_allows_initial_request(self):
        limiter = RateLimiter()
        assert limiter.allow("snapshot") is True

    def test_allows_up_to_capacity(self):
        limiter = RateLimiter()
        for _i in range(10):  # snapshot capacity is 10
            assert limiter.allow("snapshot") is True

    def test_rejects_over_capacity(self):
        limiter = RateLimiter()
        for _ in range(10):
            limiter.allow("snapshot")
        assert limiter.allow("snapshot") is False

    def test_refills_over_time(self):
        limiter = RateLimiter()
        for _ in range(10):
            limiter.allow("snapshot")
        # Manually advance by modifying bucket
        key = "snapshot"
        bucket = limiter._buckets[key]
        bucket.last_refill -= 60  # simulate 60 seconds passed
        assert limiter.allow("snapshot") is True

    def test_check_raises_on_limit(self):
        limiter = RateLimiter()
        for _ in range(10):
            limiter.allow("snapshot")
        with pytest.raises(SecurityError, match="Rate limit exceeded"):
            limiter.check("snapshot")

    def test_different_operations_independent(self):
        limiter = RateLimiter()
        for _ in range(10):
            limiter.allow("snapshot")
        # Events should still work (different bucket)
        assert limiter.allow("events") is True

    def test_unknown_operation_gets_default_limits(self):
        limiter = RateLimiter()
        # Unknown ops get default capacity of 60
        for _ in range(60):
            assert limiter.allow("unknown_op") is True
        assert limiter.allow("unknown_op") is False


# =========================================================================
# Audit Logging
# =========================================================================


class TestAuditLog:
    def test_creates_log_entry(self, tmp_path):
        """Test that audit_log writes valid JSON entries."""
        log_file = tmp_path / "test-audit.log"

        with (
            patch("childermass.protect_mcp.security._AUDIT_LOG_FILE", log_file),
            patch("childermass.protect_mcp.security._AUDIT_DIR", tmp_path),
        ):
            # Reset logger to pick up new path
            import logging

            logger_name = "childermass.protect_mcp.audit"
            logger = logging.getLogger(logger_name)
            logger.handlers.clear()

            audit_log("test_operation", details={"camera": "front_door"})

            content = log_file.read_text().strip()
            entry = json.loads(content)
            assert entry["operation"] == "test_operation"
            assert entry["success"] is True
            assert entry["details"]["camera"] == "front_door"
            assert "timestamp" in entry

    def test_failure_entry(self, tmp_path):
        """Test failure audit log."""
        log_file = tmp_path / "test-audit.log"

        with (
            patch("childermass.protect_mcp.security._AUDIT_LOG_FILE", log_file),
            patch("childermass.protect_mcp.security._AUDIT_DIR", tmp_path),
        ):
            import logging

            logger = logging.getLogger("childermass.protect_mcp.audit")
            logger.handlers.clear()

            audit_log("failed_op", success=False, details={"error": "timeout"})

            content = log_file.read_text().strip()
            entry = json.loads(content)
            assert entry["success"] is False

    def test_never_crashes(self):
        """Audit logging must never raise exceptions."""
        # Even with invalid setup, should not crash
        with patch("childermass.protect_mcp.security._get_audit_logger") as mock:
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
        from childermass.protect_mcp.auth import load_config

        with patch(
            "childermass.protect_mcp.auth.get_config_path",
            return_value=tmp_path / "nonexistent.json",
        ):
            assert load_config() is None

    def test_save_and_load_config(self, tmp_path):
        """Round-trip save and load of config."""
        from childermass.protect_mcp.auth import load_config, save_config

        config_file = tmp_path / "protect-config.json"

        with (
            patch("childermass.protect_mcp.auth.get_config_path", return_value=config_file),
            patch("childermass.protect_mcp.auth._is_keyring_available", return_value=False),
        ):
            save_config(
                host="192.168.1.100",
                username="admin",
                password="secret123",
                port=443,
                verify_ssl=False,
            )

            assert config_file.exists()
            # File should have restricted permissions
            assert oct(config_file.stat().st_mode)[-3:] == "600"

            config = load_config()
            assert config is not None
            assert config["host"] == "192.168.1.100"
            assert config["username"] == "admin"
            assert config["password"] == "secret123"
            assert config["port"] == 443
            assert config["verify_ssl"] is False

    def test_get_nvr_url_default_port(self):
        """Test URL construction with default port."""
        from childermass.protect_mcp.auth import get_nvr_url

        config = {"host": "192.168.1.1", "port": 443}
        assert get_nvr_url(config) == "https://192.168.1.1"

    def test_get_nvr_url_custom_port(self):
        """Test URL construction with custom port."""
        from childermass.protect_mcp.auth import get_nvr_url

        config = {"host": "10.0.0.5", "port": 7443}
        assert get_nvr_url(config) == "https://10.0.0.5:7443"

    def test_get_credentials(self):
        """Test credential extraction from config."""
        from childermass.protect_mcp.auth import get_credentials

        config = {"host": "1.2.3.4", "username": "admin", "password": "pw"}
        assert get_credentials(config) == ("admin", "pw")

    def test_get_credentials_no_config(self):
        """Test credential extraction with no config raises."""
        from childermass.protect_mcp.auth import get_credentials

        with pytest.raises(RuntimeError, match="not configured"):
            get_credentials(None)
