"""Comprehensive security and functionality tests for Childermass Mapy.com MCP."""

import json

import pytest

from childermass.mapy_mcp.security import (
    SecurityError,
    validate_query,
    validate_coordinates,
    validate_language,
    validate_route_type,
    validate_geocode_type,
    validate_limit,
    validate_waypoints,
    validate_positions,
    validate_departure,
    validate_geometry_format,
    RateLimiter,
    sanitize_error_message,
    audit_log,
)


# ============================================================================
# Input Validation Tests
# ============================================================================


class TestQueryValidation:
    """Test search query validation."""

    def test_valid_queries(self):
        assert validate_query("Praha") == "Praha"
        assert validate_query("  Národní muzeum  ") == "Národní muzeum"
        assert validate_query("Václavské náměstí 1, Praha 1") == "Václavské náměstí 1, Praha 1"
        assert validate_query("Lidl") == "Lidl"
        assert validate_query("50.0755,14.4378") == "50.0755,14.4378"
        assert validate_query("x") == "x"  # min length is 1

    def test_empty_query(self):
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_query("")

    def test_none_query(self):
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_query(None)

    def test_too_long_query(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_query("x" * 501)

    def test_control_characters(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_query("Praha\x00")

        with pytest.raises(SecurityError, match="control characters"):
            validate_query("test\x07query")


class TestCoordinateValidation:
    """Test coordinate validation."""

    def test_valid_coordinates(self):
        assert validate_coordinates(50.0755, 14.4378) == (50.0755, 14.4378)
        assert validate_coordinates(0, 0) == (0.0, 0.0)
        assert validate_coordinates(90, 180) == (90.0, 180.0)
        assert validate_coordinates(-90, -180) == (-90.0, -180.0)
        assert validate_coordinates(49.1951, 16.6068) == (49.1951, 16.6068)

    def test_integer_coordinates(self):
        assert validate_coordinates(50, 14) == (50.0, 14.0)

    def test_invalid_types(self):
        with pytest.raises(SecurityError, match="must be numbers"):
            validate_coordinates("50.07", 14.43)

        with pytest.raises(SecurityError, match="must be numbers"):
            validate_coordinates(50.07, "14.43")

    def test_out_of_range_latitude(self):
        with pytest.raises(SecurityError, match="Invalid latitude"):
            validate_coordinates(91, 0)

        with pytest.raises(SecurityError, match="Invalid latitude"):
            validate_coordinates(-91, 0)

    def test_out_of_range_longitude(self):
        with pytest.raises(SecurityError, match="Invalid longitude"):
            validate_coordinates(0, 181)

        with pytest.raises(SecurityError, match="Invalid longitude"):
            validate_coordinates(0, -181)


class TestLanguageValidation:
    """Test language code validation."""

    def test_valid_languages(self):
        assert validate_language("cs") == "cs"
        assert validate_language("en") == "en"
        assert validate_language("de") == "de"
        assert validate_language("sk") == "sk"
        assert validate_language("  CS  ") == "cs"

    def test_invalid_language(self):
        with pytest.raises(SecurityError, match="Unsupported language"):
            validate_language("xx")

    def test_empty_language(self):
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_language("")

    def test_none_language(self):
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_language(None)


class TestRouteTypeValidation:
    """Test route type validation."""

    def test_valid_route_types(self):
        assert validate_route_type("car_fast") == "car_fast"
        assert validate_route_type("car_fast_traffic") == "car_fast_traffic"
        assert validate_route_type("car_short") == "car_short"
        assert validate_route_type("foot_fast") == "foot_fast"
        assert validate_route_type("foot_hiking") == "foot_hiking"
        assert validate_route_type("bike_road") == "bike_road"
        assert validate_route_type("bike_mountain") == "bike_mountain"
        assert validate_route_type("  CAR_FAST  ") == "car_fast"

    def test_invalid_route_type(self):
        with pytest.raises(SecurityError, match="Invalid route type"):
            validate_route_type("airplane")

    def test_empty_route_type(self):
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_route_type("")


class TestGeocodeTypeValidation:
    """Test geocode entity type validation."""

    def test_valid_geocode_types(self):
        assert validate_geocode_type("regional") == "regional"
        assert validate_geocode_type("poi") == "poi"
        assert validate_geocode_type("regional.address") == "regional.address"
        assert validate_geocode_type("regional.municipality") == "regional.municipality"
        assert validate_geocode_type("coordinate") == "coordinate"

    def test_invalid_geocode_type(self):
        with pytest.raises(SecurityError, match="Invalid geocode type"):
            validate_geocode_type("building")

    def test_empty_geocode_type(self):
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_geocode_type("")


class TestLimitValidation:
    """Test result limit validation."""

    def test_valid_limits(self):
        assert validate_limit(1) == 1
        assert validate_limit(50) == 50
        assert validate_limit(100) == 100

    def test_below_minimum(self):
        with pytest.raises(SecurityError, match="at least 1"):
            validate_limit(0)

        with pytest.raises(SecurityError, match="at least 1"):
            validate_limit(-5)

    def test_above_maximum(self):
        with pytest.raises(SecurityError, match="cannot exceed 100"):
            validate_limit(101)

    def test_custom_max(self):
        assert validate_limit(10, max_limit=10) == 10
        with pytest.raises(SecurityError, match="cannot exceed 10"):
            validate_limit(11, max_limit=10)

    def test_invalid_type(self):
        with pytest.raises(SecurityError, match="must be an integer"):
            validate_limit("5")

        with pytest.raises(SecurityError, match="must be an integer"):
            validate_limit(5.5)


class TestWaypointsValidation:
    """Test waypoints validation."""

    def test_valid_waypoints(self):
        wps = [(50.0, 14.0), (49.0, 16.0)]
        result = validate_waypoints(wps)
        assert len(result) == 2
        assert result[0] == (50.0, 14.0)

    def test_too_many_waypoints(self):
        wps = [(50.0, 14.0)] * 16
        with pytest.raises(SecurityError, match="Maximum 15"):
            validate_waypoints(wps)

    def test_invalid_waypoint_format(self):
        with pytest.raises(SecurityError, match="must be a \\[lat, lon\\] pair"):
            validate_waypoints([(50.0,)])

    def test_invalid_waypoint_coords(self):
        with pytest.raises(SecurityError, match="Invalid latitude"):
            validate_waypoints([(91.0, 14.0)])

    def test_not_a_list(self):
        with pytest.raises(SecurityError, match="must be a list"):
            validate_waypoints("50.0,14.0")


class TestPositionsValidation:
    """Test positions validation for elevation."""

    def test_valid_positions(self):
        pos = [(50.0, 14.0)]
        result = validate_positions(pos)
        assert len(result) == 1

    def test_empty_positions(self):
        with pytest.raises(SecurityError, match="At least one position"):
            validate_positions([])

    def test_too_many_positions(self):
        pos = [(50.0, 14.0)] * 257
        with pytest.raises(SecurityError, match="Maximum 256"):
            validate_positions(pos)

    def test_invalid_position_format(self):
        with pytest.raises(SecurityError, match="must be a \\[lat, lon\\] pair"):
            validate_positions([(50.0,)])


class TestDepartureValidation:
    """Test departure time validation."""

    def test_valid_departures(self):
        assert validate_departure("2026-02-14T08:00:00") == "2026-02-14T08:00:00"
        assert validate_departure("2026-02-14T08:00:00.000") == "2026-02-14T08:00:00.000"
        assert validate_departure("2026-02-14T08:00") == "2026-02-14T08:00"
        assert validate_departure("  2026-02-14T08:00:00  ") == "2026-02-14T08:00:00"

    def test_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid departure format"):
            validate_departure("2026-02-14")

        with pytest.raises(SecurityError, match="Invalid departure format"):
            validate_departure("tomorrow")

    def test_empty_departure(self):
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_departure("")

    def test_none_departure(self):
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_departure(None)


class TestGeometryFormatValidation:
    """Test geometry format validation."""

    def test_valid_formats(self):
        assert validate_geometry_format("geojson") == "geojson"
        assert validate_geometry_format("polyline") == "polyline"
        assert validate_geometry_format("polyline6") == "polyline6"
        assert validate_geometry_format("  GEOJSON  ") == "geojson"

    def test_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid geometry format"):
            validate_geometry_format("wkt")

    def test_empty_format(self):
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_geometry_format("")


# ============================================================================
# Rate Limiter Tests
# ============================================================================


class TestRateLimiter:
    """Test rate limiter."""

    def test_within_limit(self):
        limiter = RateLimiter()
        # Should not raise for first call
        limiter.check("geocode")

    def test_over_limit(self):
        limiter = RateLimiter()
        # Exhaust all tokens
        for _ in range(60):
            limiter.check("geocode")
        # Next one should raise
        with pytest.raises(SecurityError, match="Rate limit exceeded"):
            limiter.check("geocode")

    def test_token_refill(self):
        limiter = RateLimiter()
        # Exhaust all tokens
        for _ in range(60):
            limiter.check("geocode")

        # Simulate time passing (2 seconds = 2 tokens refilled at 60/min)
        limiter.buckets["geocode"]["last_update"] -= 2
        limiter.check("geocode")  # Should not raise

    def test_operation_independence(self):
        limiter = RateLimiter()
        # Exhaust geocode tokens
        for _ in range(60):
            limiter.check("geocode")

        # Route should still work
        limiter.check("route")

    def test_unknown_operation_uses_default(self):
        limiter = RateLimiter()
        # Should not raise — falls back to "geocode" limits
        limiter.check("unknown_op")

    def test_different_operation_limits(self):
        limiter = RateLimiter()
        # Matrix has lower limit (20)
        for _ in range(20):
            limiter.check("matrix")
        with pytest.raises(SecurityError, match="Rate limit exceeded"):
            limiter.check("matrix")


# ============================================================================
# Error Sanitization Tests
# ============================================================================


class TestSanitizeErrorMessage:
    """Test error message sanitization."""

    def test_removes_api_key_from_query_param(self):
        msg = sanitize_error_message(
            Exception("Error at https://api.mapy.com/v1/geocode?apiKey=abc123secret456key")
        )
        assert "abc123secret456key" not in msg
        assert "apiKey=[API_KEY]" in msg

    def test_removes_api_key_from_header(self):
        msg = sanitize_error_message(
            Exception("Header X-Mapy-Api-Key: mySecretApiKey123")
        )
        assert "mySecretApiKey123" not in msg
        assert "X-Mapy-Api-Key: [API_KEY]" in msg

    def test_removes_file_paths(self):
        msg = sanitize_error_message(
            Exception("File not found: /home/user/.childermass/mapy_api_key")
        )
        assert "/home/user" not in msg
        assert "[PATH]" in msg

    def test_truncates_long_messages(self):
        msg = sanitize_error_message(Exception("x" * 300))
        assert len(msg) <= 200
        assert msg.endswith("...")

    def test_preserves_safe_messages(self):
        msg = sanitize_error_message(Exception("Location not found"))
        assert msg == "Location not found"


# ============================================================================
# Audit Log Tests
# ============================================================================


class TestAuditLog:
    """Test audit logging."""

    def test_writes_log_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "mapy-audit.log"
        monkeypatch.setattr(
            "childermass.mapy_mcp.security.AUDIT_LOG_FILE", log_file
        )
        monkeypatch.setattr(
            "childermass.mapy_mcp.security.CONFIG_DIR", tmp_path
        )

        audit_log("geocode", {"query": "Praha", "count": 3})

        assert log_file.exists()
        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["operation"] == "geocode"
        assert entry["details"]["query"] == "Praha"
        assert "timestamp" in entry

    def test_writes_failure_entry(self, tmp_path, monkeypatch):
        log_file = tmp_path / "mapy-audit.log"
        monkeypatch.setattr(
            "childermass.mapy_mcp.security.AUDIT_LOG_FILE", log_file
        )
        monkeypatch.setattr(
            "childermass.mapy_mcp.security.CONFIG_DIR", tmp_path
        )

        audit_log("plan_route", {"error": "timeout", "start": "50,14"})

        content = log_file.read_text()
        entry = json.loads(content.strip())
        assert entry["operation"] == "plan_route"
        assert entry["details"]["error"] == "timeout"


# ============================================================================
# Auth Module Tests
# ============================================================================


class TestAuthKeyring:
    """Test authentication key management."""

    def test_keyring_detection(self):
        from childermass.mapy_mcp.auth import KEYRING_AVAILABLE
        # Should be a boolean
        assert isinstance(KEYRING_AVAILABLE, bool)

    def test_credentials_path(self):
        from childermass.mapy_mcp.auth import API_KEY_FILE, CONFIG_DIR
        assert str(API_KEY_FILE).endswith("mapy_api_key")
        assert str(CONFIG_DIR).endswith(".childermass")

    def test_authentication_error_raised(self, monkeypatch):
        from childermass.mapy_mcp.auth import get_api_key, AuthenticationError
        # Disable keyring
        monkeypatch.setattr("childermass.mapy_mcp.auth.KEYRING_AVAILABLE", False)
        # Use non-existent file
        monkeypatch.setattr(
            "childermass.mapy_mcp.auth.API_KEY_FILE",
            pytest.importorskip("pathlib").Path("/nonexistent/mapy_api_key"),
        )
        with pytest.raises(AuthenticationError, match="No Mapy.com API key"):
            get_api_key()

    def test_set_api_key_empty(self):
        from childermass.mapy_mcp.auth import set_api_key
        with pytest.raises(ValueError, match="cannot be empty"):
            set_api_key("")

    def test_set_api_key_whitespace(self):
        from childermass.mapy_mcp.auth import set_api_key
        with pytest.raises(ValueError, match="cannot be empty"):
            set_api_key("   ")


# ============================================================================
# Client Validation Tests
# ============================================================================


class TestClientValidation:
    """Test input validation on client methods."""

    def _get_client(self):
        """Create a client with a fake API key (no real API calls)."""
        from childermass.mapy_mcp.client import MapyClient
        return MapyClient(api_key="fake_test_key_for_validation")

    def test_geocode_empty_query(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="non-empty string"):
            client.geocode("")

    def test_geocode_invalid_language(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="Unsupported language"):
            client.geocode("Praha", lang="xx")

    def test_geocode_invalid_limit(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="cannot exceed"):
            client.geocode("Praha", limit=200)

    def test_geocode_invalid_type(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="Invalid geocode type"):
            client.geocode("Praha", geocode_type="building")

    def test_reverse_geocode_invalid_coords(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="Invalid latitude"):
            client.reverse_geocode(lat=91, lon=14)

    def test_plan_route_invalid_route_type(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="Invalid route type"):
            client.plan_route(50, 14, 49, 16, route_type="airplane")

    def test_plan_route_invalid_start(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="Invalid latitude"):
            client.plan_route(91, 14, 49, 16)

    def test_plan_route_too_many_waypoints(self):
        client = self._get_client()
        wps = [(50.0, 14.0)] * 16
        with pytest.raises(SecurityError, match="Maximum 15"):
            client.plan_route(50, 14, 49, 16, waypoints=wps)

    def test_plan_route_invalid_departure(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="Invalid departure"):
            client.plan_route(50, 14, 49, 16, departure="tomorrow morning")

    def test_matrix_routing_too_many(self):
        client = self._get_client()
        starts = [(50.0, 14.0)] * 11
        ends = [(49.0, 16.0)] * 10  # 11 × 10 = 110 > 100
        with pytest.raises(SecurityError, match="exceeds maximum of 100"):
            client.matrix_routing(starts, ends)

    def test_matrix_routing_empty_starts(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="At least one start"):
            client.matrix_routing([])

    def test_elevation_too_many_positions(self):
        client = self._get_client()
        positions = [(50.0, 14.0)] * 257
        with pytest.raises(SecurityError, match="Maximum 256"):
            client.get_elevation(positions)

    def test_elevation_empty_positions(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="At least one position"):
            client.get_elevation([])

    def test_timezone_empty_name(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="non-empty string"):
            client.get_timezone_by_name("")

    def test_timezone_long_name(self):
        client = self._get_client()
        with pytest.raises(SecurityError, match="too long"):
            client.get_timezone_by_name("x" * 101)


# ============================================================================
# Server Helper Tests
# ============================================================================


class TestServerHelpers:
    """Test server helper functions."""

    def test_parse_coords_valid(self):
        from childermass.mapy_mcp.server import _parse_coords
        assert _parse_coords("50.0755,14.4378") == (50.0755, 14.4378)
        assert _parse_coords("  49.1951 , 16.6068  ") == (49.1951, 16.6068)

    def test_parse_coords_invalid_format(self):
        from childermass.mapy_mcp.server import _parse_coords
        with pytest.raises(SecurityError, match="Invalid coordinate format"):
            _parse_coords("50.0755")

        with pytest.raises(SecurityError, match="Invalid coordinate format"):
            _parse_coords("50.0755,14.43,78")

    def test_parse_coords_invalid_values(self):
        from childermass.mapy_mcp.server import _parse_coords
        with pytest.raises(SecurityError, match="Invalid coordinate values"):
            _parse_coords("abc,def")

    def test_parse_coords_out_of_range(self):
        from childermass.mapy_mcp.server import _parse_coords
        with pytest.raises(SecurityError, match="Invalid latitude"):
            _parse_coords("91,14")

    def test_parse_coords_empty(self):
        from childermass.mapy_mcp.server import _parse_coords
        with pytest.raises(SecurityError, match="non-empty string"):
            _parse_coords("")
