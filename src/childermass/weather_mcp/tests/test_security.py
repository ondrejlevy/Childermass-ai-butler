"""Comprehensive security and functionality tests for Childermass Weather MCP."""

import time
from unittest.mock import Mock, patch

import pytest

from childermass.weather_mcp.security import (
    RateLimiter,
    SecurityError,
    sanitize_error_message,
    validate_activity,
    validate_city_name,
    validate_coordinates,
    validate_date_string,
    validate_days,
    validate_hours,
    validate_location,
    validate_units,
)


# ============================================================================
# Input Validation Tests
# ============================================================================


class TestCityNameValidation:
    """Test city name validation."""

    def test_valid_city_names(self):
        """Test valid city names."""
        assert validate_city_name("London") == "London"
        assert validate_city_name("New York") == "New York"
        assert validate_city_name("San Francisco,US") == "San Francisco,US"
        assert validate_city_name("Saint-Tropez") == "Saint-Tropez"
        assert validate_city_name("O'Fallon") == "O'Fallon"
        assert validate_city_name("  Paris  ") == "Paris"

    def test_invalid_city_names(self):
        """Test invalid city names."""
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_city_name("")

        with pytest.raises(SecurityError, match="non-empty string"):
            validate_city_name(None)

        with pytest.raises(SecurityError, match="too short"):
            validate_city_name("X")

        with pytest.raises(SecurityError, match="too long"):
            validate_city_name("X" * 201)

        with pytest.raises(SecurityError, match="invalid characters"):
            validate_city_name("London123")

        with pytest.raises(SecurityError, match="invalid characters"):
            validate_city_name("Paris@France")


class TestCoordinateValidation:
    """Test coordinate validation."""

    def test_valid_coordinates(self):
        """Test valid coordinates."""
        assert validate_coordinates(51.5074, -0.1278) == (51.5074, -0.1278)
        assert validate_coordinates(0, 0) == (0.0, 0.0)
        assert validate_coordinates(90, 180) == (90.0, 180.0)
        assert validate_coordinates(-90, -180) == (-90.0, -180.0)
        assert validate_coordinates(40.7128, -74.0060) == (40.7128, -74.0060)

    def test_invalid_coordinates(self):
        """Test invalid coordinates."""
        with pytest.raises(SecurityError, match="must be numbers"):
            validate_coordinates("51.5", -0.1278)

        with pytest.raises(SecurityError, match="must be numbers"):
            validate_coordinates(51.5074, "bad")

        with pytest.raises(SecurityError, match="Invalid latitude"):
            validate_coordinates(91, 0)

        with pytest.raises(SecurityError, match="Invalid latitude"):
            validate_coordinates(-91, 0)

        with pytest.raises(SecurityError, match="Invalid longitude"):
            validate_coordinates(0, 181)

        with pytest.raises(SecurityError, match="Invalid longitude"):
            validate_coordinates(0, -181)


class TestUnitsValidation:
    """Test units validation."""

    def test_valid_units(self):
        """Test valid units."""
        assert validate_units("metric") == "metric"
        assert validate_units("imperial") == "imperial"
        assert validate_units("standard") == "standard"
        assert validate_units("  METRIC  ") == "metric"
        assert validate_units("Imperial") == "imperial"

    def test_invalid_units(self):
        """Test invalid units."""
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_units("")

        with pytest.raises(SecurityError, match="non-empty string"):
            validate_units(None)

        with pytest.raises(SecurityError, match="Invalid units"):
            validate_units("celsius")

        with pytest.raises(SecurityError, match="Invalid units"):
            validate_units("fahrenheit")


class TestDaysValidation:
    """Test days validation."""

    def test_valid_days(self):
        """Test valid days."""
        assert validate_days(1) == 1
        assert validate_days(3) == 3
        assert validate_days(5) == 5
        assert validate_days(2, max_days=10) == 2

    def test_invalid_days(self):
        """Test invalid days."""
        with pytest.raises(SecurityError, match="must be an integer"):
            validate_days("3")

        with pytest.raises(SecurityError, match="must be an integer"):
            validate_days(3.5)

        with pytest.raises(SecurityError, match="at least 1"):
            validate_days(0)

        with pytest.raises(SecurityError, match="at least 1"):
            validate_days(-1)

        with pytest.raises(SecurityError, match="cannot exceed 5"):
            validate_days(6)


class TestHoursValidation:
    """Test hours validation."""

    def test_valid_hours(self):
        """Test valid hours."""
        assert validate_hours(1) == 1
        assert validate_hours(12) == 12
        assert validate_hours(48) == 48
        assert validate_hours(24, max_hours=24) == 24

    def test_invalid_hours(self):
        """Test invalid hours."""
        with pytest.raises(SecurityError, match="must be an integer"):
            validate_hours("12")

        with pytest.raises(SecurityError, match="at least 1"):
            validate_hours(0)

        with pytest.raises(SecurityError, match="cannot exceed 48"):
            validate_hours(49)


class TestActivityValidation:
    """Test activity validation."""

    def test_valid_activities(self):
        """Test valid activities."""
        assert validate_activity("hiking") == "hiking"
        assert validate_activity("  Running  ") == "running"
        assert validate_activity("rock-climbing") == "rock-climbing"
        assert validate_activity("BEACH") == "beach"

    def test_invalid_activities(self):
        """Test invalid activities."""
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_activity("")

        with pytest.raises(SecurityError, match="too short"):
            validate_activity("x")

        with pytest.raises(SecurityError, match="too long"):
            validate_activity("x" * 51)

        with pytest.raises(SecurityError, match="invalid characters"):
            validate_activity("hiking123")

        with pytest.raises(SecurityError, match="invalid characters"):
            validate_activity("beach@sunset")


class TestDateValidation:
    """Test date string validation."""

    def test_valid_dates(self):
        """Test valid dates."""
        assert validate_date_string("2026-02-14") == "2026-02-14"
        assert validate_date_string("2026-01-01") == "2026-01-01"
        assert validate_date_string("  2026-12-31  ") == "2026-12-31"

    def test_invalid_dates(self):
        """Test invalid dates."""
        with pytest.raises(SecurityError, match="non-empty string"):
            validate_date_string("")

        with pytest.raises(SecurityError, match="Invalid date format"):
            validate_date_string("2026/02/14")

        with pytest.raises(SecurityError, match="Invalid date format"):
            validate_date_string("14-02-2026")

        with pytest.raises(SecurityError, match="Invalid date format"):
            validate_date_string("2026-2-14")

        with pytest.raises(SecurityError, match="Month out of range"):
            validate_date_string("2026-13-01")

        with pytest.raises(SecurityError, match="Day out of range"):
            validate_date_string("2026-02-32")

        with pytest.raises(SecurityError, match="Year out of range"):
            validate_date_string("1800-02-14")


class TestLocationValidation:
    """Test combined location validation."""

    def test_city_location(self):
        """Test city name locations."""
        loc_type, city, lat, lon = validate_location("London,UK")
        assert loc_type == "city"
        assert city == "London,UK"
        assert lat is None
        assert lon is None

    def test_coordinate_location(self):
        """Test coordinate locations."""
        loc_type, city, lat, lon = validate_location((51.5074, -0.1278))
        assert loc_type == "coords"
        assert city is None
        assert lat == 51.5074
        assert lon == -0.1278

    def test_invalid_location_type(self):
        """Test invalid location types."""
        with pytest.raises(SecurityError, match="city name string or.*tuple"):
            validate_location(123)

        with pytest.raises(SecurityError, match="city name string or.*tuple"):
            validate_location([51.5074])

        with pytest.raises(SecurityError, match="city name string or.*tuple"):
            validate_location((51.5074, -0.1278, 100))


# ============================================================================
# Rate Limiter Tests
# ============================================================================


class TestRateLimiter:
    """Test rate limiter functionality."""

    def test_rate_limiter_allows_within_limit(self):
        """Test that operations within limit are allowed."""
        limiter = RateLimiter()

        # Should allow multiple operations within limit
        for _ in range(5):
            limiter.check("current")  # 60/min limit

        # Should not raise
        limiter.check("forecast")  # 30/min limit

    def test_rate_limiter_blocks_exceeding_limit(self):
        """Test that operations exceeding limit are blocked."""
        limiter = RateLimiter()

        # Exhaust the bucket (10/min for historical)
        for _ in range(10):
            limiter.check("historical")

        # Next one should fail
        with pytest.raises(SecurityError, match="Rate limit exceeded"):
            limiter.check("historical")

    def test_rate_limiter_refills_over_time(self):
        """Test that rate limiter refills tokens over time."""
        limiter = RateLimiter()

        # Exhaust bucket
        for _ in range(10):
            limiter.check("historical")

        # Should fail immediately
        with pytest.raises(SecurityError, match="Rate limit exceeded"):
            limiter.check("historical")

        # Wait for refill (tokens refill at 10/min = 1 per 6 seconds)
        time.sleep(7)

        # Should work now
        limiter.check("historical")

    def test_different_operations_independent(self):
        """Test that different operations have independent limits."""
        limiter = RateLimiter()

        # Exhaust one operation
        for _ in range(10):
            limiter.check("historical")

        # Other operations should still work
        limiter.check("current")
        limiter.check("forecast")

    def test_unknown_operation_uses_default(self):
        """Test that unknown operations use default limit."""
        limiter = RateLimiter()

        # Unknown operation should work (uses "current" limit)
        limiter.check("unknown_operation")


# ============================================================================
# Error Sanitization Tests
# ============================================================================


class TestErrorSanitization:
    """Test error message sanitization."""

    def test_sanitize_api_key(self):
        """Test API key sanitization."""
        error = Exception("Error with key: abc123def456789012345678901234567890")
        sanitized = sanitize_error_message(error)
        assert "abc123def456789012345678901234567890" not in sanitized
        assert "[API_KEY]" in sanitized

    def test_sanitize_file_paths_unix(self):
        """Test Unix file path sanitization."""
        error = Exception("Failed to read /home/user/.childermass/api_key")
        sanitized = sanitize_error_message(error)
        assert "/home/user" not in sanitized
        assert "[PATH]" in sanitized

    def test_sanitize_file_paths_windows(self):
        """Test Windows file path sanitization."""
        error = Exception("Failed to read C:\\Users\\user\\.childermass\\api_key")
        sanitized = sanitize_error_message(error)
        assert "C:\\Users" not in sanitized
        assert "[PATH]" in sanitized

    def test_sanitize_api_key_in_url(self):
        """Test API key in URL sanitization."""
        error = Exception("Request failed: https://api.openweathermap.org/data?appid=abc123def456")
        sanitized = sanitize_error_message(error)
        assert "abc123def456" not in sanitized
        assert "appid=[API_KEY]" in sanitized

    def test_length_limiting(self):
        """Test that long error messages are truncated."""
        long_message = "Error: " + ("x" * 300)
        error = Exception(long_message)
        sanitized = sanitize_error_message(error)
        assert len(sanitized) <= 200
        assert sanitized.endswith("...")

    def test_normal_messages_unchanged(self):
        """Test that normal messages pass through."""
        error = Exception("Simple error message")
        sanitized = sanitize_error_message(error)
        assert "Simple error message" in sanitized


# ============================================================================
# Cache Tests
# ============================================================================


class TestResponseCache:
    """Test response caching."""

    def test_cache_stores_and_retrieves(self):
        """Test basic cache storage and retrieval."""
        from childermass.weather_mcp.client import ResponseCache

        cache = ResponseCache(ttl=10)
        cache.set("key1", {"data": "value"})

        result = cache.get("key1")
        assert result == {"data": "value"}

    def test_cache_expires(self):
        """Test that cached data expires."""
        from childermass.weather_mcp.client import ResponseCache

        cache = ResponseCache(ttl=1)
        cache.set("key1", "value")

        # Should work immediately
        assert cache.get("key1") == "value"

        # Wait for expiration
        time.sleep(1.5)

        # Should be expired
        assert cache.get("key1") is None

    def test_cache_clear(self):
        """Test clearing cache."""
        from childermass.weather_mcp.client import ResponseCache

        cache = ResponseCache(ttl=10)
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        cache.clear()

        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_cache_missing_key(self):
        """Test retrieving non-existent key."""
        from childermass.weather_mcp.client import ResponseCache

        cache = ResponseCache(ttl=10)
        assert cache.get("nonexistent") is None


# ============================================================================
# Authentication Tests
# ============================================================================


class TestAuthentication:
    """Test authentication functionality."""

    @patch("childermass.weather_mcp.auth.keyring")
    @patch("childermass.weather_mcp.auth.API_KEY_FILE")
    def test_get_api_key_from_keyring(self, mock_file, mock_keyring):
        """Test getting API key from keyring."""
        from childermass.weather_mcp.auth import KEYRING_AVAILABLE, get_api_key

        if not KEYRING_AVAILABLE:
            pytest.skip("Keyring not available")

        mock_keyring.get_password.return_value = "test_api_key_12345678901234567890"

        key = get_api_key()
        assert key == "test_api_key_12345678901234567890"

    @patch("childermass.weather_mcp.auth.keyring")
    @patch("childermass.weather_mcp.auth.API_KEY_FILE")
    def test_get_api_key_from_file_fallback(self, mock_file, mock_keyring):
        """Test getting API key from file when keyring fails."""
        from childermass.weather_mcp.auth import get_api_key

        mock_keyring.get_password.return_value = None
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = "file_api_key_123456789012345678901234\n"

        key = get_api_key()
        assert key == "file_api_key_123456789012345678901234"

    @patch("childermass.weather_mcp.auth.keyring")
    @patch("childermass.weather_mcp.auth.API_KEY_FILE")
    def test_get_api_key_missing(self, mock_file, mock_keyring):
        """Test error when no API key configured."""
        from childermass.weather_mcp.auth import AuthenticationError, get_api_key

        mock_keyring.get_password.return_value = None
        mock_file.exists.return_value = False

        with pytest.raises(AuthenticationError, match="No OpenWeatherMap API key"):
            get_api_key()

    def test_set_api_key_validation(self):
        """Test API key validation during set."""
        from childermass.weather_mcp.auth import set_api_key

        with pytest.raises(ValueError, match="cannot be empty"):
            set_api_key("")

        with pytest.raises(ValueError, match="cannot be empty"):
            set_api_key("   ")


# ============================================================================
# Mock API Tests
# ============================================================================


class TestWeatherClientMocked:
    """Test WeatherClient with mocked API responses."""

    @patch("childermass.weather_mcp.client.requests.Session.get")
    def test_get_current_weather_success(self, mock_get):
        """Test successful current weather request."""
        from childermass.weather_mcp.client import WeatherClient

        # Mock successful API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "main": {
                "temp": 15.5,
                "feels_like": 14.2,
                "temp_min": 12.0,
                "temp_max": 18.0,
                "pressure": 1013,
                "humidity": 72,
            },
            "weather": [
                {
                    "id": 800,
                    "main": "Clear",
                    "description": "clear sky",
                    "icon": "01d",
                }
            ],
            "wind": {"speed": 3.5, "deg": 180},
            "clouds": {"all": 10},
            "visibility": 10000,
            "dt": 1707926400,
            "sys": {"sunrise": 1707895200, "sunset": 1707933600},
            "timezone": 0,
            "name": "London",
        }
        mock_get.return_value = mock_response

        client = WeatherClient(api_key="test_key_12345678901234567890123456")
        weather = client.get_current_weather("London,UK")

        assert weather.temperature == 15.5
        assert weather.location_name == "London"
        assert weather.conditions[0].main == "Clear"

    @patch("childermass.weather_mcp.client.requests.Session.get")
    def test_api_error_401(self, mock_get):
        """Test API 401 error handling."""
        from childermass.weather_mcp.client import WeatherClient

        # Mock 401 response
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = Exception("401 Unauthorized")
        mock_get.return_value = mock_response

        client = WeatherClient(api_key="invalid_key")

        with pytest.raises(SecurityError, match="Invalid API key"):
            client.get_current_weather("London,UK")

    @patch("childermass.weather_mcp.client.requests.Session.get")
    def test_api_error_404(self, mock_get):
        """Test API 404 error handling."""
        from childermass.weather_mcp.client import WeatherClient

        # Mock 404 response
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = Exception("404 Not Found")
        mock_get.return_value = mock_response

        client = WeatherClient(api_key="test_key_12345678901234567890123456")

        with pytest.raises(SecurityError, match="Location not found"):
            client.get_current_weather("InvalidCity123")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
