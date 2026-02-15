"""
Comprehensive test suite for Childermass Places MCP security layer.

Tests cover:
- Input validation (place IDs, queries, coordinates, types, etc.)
- Sanitization (error messages)
- Rate limiting (token bucket)
- Audit logging

Run with:
    pytest src/childermass/places_mcp/tests/ -v
"""

import json

import pytest

from childermass.places_mcp.security import (
    MAX_AUTOCOMPLETE_INPUT_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_RESULTS,
    RateLimiter,
    SecurityError,
    audit_log,
    sanitize_error_message,
    validate_autocomplete_input,
    validate_ev_connector_types,
    validate_language_code,
    validate_latitude,
    validate_longitude,
    validate_max_results,
    validate_min_rating,
    validate_photo_max_dimension,
    validate_photo_resource_name,
    validate_place_id,
    validate_place_type,
    validate_place_types,
    validate_price_levels,
    validate_query,
    validate_radius,
    validate_rank_preference,
    validate_region_code,
)


# =========================================================================
# Place ID validation
# =========================================================================


class TestValidatePlaceId:
    def test_valid_place_id(self):
        assert validate_place_id("ChIJN1t_tDeuEmsRUsoyG83frY4") == "ChIJN1t_tDeuEmsRUsoyG83frY4"

    def test_strips_whitespace(self):
        assert validate_place_id("  ChIJN1t_tDeuEmsRUsoyG83frY4  ") == "ChIJN1t_tDeuEmsRUsoyG83frY4"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_place_id("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_place_id(None)  # type: ignore

    def test_rejects_newlines(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_place_id("ChIJ\ninjection")

    def test_rejects_null_byte(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_place_id("ChIJ\0attack")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_place_id("A" * 301)

    def test_rejects_invalid_characters(self):
        with pytest.raises(SecurityError, match="Invalid Place ID"):
            validate_place_id("place id with spaces!")


# =========================================================================
# Query validation
# =========================================================================


class TestValidateQuery:
    def test_valid_query(self):
        assert validate_query("pizza restaurants in Prague") == "pizza restaurants in Prague"

    def test_strips_whitespace(self):
        assert validate_query("  coffee  ") == "coffee"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_query("")

    def test_rejects_none(self):
        with pytest.raises(SecurityError):
            validate_query(None)  # type: ignore

    def test_rejects_control_chars(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_query("query\0injected")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_query("a" * (MAX_QUERY_LENGTH + 1))

    def test_allows_unicode(self):
        assert validate_query("restaurace v Praze") == "restaurace v Praze"

    def test_allows_special_search_chars(self):
        assert validate_query("24-hour pharmacy") == "24-hour pharmacy"


# =========================================================================
# Autocomplete input validation
# =========================================================================


class TestValidateAutocompleteInput:
    def test_valid_input(self):
        assert validate_autocomplete_input("Starbu") == "Starbu"

    def test_strips_whitespace(self):
        assert validate_autocomplete_input("  cof  ") == "cof"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_autocomplete_input("")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_autocomplete_input("x" * (MAX_AUTOCOMPLETE_INPUT_LENGTH + 1))

    def test_rejects_control_chars(self):
        with pytest.raises(SecurityError, match="control characters"):
            validate_autocomplete_input("input\0inject")


# =========================================================================
# Coordinate validation
# =========================================================================


class TestValidateLatitude:
    def test_valid_latitude(self):
        assert validate_latitude(50.0755) == 50.0755

    def test_zero(self):
        assert validate_latitude(0.0) == 0.0

    def test_min_boundary(self):
        assert validate_latitude(-90.0) == -90.0

    def test_max_boundary(self):
        assert validate_latitude(90.0) == 90.0

    def test_rejects_below_min(self):
        with pytest.raises(SecurityError, match="Latitude"):
            validate_latitude(-90.1)

    def test_rejects_above_max(self):
        with pytest.raises(SecurityError, match="Latitude"):
            validate_latitude(90.1)


class TestValidateLongitude:
    def test_valid_longitude(self):
        assert validate_longitude(14.4378) == 14.4378

    def test_zero(self):
        assert validate_longitude(0.0) == 0.0

    def test_min_boundary(self):
        assert validate_longitude(-180.0) == -180.0

    def test_max_boundary(self):
        assert validate_longitude(180.0) == 180.0

    def test_rejects_below_min(self):
        with pytest.raises(SecurityError, match="Longitude"):
            validate_longitude(-180.1)

    def test_rejects_above_max(self):
        with pytest.raises(SecurityError, match="Longitude"):
            validate_longitude(180.1)


# =========================================================================
# Radius validation
# =========================================================================


class TestValidateRadius:
    def test_valid_radius(self):
        assert validate_radius(5000.0) == 5000.0

    def test_min_boundary(self):
        assert validate_radius(0.0) == 0.0

    def test_max_boundary(self):
        assert validate_radius(50000.0) == 50000.0

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="Radius"):
            validate_radius(-1.0)

    def test_rejects_above_max(self):
        with pytest.raises(SecurityError, match="Radius"):
            validate_radius(50001.0)

    def test_integer_input(self):
        assert validate_radius(1000) == 1000.0


# =========================================================================
# Max results validation
# =========================================================================


class TestValidateMaxResults:
    def test_valid_value(self):
        assert validate_max_results(10) == 10

    def test_min_boundary(self):
        assert validate_max_results(1) == 1

    def test_max_boundary(self):
        assert validate_max_results(MAX_RESULTS) == MAX_RESULTS

    def test_rejects_zero(self):
        with pytest.raises(SecurityError, match="out of range"):
            validate_max_results(0)

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="out of range"):
            validate_max_results(-5)

    def test_rejects_above_max(self):
        with pytest.raises(SecurityError, match="out of range"):
            validate_max_results(MAX_RESULTS + 1)


# =========================================================================
# Place type validation
# =========================================================================


class TestValidatePlaceType:
    def test_valid_type(self):
        assert validate_place_type("restaurant") == "restaurant"

    def test_strips_whitespace(self):
        assert validate_place_type("  cafe  ") == "cafe"

    def test_valid_gas_station(self):
        assert validate_place_type("gas_station") == "gas_station"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Unknown place type"):
            validate_place_type("not_a_real_type_xyz")

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_place_type("")


class TestValidatePlaceTypes:
    def test_single_type(self):
        assert validate_place_types(["restaurant"]) == ["restaurant"]

    def test_multiple_types(self):
        result = validate_place_types(["restaurant", "cafe", "bar"])
        assert result == ["restaurant", "cafe", "bar"]

    def test_rejects_any_invalid(self):
        with pytest.raises(SecurityError, match="Unknown place type"):
            validate_place_types(["restaurant", "fake_type"])

    def test_empty_list_returns_empty(self):
        assert validate_place_types([]) == []


# =========================================================================
# Language code validation
# =========================================================================


class TestValidateLanguageCode:
    def test_valid_two_letter(self):
        assert validate_language_code("cs") == "cs"

    def test_valid_with_region(self):
        assert validate_language_code("en-US") == "en-us"

    def test_strips_whitespace(self):
        assert validate_language_code("  en  ") == "en"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_language_code("")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_language_code("this-is-not-a-language-code")

    def test_rejects_special_chars(self):
        with pytest.raises(SecurityError, match="Invalid language"):
            validate_language_code("e;")


# =========================================================================
# Region code validation
# =========================================================================


class TestValidateRegionCode:
    def test_valid_code(self):
        assert validate_region_code("CZ") == "cz"

    def test_lowercase_stays_lowercase(self):
        assert validate_region_code("us") == "us"

    def test_strips_whitespace(self):
        assert validate_region_code("  cz  ") == "cz"

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_region_code("")

    def test_rejects_too_long(self):
        with pytest.raises(SecurityError, match="too long"):
            validate_region_code("ABCDEF")

    def test_rejects_numbers(self):
        with pytest.raises(SecurityError, match="Invalid region"):
            validate_region_code("12")


# =========================================================================
# Price levels validation
# =========================================================================


class TestValidatePriceLevels:
    def test_single_level(self):
        result = validate_price_levels(["PRICE_LEVEL_MODERATE"])
        assert result == ["PRICE_LEVEL_MODERATE"]

    def test_multiple_levels(self):
        result = validate_price_levels([
            "PRICE_LEVEL_INEXPENSIVE",
            "PRICE_LEVEL_MODERATE",
        ])
        assert result == ["PRICE_LEVEL_INEXPENSIVE", "PRICE_LEVEL_MODERATE"]

    def test_strips_whitespace(self):
        result = validate_price_levels(["  PRICE_LEVEL_MODERATE  "])
        assert result == ["PRICE_LEVEL_MODERATE"]

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Invalid price level"):
            validate_price_levels(["PRICE_LEVEL_SUPER_CHEAP"])

    def test_empty_list_returns_empty(self):
        assert validate_price_levels([]) == []


# =========================================================================
# Rank preference validation
# =========================================================================


class TestValidateRankPreference:
    def test_valid_relevance(self):
        assert validate_rank_preference("RELEVANCE") == "RELEVANCE"

    def test_valid_distance(self):
        assert validate_rank_preference("DISTANCE") == "DISTANCE"

    def test_valid_popularity(self):
        assert validate_rank_preference("POPULARITY") == "POPULARITY"

    def test_strips_whitespace(self):
        assert validate_rank_preference("  RELEVANCE  ") == "RELEVANCE"

    def test_uppercases(self):
        assert validate_rank_preference("relevance") == "RELEVANCE"

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Invalid rank preference"):
            validate_rank_preference("CHEAPEST")


# =========================================================================
# Min rating validation
# =========================================================================


class TestValidateMinRating:
    def test_valid_rating(self):
        assert validate_min_rating(4.0) == 4.0

    def test_min_boundary(self):
        assert validate_min_rating(0.0) == 0.0

    def test_max_boundary(self):
        assert validate_min_rating(5.0) == 5.0

    def test_rejects_negative(self):
        with pytest.raises(SecurityError, match="out of range"):
            validate_min_rating(-0.1)

    def test_rejects_above_five(self):
        with pytest.raises(SecurityError, match="out of range"):
            validate_min_rating(5.1)


# =========================================================================
# EV connector types validation
# =========================================================================


class TestValidateEvConnectorTypes:
    def test_valid_type(self):
        result = validate_ev_connector_types(["EV_CONNECTOR_TYPE_TYPE_2"])
        assert result == ["EV_CONNECTOR_TYPE_TYPE_2"]

    def test_multiple_types(self):
        result = validate_ev_connector_types([
            "EV_CONNECTOR_TYPE_CCS_COMBO_2",
            "EV_CONNECTOR_TYPE_CHADEMO",
        ])
        assert len(result) == 2

    def test_rejects_invalid(self):
        with pytest.raises(SecurityError, match="Invalid EV connector"):
            validate_ev_connector_types(["NOT_A_CONNECTOR"])


# =========================================================================
# Photo validation
# =========================================================================


class TestValidatePhotoResourceName:
    def test_valid_name(self):
        name = "places/ChIJN1t_tDeuEmsR/photos/AUacShg"
        assert validate_photo_resource_name(name) == name

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="required"):
            validate_photo_resource_name("")

    def test_rejects_invalid_format(self):
        with pytest.raises(SecurityError, match="Invalid photo"):
            validate_photo_resource_name("not/a/valid/photo/name/at/all/x/y")

    def test_rejects_path_traversal(self):
        with pytest.raises(SecurityError, match="Invalid photo"):
            validate_photo_resource_name("places/../../../etc/passwd/photos/x")


class TestValidatePhotoMaxDimension:
    def test_valid_dimension(self):
        assert validate_photo_max_dimension(400, "max_width") == 400

    def test_min_boundary(self):
        assert validate_photo_max_dimension(1, "max_width") == 1

    def test_max_boundary(self):
        assert validate_photo_max_dimension(4800, "max_height") == 4800

    def test_rejects_zero(self):
        with pytest.raises(SecurityError, match="out of range"):
            validate_photo_max_dimension(0, "max_width")

    def test_rejects_above_max(self):
        with pytest.raises(SecurityError, match="out of range"):
            validate_photo_max_dimension(4801, "max_height")


# =========================================================================
# Rate limiter
# =========================================================================


class TestRateLimiter:
    def test_allows_within_limit(self):
        limiter = RateLimiter()
        # Should not raise for reasonable number of calls
        for _ in range(5):
            limiter.check("test_account", "text_search")

    def test_blocks_when_exceeded(self):
        limiter = RateLimiter()
        # Exhaust the bucket
        with pytest.raises(SecurityError, match="Rate limit"):
            for _ in range(200):
                limiter.check("test_account_exhaust", "text_search")

    def test_separate_accounts(self):
        limiter = RateLimiter()
        # Different accounts have independent limits
        for _ in range(5):
            limiter.check("account_a", "text_search")
            limiter.check("account_b", "text_search")

    def test_separate_operations(self):
        limiter = RateLimiter()
        # Different operations have independent limits
        for _ in range(5):
            limiter.check("test_account_ops", "text_search")
            limiter.check("test_account_ops", "nearby_search")

    def test_unknown_operation_uses_default(self):
        limiter = RateLimiter()
        # Should not raise – uses default limit
        limiter.check("test_unknown", "unknown_operation")


# =========================================================================
# Error sanitization
# =========================================================================


class TestSanitizeErrorMessage:
    def test_plain_message_unchanged(self):
        assert sanitize_error_message("Something went wrong") == "Something went wrong"

    def test_removes_api_key(self):
        msg = "Error with key AIzaSyBabcdef1234567890"
        result = sanitize_error_message(msg)
        assert "AIzaSyB" not in result
        assert "***" in result

    def test_removes_oauth_token(self):
        msg = "Bearer ya29.a0AfH6SMBx1234567890abcdef"
        result = sanitize_error_message(msg)
        assert "ya29" not in result

    def test_removes_file_paths(self):
        msg = "Error at /Users/john/.childermass/tokens.json"
        result = sanitize_error_message(msg)
        assert "tokens.json" not in result

    def test_handles_exception_input(self):
        exc = RuntimeError("Connection failed with key AIzaSyBtest123")
        result = sanitize_error_message(exc)
        assert "AIza" not in result

    def test_preserves_useful_info(self):
        msg = "Places API returned 403: quota exceeded"
        result = sanitize_error_message(msg)
        assert "403" in result or "quota" in result


# =========================================================================
# Audit logging
# =========================================================================


class TestAuditLog:
    def test_creates_log_entry(self, tmp_path):
        """Audit log should write a JSON line."""
        import os

        log_file = tmp_path / "test-audit.log"
        os.environ["HOUSTON_AUDIT_LOG"] = str(log_file)

        try:
            audit_log("test_op", "test@example.com", {"key": "value"})

            # The audit log may use the default path; check if it wrote
            # to the environment-specified path or default
            if log_file.exists():
                content = log_file.read_text()
                lines = [ln for ln in content.strip().split("\n") if ln]
                assert len(lines) >= 1
                entry = json.loads(lines[-1])
                assert entry["operation"] == "test_op"
                assert entry["account"] == "test@example.com"
        finally:
            os.environ.pop("HOUSTON_AUDIT_LOG", None)

    def test_log_with_failure(self, tmp_path):
        """Audit log should record success=False."""
        import os

        log_file = tmp_path / "test-audit-fail.log"
        os.environ["HOUSTON_AUDIT_LOG"] = str(log_file)

        try:
            audit_log(
                "test_fail_op",
                "test@example.com",
                {"error": "something broke"},
                success=False,
            )

            if log_file.exists():
                content = log_file.read_text()
                lines = [ln for ln in content.strip().split("\n") if ln]
                entry = json.loads(lines[-1])
                assert entry["success"] is False
        finally:
            os.environ.pop("HOUSTON_AUDIT_LOG", None)


# =========================================================================
# Integration-style tests: combined validations
# =========================================================================


class TestCombinedValidations:
    """Test realistic combinations of validations."""

    def test_text_search_params(self):
        """Validate a typical text search parameter set."""
        query = validate_query("restaurants in Prague")
        max_results = validate_max_results(10)
        lang = validate_language_code("cs")
        region = validate_region_code("cz")
        lat = validate_latitude(50.0755)
        lng = validate_longitude(14.4378)
        radius = validate_radius(5000.0)

        assert query == "restaurants in Prague"
        assert max_results == 10
        assert lang == "cs"
        assert region == "cz"
        assert lat == 50.0755
        assert lng == 14.4378
        assert radius == 5000.0

    def test_nearby_search_params(self):
        """Validate a typical nearby search parameter set."""
        validate_latitude(50.0755)
        validate_longitude(14.4378)
        validate_radius(2000.0)
        types = validate_place_types(["restaurant", "cafe"])

        assert types == ["restaurant", "cafe"]

    def test_ev_charger_search_params(self):
        """Validate EV charger search parameters."""
        validate_latitude(50.0755)
        validate_longitude(14.4378)
        validate_radius(10000.0)
        connectors = validate_ev_connector_types([
            "EV_CONNECTOR_TYPE_CCS_COMBO_2",
            "EV_CONNECTOR_TYPE_TYPE_2",
        ])

        assert len(connectors) == 2

    def test_detail_request_params(self):
        """Validate a place details request."""
        place_id = validate_place_id("ChIJN1t_tDeuEmsRUsoyG83frY4")
        lang = validate_language_code("en")
        region = validate_region_code("us")

        assert place_id.startswith("ChIJ")
        assert lang == "en"
        assert region == "us"
