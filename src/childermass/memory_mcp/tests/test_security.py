"""
Tests for memory_mcp security module.

Covers all validators, sanitizers, rate limiter, and audit logging.
"""

import pytest

from childermass.memory_mcp.security import (
    MAX_CONTENT_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_TAG_LENGTH,
    MAX_TAGS_COUNT,
    MAX_URL_LENGTH,
    VALID_CATEGORIES,
    VALID_SECTORS,
    RateLimiter,
    SecurityError,
    audit_log,
    sanitize_error_message,
    validate_category,
    validate_github_repo,
    validate_limit,
    validate_memory_content,
    validate_memory_id,
    validate_predicate,
    validate_query,
    validate_salience_boost,
    validate_sector,
    validate_subject,
    validate_tags,
    validate_temporal_date,
    validate_url,
)


# ===========================================================================
# validate_memory_content
# ===========================================================================


class TestValidateMemoryContent:
    def test_valid_content(self):
        assert validate_memory_content("User prefers 21°C") == "User prefers 21°C"

    def test_strips_whitespace(self):
        assert validate_memory_content("  hello  ") == "hello"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="[Cc]ontent.*required|[Cc]ontent.*empty"):
            validate_memory_content("")

    def test_none_raises(self):
        with pytest.raises(SecurityError):
            validate_memory_content(None)

    def test_too_long_raises(self):
        with pytest.raises(SecurityError, match="[Cc]ontent.*long|[Cc]ontent.*exceed"):
            validate_memory_content("x" * (MAX_CONTENT_LENGTH + 1))

    def test_max_length_ok(self):
        content = "x" * MAX_CONTENT_LENGTH
        assert validate_memory_content(content) == content

    def test_multiline_ok(self):
        content = "Line 1\nLine 2\nLine 3"
        assert validate_memory_content(content) == content


# ===========================================================================
# validate_query
# ===========================================================================


class TestValidateQuery:
    def test_valid_query(self):
        assert validate_query("bedroom temperature") == "bedroom temperature"

    def test_strips_whitespace(self):
        assert validate_query("  query  ") == "query"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="[Qq]uery.*required|[Qq]uery.*empty"):
            validate_query("")

    def test_none_raises(self):
        with pytest.raises(SecurityError):
            validate_query(None)

    def test_too_long_raises(self):
        with pytest.raises(SecurityError, match="[Qq]uery.*long|[Qq]uery.*exceed"):
            validate_query("x" * (MAX_QUERY_LENGTH + 1))


# ===========================================================================
# validate_memory_id
# ===========================================================================


class TestValidateMemoryId:
    def test_valid_id(self):
        assert validate_memory_id("abc-123") == "abc-123"

    def test_uuid_format(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_memory_id(uuid) == uuid

    def test_strips_whitespace(self):
        assert validate_memory_id("  id123  ") == "id123"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="[Mm]emory.*[Ii][Dd].*required|[Ii][Dd].*empty"):
            validate_memory_id("")

    def test_none_raises(self):
        with pytest.raises(SecurityError):
            validate_memory_id(None)


# ===========================================================================
# validate_tags
# ===========================================================================


class TestValidateTags:
    def test_valid_tags(self):
        result = validate_tags(["bedroom", "temperature"])
        assert result == ["bedroom", "temperature"]

    def test_none_returns_empty(self):
        assert validate_tags(None) == []

    def test_empty_list_ok(self):
        assert validate_tags([]) == []

    def test_strips_whitespace(self):
        assert validate_tags(["  hello  ", "  world  "]) == ["hello", "world"]

    def test_filters_empty_strings(self):
        result = validate_tags(["hello", "", "  ", "world"])
        assert result == ["hello", "world"]

    def test_too_many_raises(self):
        tags = [f"tag{i}" for i in range(MAX_TAGS_COUNT + 1)]
        with pytest.raises(SecurityError, match="[Tt]ag"):
            validate_tags(tags)

    def test_tag_too_long_raises(self):
        with pytest.raises(SecurityError, match="[Tt]ag.*long|[Tt]ag.*exceed"):
            validate_tags(["x" * (MAX_TAG_LENGTH + 1)])


# ===========================================================================
# validate_sector
# ===========================================================================


class TestValidateSector:
    @pytest.mark.parametrize("sector", VALID_SECTORS)
    def test_valid_sectors(self, sector):
        assert validate_sector(sector) == sector

    def test_case_insensitive(self):
        assert validate_sector("EPISODIC") == "episodic"

    def test_strips_whitespace(self):
        assert validate_sector("  semantic  ") == "semantic"

    def test_invalid_raises(self):
        with pytest.raises(SecurityError, match="[Ss]ector"):
            validate_sector("invalid")

    def test_empty_raises(self):
        with pytest.raises(SecurityError):
            validate_sector("")


# ===========================================================================
# validate_category
# ===========================================================================


class TestValidateCategory:
    @pytest.mark.parametrize("category", VALID_CATEGORIES)
    def test_valid_categories(self, category):
        assert validate_category(category) == category

    def test_case_insensitive(self):
        assert validate_category("PREFERENCE") == "preference"

    def test_strips_whitespace(self):
        assert validate_category("  routine  ") == "routine"

    def test_invalid_raises(self):
        with pytest.raises(SecurityError, match="[Cc]ategory"):
            validate_category("invalid")


# ===========================================================================
# validate_limit
# ===========================================================================


class TestValidateLimit:
    def test_valid_limit(self):
        assert validate_limit(10) == 10

    def test_min_limit(self):
        assert validate_limit(1) == 1

    def test_max_limit(self):
        assert validate_limit(100) == 100

    def test_below_min_raises(self):
        with pytest.raises(SecurityError, match="[Ll]imit"):
            validate_limit(0)

    def test_above_max_raises(self):
        with pytest.raises(SecurityError, match="[Ll]imit"):
            validate_limit(101)

    def test_negative_raises(self):
        with pytest.raises(SecurityError):
            validate_limit(-5)


# ===========================================================================
# validate_temporal_date
# ===========================================================================


class TestValidateTemporalDate:
    def test_valid_date(self):
        assert validate_temporal_date("2025-01-15") == "2025-01-15"

    def test_strips_whitespace(self):
        assert validate_temporal_date("  2025-06-01  ") == "2025-06-01"

    def test_invalid_format_raises(self):
        with pytest.raises(SecurityError, match="[Dd]ate"):
            validate_temporal_date("15-01-2025")

    def test_invalid_date_raises(self):
        with pytest.raises(SecurityError, match="[Dd]ate"):
            validate_temporal_date("not-a-date")

    def test_empty_raises(self):
        with pytest.raises(SecurityError):
            validate_temporal_date("")


# ===========================================================================
# validate_subject
# ===========================================================================


class TestValidateSubject:
    def test_valid_subject(self):
        assert validate_subject("bedroom") == "bedroom"

    def test_strips_whitespace(self):
        assert validate_subject("  user  ") == "user"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="[Ss]ubject.*required|[Ss]ubject.*empty"):
            validate_subject("")

    def test_none_raises(self):
        with pytest.raises(SecurityError):
            validate_subject(None)


# ===========================================================================
# validate_predicate
# ===========================================================================


class TestValidatePredicate:
    def test_valid_predicate(self):
        assert validate_predicate("preferred_temperature") == "preferred_temperature"

    def test_strips_whitespace(self):
        assert validate_predicate("  wake_up_time  ") == "wake_up_time"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="[Pp]redicate.*required|[Pp]redicate.*empty"):
            validate_predicate("")


# ===========================================================================
# sanitize_error_message
# ===========================================================================


class TestSanitizeErrorMessage:
    def test_generic_exception(self):
        result = sanitize_error_message(Exception("something failed"))
        assert "something failed" in result

    def test_strips_file_paths(self):
        err = Exception("Error at /Users/admin/.childermass/data.sqlite: bad query")
        result = sanitize_error_message(err)
        assert "/Users/" not in result

    def test_strips_sql(self):
        err = Exception("sqlite3.OperationalError: SELECT * FROM memories WHERE id=1")
        result = sanitize_error_message(err)
        assert "SELECT" not in result

    def test_strips_api_keys(self):
        err = Exception("API key: sk-abc123def456 is invalid")  # gitleaks:allow
        result = sanitize_error_message(err)
        assert "sk-abc123def456" not in result


# ===========================================================================
# RateLimiter
# ===========================================================================


class TestRateLimiter:
    def test_allows_normal_usage(self):
        limiter = RateLimiter()
        # Should not raise for a few calls
        for _ in range(5):
            limiter.check("recall")

    def test_blocks_burst(self):
        limiter = RateLimiter()
        # Exhaust the "forget" bucket (capacity 10)
        for _ in range(10):
            limiter.check("forget")
        with pytest.raises(SecurityError, match="[Rr]ate"):
            limiter.check("forget")

    def test_default_for_unknown_operation(self):
        limiter = RateLimiter()
        limiter.check("unknown_op")  # Falls back to "recall" limits


# ===========================================================================
# audit_log
# ===========================================================================


class TestAuditLog:
    def test_writes_to_file(self, tmp_path, monkeypatch):
        """Test that audit_log writes JSON to the audit file."""
        import childermass.memory_mcp.security as sec

        fake_log = tmp_path / "audit.log"
        monkeypatch.setattr(sec, "AUDIT_LOG_FILE", fake_log)
        monkeypatch.setattr(sec, "CONFIG_DIR", tmp_path)

        audit_log("test_action", "Test message")

        content = fake_log.read_text()
        assert "test_action" in content
        assert "Test message" in content

    def test_writes_with_metadata(self, tmp_path, monkeypatch):
        """Test that audit_log includes metadata."""
        import childermass.memory_mcp.security as sec

        fake_log = tmp_path / "audit.log"
        monkeypatch.setattr(sec, "AUDIT_LOG_FILE", fake_log)
        monkeypatch.setattr(sec, "CONFIG_DIR", tmp_path)

        audit_log("store", "Stored memory", {"id": "123"})

        content = fake_log.read_text()
        assert "store" in content
        assert "123" in content


# ===========================================================================
# validate_url
# ===========================================================================


class TestValidateUrl:
    def test_valid_https(self):
        assert validate_url("https://example.com") == "https://example.com"

    def test_valid_http(self):
        assert validate_url("http://example.com/page") == "http://example.com/page"

    def test_strips_whitespace(self):
        assert validate_url("  https://example.com  ") == "https://example.com"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="URL.*empty|URL.*non-empty"):
            validate_url("")

    def test_none_raises(self):
        with pytest.raises(SecurityError):
            validate_url(None)

    def test_no_scheme_raises(self):
        with pytest.raises(SecurityError, match="http"):
            validate_url("example.com")

    def test_ftp_raises(self):
        with pytest.raises(SecurityError, match="http"):
            validate_url("ftp://example.com")

    def test_too_long_raises(self):
        with pytest.raises(SecurityError, match="URL.*long"):
            validate_url("https://example.com/" + "x" * MAX_URL_LENGTH)

    def test_localhost_blocked(self):
        with pytest.raises(SecurityError, match="private"):
            validate_url("http://localhost:8080/api")

    def test_private_ip_127_blocked(self):
        with pytest.raises(SecurityError, match="private"):
            validate_url("http://127.0.0.1:3000")

    def test_private_ip_192_blocked(self):
        with pytest.raises(SecurityError, match="private"):
            validate_url("http://192.168.1.1/admin")

    def test_private_ip_10_blocked(self):
        with pytest.raises(SecurityError, match="private"):
            validate_url("http://10.0.0.1/internal")

    def test_private_ip_172_blocked(self):
        with pytest.raises(SecurityError, match="private"):
            validate_url("http://172.16.0.1/secret")

    def test_public_ip_ok(self):
        assert validate_url("https://8.8.8.8") == "https://8.8.8.8"


# ===========================================================================
# validate_github_repo
# ===========================================================================


class TestValidateGithubRepo:
    def test_valid_repo(self):
        assert validate_github_repo("CaviraOSS/OpenMemory") == "CaviraOSS/OpenMemory"

    def test_strips_whitespace(self):
        assert validate_github_repo("  owner/repo  ") == "owner/repo"

    def test_empty_raises(self):
        with pytest.raises(SecurityError, match="[Rr]epository.*empty|[Rr]epository.*non-empty"):
            validate_github_repo("")

    def test_none_raises(self):
        with pytest.raises(SecurityError):
            validate_github_repo(None)

    def test_no_slash_raises(self):
        with pytest.raises(SecurityError, match="[Rr]epository.*format"):
            validate_github_repo("just-repo-name")

    def test_multiple_slashes_raises(self):
        with pytest.raises(SecurityError, match="[Rr]epository.*format"):
            validate_github_repo("owner/repo/extra")

    def test_dots_and_hyphens_ok(self):
        assert validate_github_repo("my-org/my.repo") == "my-org/my.repo"

    def test_too_long_raises(self):
        with pytest.raises(SecurityError, match="[Rr]epository.*long"):
            validate_github_repo("a" * 100 + "/" + "b" * 101)


# ===========================================================================
# validate_salience_boost
# ===========================================================================


class TestValidateSalienceBoost:
    def test_valid_boost(self):
        assert validate_salience_boost(0.1) == 0.1

    def test_min_boost(self):
        assert validate_salience_boost(0.01) == 0.01

    def test_max_boost(self):
        assert validate_salience_boost(0.5) == 0.5

    def test_int_converted_to_float(self):
        # Expects SecurityError because 1 > 0.5
        with pytest.raises(SecurityError, match="[Ss]alience.*large"):
            validate_salience_boost(1)

    def test_too_small_raises(self):
        with pytest.raises(SecurityError, match="[Ss]alience.*small"):
            validate_salience_boost(0.001)

    def test_too_large_raises(self):
        with pytest.raises(SecurityError, match="[Ss]alience.*large"):
            validate_salience_boost(0.6)

    def test_string_raises(self):
        with pytest.raises(SecurityError, match="[Ss]alience.*number"):
            validate_salience_boost("0.1")

    def test_none_raises(self):
        with pytest.raises(SecurityError):
            validate_salience_boost(None)


# ===========================================================================
# RateLimiter — new operations
# ===========================================================================


class TestRateLimiterNewOps:
    def test_reinforce_operation(self):
        limiter = RateLimiter()
        limiter.check("reinforce")  # Should not raise

    def test_ingest_operation(self):
        limiter = RateLimiter()
        limiter.check("ingest")  # Should not raise

    def test_decay_operation(self):
        limiter = RateLimiter()
        limiter.check("decay")  # Should not raise

    def test_decay_burst_blocked(self):
        limiter = RateLimiter()
        # Exhaust the "decay" bucket (capacity 5)
        for _ in range(5):
            limiter.check("decay")
        with pytest.raises(SecurityError, match="[Rr]ate"):
            limiter.check("decay")
