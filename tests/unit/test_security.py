"""
Tests for security module.
"""

import pytest

from rootly_mcp_server.exceptions import (
    RootlyConfigurationError,
    RootlyValidationError,
)
from rootly_mcp_server.security import (
    RateLimiter,
    enforce_https,
    get_api_token_from_env,
    mask_sensitive_data,
    sanitize_error_message,
    sanitize_input,
    validate_api_token,
    validate_url,
)


class TestRateLimiter:
    """Test suite for RateLimiter."""

    def test_rate_limiter_allows_within_limit(self):
        """Test that requests within limit are allowed."""
        limiter = RateLimiter(max_requests=5, time_window=60)
        identifier = "test_user"

        for _ in range(5):
            allowed, retry_after = limiter.is_allowed(identifier)
            assert allowed is True
            assert retry_after is None

    def test_rate_limiter_blocks_over_limit(self):
        """Test that requests over limit are blocked."""
        limiter = RateLimiter(max_requests=2, time_window=60)
        identifier = "test_user"

        # First 2 should succeed
        assert limiter.is_allowed(identifier)[0] is True
        assert limiter.is_allowed(identifier)[0] is True

        # Third should fail
        allowed, retry_after = limiter.is_allowed(identifier)
        assert allowed is False
        assert retry_after is not None
        assert retry_after > 0

    def test_rate_limiter_reset(self):
        """Test resetting rate limit for an identifier."""
        limiter = RateLimiter(max_requests=1, time_window=60)
        identifier = "test_user"

        limiter.is_allowed(identifier)
        assert limiter.is_allowed(identifier)[0] is False

        limiter.reset(identifier)
        assert limiter.is_allowed(identifier)[0] is True


class TestTokenValidation:
    """Test suite for API token validation."""

    def test_validate_api_token_valid(self):
        """Test validation of valid API token."""
        token = "valid_token_12345678901234567890"
        result = validate_api_token(token)
        assert result == token.strip()

    def test_validate_api_token_empty(self):
        """Test validation of empty token."""
        with pytest.raises(RootlyConfigurationError, match="API token is required"):
            validate_api_token("")

    def test_validate_api_token_none(self):
        """Test validation of None token."""
        with pytest.raises(RootlyConfigurationError, match="API token is required"):
            validate_api_token(None)

    def test_validate_api_token_too_short(self):
        """Test validation of too-short token."""
        with pytest.raises(RootlyConfigurationError, match="too short"):
            validate_api_token("short")

    def test_get_api_token_from_env(self, monkeypatch):
        """Test getting API token from environment."""
        token = "test_token_12345678901234567890"
        monkeypatch.setenv("ROOTLY_API_TOKEN", token)
        result = get_api_token_from_env()
        assert result == token

    def test_get_api_token_from_env_missing(self, monkeypatch):
        """Test getting API token when env var is missing."""
        monkeypatch.delenv("ROOTLY_API_TOKEN", raising=False)
        with pytest.raises(RootlyConfigurationError):
            get_api_token_from_env()


class TestHTTPSEnforcement:
    """Test suite for HTTPS enforcement."""

    def test_enforce_https_valid(self):
        """Test HTTPS URL passes validation."""
        url = "https://api.rootly.com/v1/incidents"
        result = enforce_https(url)
        assert result == url

    def test_enforce_https_adds_https(self):
        """Test that scheme-less URL gets HTTPS added."""
        url = "api.rootly.com/v1/incidents"
        result = enforce_https(url)
        assert result.startswith("https://")

    def test_enforce_https_rejects_http(self):
        """Test that HTTP URLs are rejected."""
        url = "http://api.rootly.com/v1/incidents"
        with pytest.raises(RootlyValidationError, match="Only HTTPS"):
            enforce_https(url)

    def test_enforce_https_empty(self):
        """Test empty URL validation."""
        with pytest.raises(RootlyValidationError, match="cannot be empty"):
            enforce_https("")


class TestURLValidation:
    """Test suite for URL validation."""

    def test_validate_url_valid(self):
        """Test validation of valid URL."""
        url = "https://api.rootly.com/v1/incidents"
        result = validate_url(url, allowed_domains=["rootly.com"])
        assert result == url

    def test_validate_url_allowed_domain(self):
        """Test URL validation with allowed domains."""
        url = "https://api.rootly.com/v1/incidents"
        result = validate_url(url, allowed_domains=["rootly.com", "example.com"])
        assert result == url

    def test_validate_url_not_allowed_domain(self):
        """Test URL validation rejects disallowed domain."""
        url = "https://evil.com/api"
        with pytest.raises(RootlyValidationError, match="not in the allowed list"):
            validate_url(url, allowed_domains=["rootly.com"])


class TestInputSanitization:
    """Test suite for input sanitization."""

    def test_sanitize_input_string(self):
        """Test sanitizing clean string."""
        value = "clean string"
        result = sanitize_input(value)
        assert result == value

    def test_sanitize_input_sql_injection(self):
        """Test detecting SQL injection patterns."""
        malicious = "'; DROP TABLE users; --"
        with pytest.raises(RootlyValidationError, match="SQL patterns"):
            sanitize_input(malicious)

    def test_sanitize_input_xss(self):
        """Test detecting XSS patterns."""
        malicious = "<iframe src='evil.com'></iframe>"
        with pytest.raises(RootlyValidationError, match="XSS patterns"):
            sanitize_input(malicious)

    def test_sanitize_input_too_long(self):
        """Test detecting too-long input."""
        long_string = "a" * 10001
        with pytest.raises(RootlyValidationError, match="too long"):
            sanitize_input(long_string, max_length=10000)

    def test_sanitize_input_dict(self):
        """Test sanitizing dictionary."""
        data = {"key1": "value1", "key2": "value2"}
        result = sanitize_input(data)
        assert result == data

    def test_sanitize_input_list(self):
        """Test sanitizing list."""
        data = ["item1", "item2"]
        result = sanitize_input(data)
        assert result == data

    def test_sanitize_input_none(self):
        """Test sanitizing None."""
        result = sanitize_input(None)
        assert result is None

    def test_sanitize_input_numbers(self):
        """Test sanitizing numbers."""
        assert sanitize_input(42) == 42
        assert sanitize_input(3.14) == 3.14


class TestErrorMessageSanitization:
    """Test suite for error message sanitization."""

    def test_sanitize_error_message_removes_paths(self):
        """Test removing file paths from error messages."""
        message = "Error in /home/user/project/file.py at line 42"
        result = sanitize_error_message(message)
        assert "/home/user" not in result
        assert "[file]" in result

    def test_sanitize_error_message_removes_traceback(self):
        """Test removing traceback from error messages."""
        message = "Error occurred\nTraceback (most recent call last):\n  File..."
        result = sanitize_error_message(message)
        assert "Traceback" not in result

    def test_sanitize_error_message_truncates(self):
        """Test truncating long error messages."""
        long_message = "Error: " + "a" * 1000
        result = sanitize_error_message(long_message, max_length=100)
        assert len(result) <= 103  # 100 + "..."

    def test_sanitize_error_message_empty(self):
        """Test sanitizing empty error message."""
        result = sanitize_error_message("")
        assert result == "An error occurred"


class TestMaskSensitiveData:
    """Test suite for masking sensitive data."""

    def test_mask_sensitive_data_token(self):
        """Test masking API token."""
        data = {"api_token": "secret123", "user": "john"}
        result = mask_sensitive_data(data)
        assert result["api_token"] == "***REDACTED***"
        assert result["user"] == "john"

    def test_mask_sensitive_data_password(self):
        """Test masking password."""
        data = {"password": "secret", "email": "test@example.com"}
        result = mask_sensitive_data(data)
        assert result["password"] == "***REDACTED***"
        assert result["email"] == "test@example.com"

    def test_mask_sensitive_data_nested(self):
        """Test masking in nested dictionaries."""
        data = {"user": {"username": "john", "api_key": "secret123"}}
        result = mask_sensitive_data(data)
        assert result["user"]["api_key"] == "***REDACTED***"
        assert result["user"]["username"] == "john"

    def test_mask_sensitive_data_list(self):
        """Test masking in lists."""
        data = {"users": [{"name": "john", "token": "secret"}]}
        result = mask_sensitive_data(data)
        assert result["users"][0]["token"] == "***REDACTED***"
        assert result["users"][0]["name"] == "john"

    def test_mask_sensitive_data_custom_keys(self):
        """Test masking with custom sensitive keys."""
        data = {"credit_card": "1234-5678-9012-3456"}
        result = mask_sensitive_data(data, sensitive_keys=["credit"])
        assert result["credit_card"] == "***REDACTED***"
