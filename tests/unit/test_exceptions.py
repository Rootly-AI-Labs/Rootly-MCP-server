"""
Tests for exception handling module.
"""

from rootly_mcp_server.exceptions import (
    RootlyAPIError,
    RootlyAuthenticationError,
    RootlyAuthorizationError,
    RootlyMCPError,
    RootlyRateLimitError,
    RootlyResourceNotFoundError,
    RootlyServerError,
    RootlyTimeoutError,
    RootlyValidationError,
    categorize_exception,
)


class TestExceptions:
    """Test suite for exception classes."""

    def test_base_exception(self):
        """Test base RootlyMCPError."""
        error = RootlyMCPError("test error", details={"key": "value"})
        assert str(error) == "test error"
        assert error.message == "test error"
        assert error.details == {"key": "value"}

    def test_authentication_error(self):
        """Test RootlyAuthenticationError."""
        error = RootlyAuthenticationError("auth failed")
        assert isinstance(error, RootlyMCPError)
        assert "auth failed" in str(error)

    def test_rate_limit_error(self):
        """Test RootlyRateLimitError with retry_after."""
        error = RootlyRateLimitError("rate limit", retry_after=60)
        assert error.retry_after == 60
        assert isinstance(error, RootlyMCPError)

    def test_api_error_with_status_code(self):
        """Test RootlyAPIError with status code."""
        error = RootlyAPIError("api error", status_code=500)
        assert error.status_code == 500
        assert isinstance(error, RootlyMCPError)


class TestCategorizeException:
    """Test suite for exception categorization."""

    def test_categorize_401_error(self):
        """Test categorization of 401 authentication error."""
        exc = Exception("401 unauthorized")
        exc_class, message = categorize_exception(exc)
        assert exc_class == RootlyAuthenticationError
        assert "Authentication failed" in message

    def test_categorize_403_error(self):
        """Test categorization of 403 authorization error."""
        exc = Exception("403 forbidden")
        exc_class, message = categorize_exception(exc)
        assert exc_class == RootlyAuthorizationError
        assert "Authorization failed" in message

    def test_categorize_429_error(self):
        """Test categorization of 429 rate limit error."""
        exc = Exception("429 rate limit exceeded")
        exc_class, message = categorize_exception(exc)
        assert exc_class == RootlyRateLimitError
        assert "Rate limit exceeded" in message

    def test_categorize_404_error(self):
        """Test categorization of 404 not found error."""
        exc = Exception("404 not found")
        exc_class, message = categorize_exception(exc)
        assert exc_class == RootlyResourceNotFoundError
        assert "Resource not found" in message

    def test_categorize_500_error(self):
        """Test categorization of 500 server error."""
        exc = Exception("500 server error")
        exc_class, message = categorize_exception(exc)
        assert exc_class == RootlyServerError
        assert "Server error" in message

    def test_categorize_timeout_error(self):
        """Test categorization of timeout error."""

        class TimeoutError(Exception):
            pass

        exc = TimeoutError("request timeout")
        exc_class, message = categorize_exception(exc)
        assert exc_class == RootlyTimeoutError
        assert "timed out" in message.lower()

    def test_categorize_validation_error(self):
        """Test categorization of validation error."""

        class PydanticError(Exception):
            pass

        exc = PydanticError("field validation failed")
        exc_class, message = categorize_exception(exc)
        assert exc_class == RootlyValidationError
        assert "Validation error" in message

    def test_categorize_generic_error(self):
        """Test categorization of generic error."""
        exc = Exception("something went wrong")
        exc_class, message = categorize_exception(exc)
        assert exc_class == RootlyAPIError
        assert "API error" in message
