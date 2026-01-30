"""
Security utilities for the Rootly MCP Server.

This module provides security-related functionality including:
- Secure token handling
- HTTPS enforcement
- Input sanitization
- Rate limiting
- Security validation
"""

import os
import re
import time
from collections import defaultdict
from functools import wraps
from threading import Lock
from typing import Any
from urllib.parse import urlparse

from .exceptions import (
    RootlyConfigurationError,
    RootlyRateLimitError,
    RootlyValidationError,
)

# Token validation pattern (Bearer tokens typically start with a prefix)
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,}$")

# URL validation patterns
HTTPS_PATTERN = re.compile(r"^https://")
VALID_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# SQL injection patterns to block
SQL_INJECTION_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)",
    r"(--|;|\/\*|\*\/|xp_|sp_)",
    r"(\bOR\b.*=.*)",
    r"(\bAND\b.*=.*)",
]

# XSS patterns to block
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<iframe[^>]*>",
]


class RateLimiter:
    """
    Token bucket rate limiter for API requests.

    Implements a sliding window rate limiter to prevent API abuse.
    """

    def __init__(self, max_requests: int = 100, time_window: int = 60):
        """
        Initialize the rate limiter.

        Args:
            max_requests: Maximum number of requests allowed in the time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self._requests = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, identifier: str) -> tuple[bool, int | None]:
        """
        Check if a request is allowed for the given identifier.

        Args:
            identifier: Unique identifier for the client (e.g., IP address, user ID)

        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        with self._lock:
            current_time = time.time()
            window_start = current_time - self.time_window

            # Clean up old requests
            self._requests[identifier] = [
                req_time for req_time in self._requests[identifier] if req_time > window_start
            ]

            # Check if limit is exceeded
            if len(self._requests[identifier]) >= self.max_requests:
                # Calculate retry_after based on oldest request
                oldest_request = min(self._requests[identifier])
                retry_after = int(oldest_request + self.time_window - current_time) + 1
                return False, retry_after

            # Allow the request and record it
            self._requests[identifier].append(current_time)
            return True, None

    def reset(self, identifier: str) -> None:
        """Reset the rate limit for a specific identifier."""
        with self._lock:
            self._requests.pop(identifier, None)


# Global rate limiter instance
_rate_limiter = RateLimiter(max_requests=100, time_window=60)


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    return _rate_limiter


def rate_limit(identifier_func=None):
    """
    Decorator to apply rate limiting to a function.

    Args:
        identifier_func: Optional function to extract identifier from function args.
                        If None, uses "default" as identifier.
    """

    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            identifier = identifier_func(*args, **kwargs) if identifier_func else "default"
            allowed, retry_after = _rate_limiter.is_allowed(identifier)

            if not allowed:
                raise RootlyRateLimitError(
                    f"Rate limit exceeded. Try again in {retry_after} seconds.",
                    retry_after=retry_after,
                )

            return await func(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            identifier = identifier_func(*args, **kwargs) if identifier_func else "default"
            allowed, retry_after = _rate_limiter.is_allowed(identifier)

            if not allowed:
                raise RootlyRateLimitError(
                    f"Rate limit exceeded. Try again in {retry_after} seconds.",
                    retry_after=retry_after,
                )

            return func(*args, **kwargs)

        # Return appropriate wrapper based on function type
        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def validate_api_token(token: str | None) -> str:
    """
    Validate that an API token is properly formatted and not empty.

    Args:
        token: The API token to validate

    Returns:
        The validated token

    Raises:
        RootlyConfigurationError: If token is missing or invalid
    """
    if not token:
        raise RootlyConfigurationError(
            "API token is required but not provided. Set the ROOTLY_API_TOKEN environment variable."
        )

    token = token.strip()

    if len(token) < 20:
        raise RootlyConfigurationError(
            "API token appears to be invalid (too short). Please check your ROOTLY_API_TOKEN value."
        )

    # Don't log the actual token value for security
    return token


def get_api_token_from_env() -> str:
    """
    Get and validate the API token from environment variables.

    Returns:
        The validated API token

    Raises:
        RootlyConfigurationError: If token is missing or invalid
    """
    token = os.getenv("ROOTLY_API_TOKEN")
    return validate_api_token(token)


def enforce_https(url: str) -> str:
    """
    Ensure that a URL uses HTTPS.

    Args:
        url: The URL to validate

    Returns:
        The validated HTTPS URL

    Raises:
        RootlyValidationError: If URL doesn't use HTTPS
    """
    if not url:
        raise RootlyValidationError("URL cannot be empty")

    parsed = urlparse(url)

    if not parsed.scheme:
        # Assume HTTPS if no scheme provided
        return f"https://{url}"

    if parsed.scheme != "https":
        raise RootlyValidationError(
            f"Only HTTPS URLs are allowed for security reasons. Got: {parsed.scheme}://"
        )

    return url


def validate_url(url: str, allowed_domains: list[str] | None = None) -> str:
    """
    Validate a URL for security.

    Args:
        url: The URL to validate
        allowed_domains: Optional list of allowed domains

    Returns:
        The validated URL

    Raises:
        RootlyValidationError: If URL is invalid or not allowed
    """
    if not url:
        raise RootlyValidationError("URL cannot be empty")

    # Enforce HTTPS
    url = enforce_https(url)

    parsed = urlparse(url)

    # Validate domain
    if not parsed.netloc:
        raise RootlyValidationError(f"Invalid URL: missing domain in {url}")

    # Check against allowed domains if provided
    if allowed_domains:
        domain_allowed = any(
            parsed.netloc == domain or parsed.netloc.endswith(f".{domain}")
            for domain in allowed_domains
        )
        if not domain_allowed:
            raise RootlyValidationError(f"Domain {parsed.netloc} is not in the allowed list")

    return url


def sanitize_input(value: Any, max_length: int = 10000) -> Any:
    """
    Sanitize user input to prevent injection attacks.

    Args:
        value: The value to sanitize
        max_length: Maximum allowed length for strings

    Returns:
        The sanitized value

    Raises:
        RootlyValidationError: If input contains malicious patterns
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int | float):
        return value

    if isinstance(value, str):
        # Check length
        if len(value) > max_length:
            raise RootlyValidationError(
                f"Input too long: {len(value)} characters (max: {max_length})"
            )

        # Check for SQL injection patterns
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise RootlyValidationError("Input contains potentially malicious SQL patterns")

        # Check for XSS patterns
        for pattern in XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise RootlyValidationError("Input contains potentially malicious XSS patterns")

        return value

    if isinstance(value, dict):
        return {k: sanitize_input(v, max_length) for k, v in value.items()}

    if isinstance(value, list | tuple):
        return type(value)(sanitize_input(item, max_length) for item in value)

    # For other types, convert to string and sanitize
    return sanitize_input(str(value), max_length)


def sanitize_error_message(error_message: str, max_length: int = 500) -> str:
    """
    Sanitize error messages to prevent information leakage.

    Removes file paths, stack traces, and other sensitive information.

    Args:
        error_message: The error message to sanitize
        max_length: Maximum length for the sanitized message

    Returns:
        The sanitized error message
    """
    if not error_message:
        return "An error occurred"

    # Remove absolute file paths
    error_message = re.sub(r"/[\w/.-]+\.py", "[file]", error_message)
    error_message = re.sub(r"C:\\[\w\\.-]+\.py", "[file]", error_message)

    # Remove line numbers
    error_message = re.sub(r", line \d+", "", error_message)

    # Remove "Traceback" and everything after it
    if "Traceback" in error_message:
        error_message = error_message.split("Traceback")[0].strip()

    # Remove stack trace markers
    error_message = re.sub(r"File \"[^\"]+\"", "", error_message)

    # Truncate if too long
    if len(error_message) > max_length:
        error_message = error_message[:max_length] + "..."

    return error_message.strip() or "An error occurred"


def mask_sensitive_data(
    data: dict[str, Any], sensitive_keys: list[str] | None = None
) -> dict[str, Any]:
    """
    Mask sensitive data in a dictionary for logging.

    Args:
        data: The data dictionary to mask
        sensitive_keys: List of key patterns to mask (case-insensitive)

    Returns:
        Dictionary with sensitive values masked
    """
    if sensitive_keys is None:
        sensitive_keys = ["token", "password", "secret", "api_key", "auth"]

    def should_mask(key: str) -> bool:
        key_lower = key.lower()
        return any(sensitive in key_lower for sensitive in sensitive_keys)

    def mask_value(value: Any) -> Any:
        if isinstance(value, str) and len(value) > 0:
            return "***REDACTED***"
        return value

    masked = {}
    for key, value in data.items():
        if should_mask(key):
            masked[key] = mask_value(value)
        elif isinstance(value, dict):
            masked[key] = mask_sensitive_data(value, sensitive_keys)
        elif isinstance(value, list):
            masked[key] = [
                mask_sensitive_data(item, sensitive_keys) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            masked[key] = value

    return masked
