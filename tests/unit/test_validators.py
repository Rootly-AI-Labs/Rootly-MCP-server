"""
Tests for validators module.
"""

import pytest

from rootly_mcp_server.exceptions import RootlyValidationError
from rootly_mcp_server.validators import (
    validate_dict,
    validate_enum,
    validate_page_params,
    validate_positive_integer,
    validate_string,
)


class TestPositiveIntegerValidation:
    """Test suite for positive integer validation."""

    def test_valid_positive_integer(self):
        """Test validation of valid positive integer."""
        result = validate_positive_integer(42, "count")
        assert result == 42

    def test_zero_fails_by_default(self):
        """Test that zero fails with default min_value=1."""
        with pytest.raises(RootlyValidationError, match="must be >= 1"):
            validate_positive_integer(0, "count")

    def test_negative_fails(self):
        """Test that negative integers fail."""
        with pytest.raises(RootlyValidationError, match="must be >= 1"):
            validate_positive_integer(-1, "count")

    def test_custom_min_value(self):
        """Test validation with custom min_value."""
        result = validate_positive_integer(10, "count", min_value=10)
        assert result == 10

        with pytest.raises(RootlyValidationError, match="must be >= 10"):
            validate_positive_integer(9, "count", min_value=10)

    def test_non_integer_fails(self):
        """Test that non-integers fail."""
        with pytest.raises(RootlyValidationError, match="must be an integer"):
            validate_positive_integer("42", "count")  # type: ignore[arg-type]


class TestStringValidation:
    """Test suite for string validation."""

    def test_valid_string(self):
        """Test validation of valid string."""
        result = validate_string("hello", "name")
        assert result == "hello"

    def test_min_length(self):
        """Test minimum length validation."""
        with pytest.raises(RootlyValidationError, match="at least 5 characters"):
            validate_string("hi", "name", min_length=5)

    def test_max_length(self):
        """Test maximum length validation."""
        with pytest.raises(RootlyValidationError, match="at most 5 characters"):
            validate_string("hello world", "name", max_length=5)

    def test_pattern_validation(self):
        """Test pattern validation."""
        result = validate_string("abc123", "code", pattern=r"^[a-z0-9]+$")
        assert result == "abc123"

        with pytest.raises(RootlyValidationError, match="does not match"):
            validate_string("ABC-123", "code", pattern=r"^[a-z0-9]+$")

    def test_non_string_fails(self):
        """Test that non-strings fail."""
        with pytest.raises(RootlyValidationError, match="must be a string"):
            validate_string(42, "name")  # type: ignore[arg-type]


class TestDictValidation:
    """Test suite for dict validation."""

    def test_valid_dict(self):
        """Test validation of valid dict."""
        data = {"key": "value"}
        result = validate_dict(data, "config")
        assert result == data

    def test_required_keys(self):
        """Test required keys validation."""
        data = {"key1": "value1", "key2": "value2"}
        result = validate_dict(data, "config", required_keys=["key1", "key2"])
        assert result == data

    def test_missing_required_keys(self):
        """Test missing required keys."""
        data = {"key1": "value1"}
        with pytest.raises(RootlyValidationError, match="missing required keys: key2"):
            validate_dict(data, "config", required_keys=["key1", "key2"])

    def test_non_dict_fails(self):
        """Test that non-dicts fail."""
        with pytest.raises(RootlyValidationError, match="must be a dict"):
            validate_dict("not a dict", "config")  # type: ignore[arg-type]


class TestEnumValidation:
    """Test suite for enum validation."""

    def test_valid_enum_value(self):
        """Test validation of valid enum value."""
        result = validate_enum("apple", "fruit", ["apple", "banana", "orange"])
        assert result == "apple"

    def test_invalid_enum_value(self):
        """Test invalid enum value."""
        with pytest.raises(RootlyValidationError, match="must be one of"):
            validate_enum("grape", "fruit", ["apple", "banana", "orange"])


class TestPageParamsValidation:
    """Test suite for page params validation."""

    def test_valid_page_params(self):
        """Test validation of valid page params."""
        page_size, page_number = validate_page_params(10, 1)
        assert page_size == 10
        assert page_number == 1

    def test_page_size_zero_fails(self):
        """Test that page_size=0 fails."""
        with pytest.raises(RootlyValidationError):
            validate_page_params(0, 1)

    def test_page_number_zero_allowed(self):
        """Test that page_number=0 is allowed (means all pages)."""
        page_size, page_number = validate_page_params(10, 0)
        assert page_size == 10
        assert page_number == 0

    def test_page_size_too_large(self):
        """Test that page_size>100 fails."""
        with pytest.raises(RootlyValidationError, match="cannot exceed 100"):
            validate_page_params(101, 1)

    def test_negative_values_fail(self):
        """Test that negative values fail."""
        with pytest.raises(RootlyValidationError):
            validate_page_params(-1, 1)

        with pytest.raises(RootlyValidationError):
            validate_page_params(10, -1)
