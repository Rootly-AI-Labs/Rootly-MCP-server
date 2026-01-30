"""
Input validation utilities for the Rootly MCP Server.

This module provides validation functions for API inputs, parameters,
and data structures.
"""

from typing import Any

from .exceptions import RootlyValidationError


def validate_positive_integer(value: int, field_name: str, min_value: int = 1) -> int:
    """
    Validate that a value is a positive integer.

    Args:
        value: The value to validate
        field_name: Name of the field for error messages
        min_value: Minimum allowed value

    Returns:
        The validated value

    Raises:
        RootlyValidationError: If validation fails
    """
    if not isinstance(value, int):
        raise RootlyValidationError(f"{field_name} must be an integer, got {type(value).__name__}")

    if value < min_value:
        raise RootlyValidationError(f"{field_name} must be >= {min_value}, got {value}")

    return value


def validate_string(
    value: str,
    field_name: str,
    min_length: int = 0,
    max_length: int | None = None,
    pattern: str | None = None,
) -> str:
    """
    Validate a string value.

    Args:
        value: The string to validate
        field_name: Name of the field for error messages
        min_length: Minimum allowed length
        max_length: Maximum allowed length
        pattern: Optional regex pattern to match

    Returns:
        The validated string

    Raises:
        RootlyValidationError: If validation fails
    """
    if not isinstance(value, str):
        raise RootlyValidationError(f"{field_name} must be a string, got {type(value).__name__}")

    if len(value) < min_length:
        raise RootlyValidationError(f"{field_name} must be at least {min_length} characters")

    if max_length and len(value) > max_length:
        raise RootlyValidationError(f"{field_name} must be at most {max_length} characters")

    if pattern:
        import re

        if not re.match(pattern, value):
            raise RootlyValidationError(f"{field_name} does not match required pattern")

    return value


def validate_dict(value: dict, field_name: str, required_keys: list[str] | None = None) -> dict:
    """
    Validate a dictionary value.

    Args:
        value: The dict to validate
        field_name: Name of the field for error messages
        required_keys: Optional list of required keys

    Returns:
        The validated dict

    Raises:
        RootlyValidationError: If validation fails
    """
    if not isinstance(value, dict):
        raise RootlyValidationError(f"{field_name} must be a dict, got {type(value).__name__}")

    if required_keys:
        missing_keys = set(required_keys) - set(value.keys())
        if missing_keys:
            raise RootlyValidationError(
                f"{field_name} is missing required keys: {', '.join(missing_keys)}"
            )

    return value


def validate_enum(value: Any, field_name: str, allowed_values: list[Any]) -> Any:
    """
    Validate that a value is one of the allowed values.

    Args:
        value: The value to validate
        field_name: Name of the field for error messages
        allowed_values: List of allowed values

    Returns:
        The validated value

    Raises:
        RootlyValidationError: If validation fails
    """
    if value not in allowed_values:
        raise RootlyValidationError(f"{field_name} must be one of {allowed_values}, got {value}")

    return value


def validate_page_params(page_size: int, page_number: int) -> tuple[int, int]:
    """
    Validate pagination parameters.

    Args:
        page_size: Number of items per page
        page_number: Page number (0 for all, 1+ for specific page)

    Returns:
        Tuple of validated (page_size, page_number)

    Raises:
        RootlyValidationError: If validation fails
    """
    page_size = validate_positive_integer(page_size, "page_size", min_value=1)
    page_number = validate_positive_integer(page_number, "page_number", min_value=0)

    if page_size > 100:
        raise RootlyValidationError("page_size cannot exceed 100")

    return page_size, page_number
