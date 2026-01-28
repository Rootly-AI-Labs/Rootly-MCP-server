"""
Shared pytest fixtures and configuration for Rootly MCP Server tests.

This module provides fixtures for:
- Token management (secure API token access)
- Test environment detection
- Common test utilities
- Mock configurations
"""

import os
from typing import Any
from unittest.mock import Mock, patch

import pytest


@pytest.fixture(scope="session")
def api_token() -> str:
    """
    Provide API token for testing.

    Skips tests if token is not available to prevent failures
    in environments without proper token configuration.
    """
    token = os.getenv("ROOTLY_API_TOKEN")
    if not token:
        pytest.skip("ROOTLY_API_TOKEN not set - skipping API tests")
    return token  # pytest.skip() never returns, so this is always a string


@pytest.fixture(scope="session")
def test_environment() -> dict[str, Any]:
    """
    Provide information about the current test environment.

    Returns:
        Dict with environment details:
        - has_token: Whether API token is available
        - is_ci: Whether running in CI environment
        - github_ref: Git reference (for CI)
    """
    return {
        "has_token": bool(os.getenv("ROOTLY_API_TOKEN")),
        "is_ci": os.getenv("CI") == "true",
        "github_ref": os.getenv("GITHUB_REF", ""),
        "github_actor": os.getenv("GITHUB_ACTOR", ""),
    }


@pytest.fixture
def mock_api_response():
    """
    Provide a mock API response for testing without real API calls.

    Returns a function that creates mock responses with common structure.
    """

    def create_response(
        data: list | None = None, meta: dict | None = None, status_code: int = 200
    ) -> dict[str, Any]:
        if data is None:
            data = []
        if meta is None:
            meta = {"total": len(data), "page": 1}

        return {"data": data, "meta": meta, "status_code": status_code}

    return create_response


@pytest.fixture
def mock_incident_data():
    """
    Provide sample incident data for testing.

    Returns realistic incident data structure matching Rootly API format.
    """
    return [
        {
            "id": "1",
            "type": "incidents",
            "attributes": {
                "title": "Database connection timeout",
                "summary": "Users experiencing slow response times",
                "status": "investigating",
                "severity": "high",
                "created_at": "2025-08-21T10:00:00Z",
            },
        },
        {
            "id": "2",
            "type": "incidents",
            "attributes": {
                "title": "API rate limiting activated",
                "summary": "High traffic causing rate limits",
                "status": "resolved",
                "severity": "medium",
                "created_at": "2025-08-21T09:30:00Z",
            },
        },
    ]


@pytest.fixture
def mock_server_config():
    """
    Provide mock server configuration for testing.

    Returns configuration that doesn't require external dependencies.
    """
    return {
        "name": "TestServer",
        "hosted": False,
        "swagger_path": None,
        "api_base": "https://api.rootly.com/v1",
    }


@pytest.fixture
def mock_httpx_client():
    """
    Provide a mock httpx client for testing HTTP interactions.
    """
    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = Mock()
        mock_client.return_value = mock_instance

        # Configure default responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [], "meta": {"total": 0}}
        mock_instance.get.return_value = mock_response
        mock_instance.post.return_value = mock_response

        yield mock_instance


@pytest.fixture
def mock_environment_token():
    """
    Temporarily set environment token for testing.

    Use this fixture when you need to test token loading behavior.
    """
    test_token = "rootly_test_token_123456789"
    with patch.dict(os.environ, {"ROOTLY_API_TOKEN": test_token}):
        yield test_token


@pytest.fixture
def skip_if_no_token():
    """
    Skip test if no API token is available.

    Use as a fixture in tests that absolutely require an API token.
    """
    if not os.getenv("ROOTLY_API_TOKEN"):
        pytest.skip("API token required for this test")


# Markers for test categorization
pytestmark = pytest.mark.asyncio  # Default async support for all tests
