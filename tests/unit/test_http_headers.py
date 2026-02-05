"""
Unit tests for HTTP header handling in AuthenticatedHTTPXClient.

Tests cover:
- Content-Type header override for Rootly JSON-API format
- Header handling when FastMCP passes MCP client headers
- Ensuring correct headers reach the Rootly API
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestAuthenticatedHTTPXClientHeaders:
    """Tests for header handling in AuthenticatedHTTPXClient."""

    @pytest.fixture
    def mock_httpx_client(self):
        """Create a mock httpx.AsyncClient."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_client.request.return_value = mock_response
        return mock_client

    @pytest.mark.asyncio
    async def test_overrides_content_type_from_mcp_client(self, mock_httpx_client):
        """Test that Content-Type is overridden when MCP client sends application/json."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            # Simulate FastMCP passing headers from MCP client request
            # This is what causes the 415 error - MCP client sends application/json
            mcp_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer user-token",
            }

            await client.request("GET", "/v1/teams", headers=mcp_headers)

            # Verify the request was made with correct JSON-API headers
            call_kwargs = mock_httpx_client.request.call_args[1]
            assert call_kwargs["headers"]["Content-Type"] == "application/vnd.api+json"
            assert call_kwargs["headers"]["Accept"] == "application/vnd.api+json"
            # Authorization should be preserved
            assert call_kwargs["headers"]["Authorization"] == "Bearer user-token"

    @pytest.mark.asyncio
    async def test_sets_headers_when_empty_headers_passed(self, mock_httpx_client):
        """Test that headers are set correctly when empty headers dict is passed."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            # FastMCP might pass empty headers
            await client.request("GET", "/v1/incidents", headers={})

            call_kwargs = mock_httpx_client.request.call_args[1]
            assert call_kwargs["headers"]["Content-Type"] == "application/vnd.api+json"
            assert call_kwargs["headers"]["Accept"] == "application/vnd.api+json"

    @pytest.mark.asyncio
    async def test_preserves_other_headers(self, mock_httpx_client):
        """Test that non-content-type headers are preserved."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            custom_headers = {
                "Content-Type": "application/json",  # Should be overridden
                "X-Custom-Header": "custom-value",  # Should be preserved
                "X-Request-ID": "12345",  # Should be preserved
            }

            await client.request("POST", "/v1/incidents", headers=custom_headers)

            call_kwargs = mock_httpx_client.request.call_args[1]
            assert call_kwargs["headers"]["Content-Type"] == "application/vnd.api+json"
            assert call_kwargs["headers"]["X-Custom-Header"] == "custom-value"
            assert call_kwargs["headers"]["X-Request-ID"] == "12345"

    @pytest.mark.asyncio
    async def test_no_headers_kwarg_works(self, mock_httpx_client):
        """Test that requests without headers kwarg still work."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            # Request without headers kwarg (relies on client defaults)
            await client.request("GET", "/v1/users")

            # Should still make the request successfully
            mock_httpx_client.request.assert_called_once()

    @pytest.mark.asyncio
    async def test_none_headers_handled(self, mock_httpx_client):
        """Test that None headers are handled gracefully."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            # FastMCP might pass headers=None
            await client.request("GET", "/v1/schedules", headers=None)

            call_kwargs = mock_httpx_client.request.call_args[1]
            assert call_kwargs["headers"]["Content-Type"] == "application/vnd.api+json"
            assert call_kwargs["headers"]["Accept"] == "application/vnd.api+json"


class TestHTTPMethodsWithHeaders:
    """Test all HTTP methods correctly handle headers."""

    @pytest.fixture
    def mock_httpx_client(self):
        """Create a mock httpx.AsyncClient."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_client.request.return_value = mock_response
        return mock_client

    @pytest.mark.asyncio
    async def test_get_method_headers(self, mock_httpx_client):
        """Test GET method correctly overrides headers."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            await client.get("/v1/teams", headers={"Content-Type": "application/json"})

            call_kwargs = mock_httpx_client.request.call_args[1]
            assert call_kwargs["headers"]["Content-Type"] == "application/vnd.api+json"

    @pytest.mark.asyncio
    async def test_post_method_headers(self, mock_httpx_client):
        """Test POST method correctly overrides headers."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            await client.post(
                "/v1/incidents",
                headers={"Content-Type": "application/json"},
                json={"title": "Test"},
            )

            call_kwargs = mock_httpx_client.request.call_args[1]
            assert call_kwargs["headers"]["Content-Type"] == "application/vnd.api+json"

    @pytest.mark.asyncio
    async def test_patch_method_headers(self, mock_httpx_client):
        """Test PATCH method correctly overrides headers."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            await client.patch(
                "/v1/incidents/123",
                headers={"Content-Type": "application/json"},
                json={"status": "resolved"},
            )

            call_kwargs = mock_httpx_client.request.call_args[1]
            assert call_kwargs["headers"]["Content-Type"] == "application/vnd.api+json"

    @pytest.mark.asyncio
    async def test_delete_method_headers(self, mock_httpx_client):
        """Test DELETE method correctly overrides headers."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            await client.delete("/v1/incidents/123", headers={"Content-Type": "application/json"})

            call_kwargs = mock_httpx_client.request.call_args[1]
            assert call_kwargs["headers"]["Content-Type"] == "application/vnd.api+json"


class TestFastMCPIntegrationScenario:
    """Test scenarios that simulate FastMCP's behavior."""

    @pytest.fixture
    def mock_httpx_client(self):
        """Create a mock httpx.AsyncClient."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [{"id": "1", "type": "teams"}]}
        mock_client.request.return_value = mock_response
        return mock_client

    @pytest.mark.asyncio
    async def test_simulated_fastmcp_listteams_call(self, mock_httpx_client):
        """Simulate the exact scenario that causes 415 error with listTeams."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            # This simulates what FastMCP does:
            # 1. Gets headers from MCP client HTTP request (SSE connection)
            # 2. These headers include Content-Type: application/json
            # 3. Passes them to our client
            mcp_client_headers = {
                "host": "mcp.rootly.com",
                "content-type": "application/json",  # From MCP client
                "accept": "text/event-stream",
                "authorization": "Bearer user-api-token",
            }

            # Make request like FastMCP would
            await client.request(
                method="GET",
                url="/v1/teams",
                params={"page[size]": 10},
                headers=mcp_client_headers,
            )

            # Verify correct headers were sent to Rootly API
            call_kwargs = mock_httpx_client.request.call_args[1]
            assert call_kwargs["headers"]["Content-Type"] == "application/vnd.api+json"
            assert call_kwargs["headers"]["Accept"] == "application/vnd.api+json"
            # Auth header should be preserved for hosted mode
            assert call_kwargs["headers"]["authorization"] == "Bearer user-api-token"

    @pytest.mark.asyncio
    async def test_simulated_fastmcp_getcurrentuser_call(self, mock_httpx_client):
        """Simulate the exact scenario that causes 415 error with getCurrentUser."""
        from rootly_mcp_server.server import AuthenticatedHTTPXClient

        mock_httpx_client.request.return_value.json.return_value = {
            "data": {"id": "123", "type": "users", "attributes": {"name": "Test User"}}
        }

        with patch.object(AuthenticatedHTTPXClient, "_get_api_token", return_value="test-token"):
            client = AuthenticatedHTTPXClient()
            client.client = mock_httpx_client

            # Simulate FastMCP headers for getCurrentUser
            mcp_client_headers = {
                "content-type": "application/json",
                "accept": "application/json",
            }

            await client.request(
                method="GET",
                url="/v1/users/me",
                headers=mcp_client_headers,
            )

            call_kwargs = mock_httpx_client.request.call_args[1]
            assert call_kwargs["headers"]["Content-Type"] == "application/vnd.api+json"
            assert call_kwargs["headers"]["Accept"] == "application/vnd.api+json"
