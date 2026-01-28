"""
Basic local integration tests for Rootly MCP Server.

These tests validate that the server can be created and basic functionality
works in local development mode.
"""

import os
from unittest.mock import patch

import pytest

from rootly_mcp_server.server import AuthenticatedHTTPXClient, create_rootly_mcp_server


@pytest.mark.integration
class TestLocalServerBasics:
    """Test basic local server functionality."""

    def test_server_creation_integration(self):
        """Test that server can be created with real configuration."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            # Use a more complete mock spec
            mock_spec = {
                "openapi": "3.0.0",
                "info": {
                    "title": "Rootly API",
                    "version": "1.0.0",
                    "description": "Rootly API for incident management",
                },
                "paths": {
                    "/v1/incidents": {
                        "get": {
                            "operationId": "listIncidents",
                            "summary": "List incidents",
                            "responses": {"200": {"description": "Success"}},
                        }
                    }
                },
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            server = create_rootly_mcp_server()

            assert server is not None
            assert hasattr(server, "get_tools")

    def test_server_creation_hosted_mode(self):
        """Test server creation in hosted mode."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Rootly API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            server = create_rootly_mcp_server(hosted=True)

            assert server is not None

    def test_server_creation_local_mode(self):
        """Test server creation in local mode."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Rootly API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            server = create_rootly_mcp_server(hosted=False)

            assert server is not None


@pytest.mark.integration
class TestLocalAuthentication:
    """Test local authentication integration."""

    def test_local_client_with_environment_token(self, api_token):
        """Test local client can use environment token."""
        client = AuthenticatedHTTPXClient(hosted=False)

        # Should have loaded token from environment
        assert client._api_token == api_token
        assert client.hosted is False

        # Should have proper headers
        headers = client.client.headers
        assert headers["Authorization"] == f"Bearer {api_token}"

    def test_local_vs_hosted_client_differences(self):
        """Test differences between local and hosted clients."""
        # Create both types of clients
        local_client = AuthenticatedHTTPXClient(hosted=False)
        hosted_client = AuthenticatedHTTPXClient(hosted=True)

        # They should have different authentication behavior
        assert local_client.hosted is False
        assert hosted_client.hosted is True


@pytest.mark.integration
class TestLocalServerConfiguration:
    """Test local server configuration options."""

    def test_server_with_custom_swagger_path(self):
        """Test server creation with custom swagger path."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Custom API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            custom_path = "/path/to/custom/swagger.json"
            server = create_rootly_mcp_server(swagger_path=custom_path)

            # Verify custom path was used
            mock_load_spec.assert_called_once_with(custom_path)
            assert server is not None

    def test_server_with_custom_allowed_paths(self):
        """Test server creation with custom allowed paths."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Filtered API", "version": "1.0.0"},
                "paths": {
                    "/custom/endpoint": {"get": {"operationId": "customOp"}},
                    "/another/endpoint": {"post": {"operationId": "anotherOp"}},
                },
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            custom_paths = ["/custom/endpoint"]
            server = create_rootly_mcp_server(allowed_paths=custom_paths)

            assert server is not None

    def test_server_with_custom_name(self):
        """Test server creation with custom name."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Named API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            custom_name = "MyCustomRootlyServer"
            server = create_rootly_mcp_server(name=custom_name)

            assert server is not None


@pytest.mark.integration
class TestLocalAPIIntegration:
    """Test local integration with mock API responses."""

    def test_client_request_structure(self):
        """Test that client constructs requests properly."""
        client = AuthenticatedHTTPXClient(hosted=False)

        # Verify client configuration
        assert client.client.base_url == "https://api.rootly.com"
        assert client.client.timeout.read == 30.0
        assert client.client.follow_redirects is True

    def test_client_headers_integration(self, api_token):
        """Test that client sets headers correctly for API integration."""
        client = AuthenticatedHTTPXClient(hosted=False)

        headers = client.client.headers

        # Verify all required headers for Rootly API
        assert headers["Content-Type"] == "application/vnd.api+json"
        assert headers["Accept"] == "application/vnd.api+json"
        assert headers["Authorization"] == f"Bearer {api_token}"

    def test_client_custom_base_url(self):
        """Test client with custom base URL for testing."""
        custom_base = "https://staging.rootly.com"
        client = AuthenticatedHTTPXClient(base_url=custom_base, hosted=False)

        assert str(client.client.base_url) == custom_base
        assert client._base_url == custom_base


@pytest.mark.integration
@pytest.mark.skipif(not os.getenv("ROOTLY_API_TOKEN"), reason="API token required")
class TestLocalWithRealToken:
    """Tests that run only when a real API token is available."""

    def test_token_format_validation(self):
        """Test that real token has expected format."""
        token = os.getenv("ROOTLY_API_TOKEN")

        # Basic format validation
        assert token is not None and token.startswith(
            "rootly_"
        ), "Token should start with 'rootly_'"
        assert token is not None and len(token) > 20, "Token should be reasonably long"
        assert token is not None and "_" in token, "Token should contain underscores"

    def test_client_initialization_with_real_token(self):
        """Test client initialization with real token."""
        client = AuthenticatedHTTPXClient(hosted=False)

        # Should have loaded the real token
        token = os.getenv("ROOTLY_API_TOKEN")
        assert client._api_token == token

        # Should have set authorization header
        expected_header = f"Bearer {token}"
        assert client.client.headers["Authorization"] == expected_header
