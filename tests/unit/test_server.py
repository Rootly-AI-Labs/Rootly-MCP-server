"""
Unit tests for Rootly MCP Server core functionality.

Tests cover:
- Server creation with different configurations
- OpenAPI spec loading and filtering
- HTTP client configuration
- Tool generation from OpenAPI spec
"""

import json
import os
from unittest.mock import Mock, mock_open, patch

import pytest

from rootly_mcp_server.server import (
    DEFAULT_ALLOWED_PATHS,
    AuthenticatedHTTPXClient,
    _filter_openapi_spec,
    _load_swagger_spec,
    create_rootly_mcp_server,
)


@pytest.mark.unit
class TestServerCreation:
    """Test server creation with various configurations."""

    def test_create_server_with_defaults(self, mock_httpx_client, mock_api_response):
        """Test creating server with default parameters."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Rootly API", "version": "1.0.0"},
                "paths": {"/incidents": {"get": {"operationId": "listIncidents"}}},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            server = create_rootly_mcp_server()

            # Verify server was created
            assert server is not None
            assert hasattr(server, "get_tools")

            # Verify default parameters were used
            mock_load_spec.assert_called_once_with(None)

    def test_create_server_with_custom_name(self, mock_httpx_client):
        """Test server creation with custom name."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            custom_name = "CustomRootlyServer"
            server = create_rootly_mcp_server(name=custom_name)

            assert server is not None

    def test_create_server_hosted_mode(self, mock_httpx_client):
        """Test server creation in hosted mode."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            server = create_rootly_mcp_server(hosted=True)

            assert server is not None

    def test_create_server_with_custom_paths(self, mock_httpx_client):
        """Test server creation with custom allowed paths."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {"/custom": {}},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            custom_paths = ["/custom"]
            server = create_rootly_mcp_server(allowed_paths=custom_paths)

            assert server is not None

    def test_create_server_with_swagger_path(self, mock_httpx_client):
        """Test server creation with explicit swagger file path."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            swagger_path = "/path/to/swagger.json"
            create_rootly_mcp_server(swagger_path=swagger_path)

            mock_load_spec.assert_called_once_with(swagger_path)


@pytest.mark.unit
class TestAuthenticatedHTTPXClient:
    """Test the HTTP client wrapper functionality."""

    def test_client_initialization_local_mode(self, mock_environment_token):
        """Test client initialization in local mode with environment token."""
        client = AuthenticatedHTTPXClient(hosted=False)

        assert client.hosted is False
        assert client._api_token == mock_environment_token
        assert client.client is not None

        # Verify headers include authorization
        headers = client.client.headers
        assert "Authorization" in headers
        assert headers["Authorization"] == f"Bearer {mock_environment_token}"
        assert headers["Content-Type"] == "application/vnd.api+json"

    def test_client_initialization_hosted_mode(self):
        """Test client initialization in hosted mode without token loading."""
        client = AuthenticatedHTTPXClient(hosted=True)

        assert client.hosted is True
        assert client._api_token is None
        assert client.client is not None

        # Verify no authorization header in hosted mode
        headers = client.client.headers
        assert "Authorization" not in headers or not headers.get("Authorization")

    def test_client_with_custom_base_url(self):
        """Test client initialization with custom base URL."""
        custom_base = "https://custom.api.com"
        client = AuthenticatedHTTPXClient(base_url=custom_base, hosted=True)

        assert client._base_url == custom_base
        assert client.client.base_url == custom_base

    @patch.dict(os.environ, {}, clear=True)
    def test_client_without_token(self):
        """Test client behavior when no token is available."""
        client = AuthenticatedHTTPXClient(hosted=False)

        # Should handle missing token gracefully
        assert client._api_token is None

    def test_get_api_token_success(self, mock_environment_token):
        """Test successful API token retrieval."""
        client = AuthenticatedHTTPXClient(hosted=False)
        token = client._get_api_token()

        assert token == mock_environment_token
        assert token is not None and token.startswith("rootly_")

    @patch.dict(os.environ, {}, clear=True)
    def test_get_api_token_missing(self):
        """Test API token retrieval when token is missing."""
        client = AuthenticatedHTTPXClient(hosted=True)  # Won't try to get token
        token = client._get_api_token()

        assert token is None


@pytest.mark.unit
class TestSwaggerSpecLoading:
    """Test OpenAPI/Swagger specification loading functionality."""

    def test_load_spec_from_file(self):
        """Test loading OpenAPI spec from local file."""
        mock_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {},
        }

        with patch("os.path.isfile", return_value=True):
            with patch("builtins.open", mock_open(read_data=json.dumps(mock_spec))):
                spec = _load_swagger_spec("/path/to/swagger.json")

                assert spec == mock_spec
                assert spec["openapi"] == "3.0.0"

    def test_load_spec_from_url(self):
        """Test loading OpenAPI spec from remote URL."""
        mock_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Remote API", "version": "1.0.0"},
            "paths": {},
        }

        with patch("pathlib.Path.is_file", return_value=False):
            with patch("requests.get") as mock_get:
                mock_response = Mock()
                mock_response.json.return_value = mock_spec
                mock_response.raise_for_status.return_value = None
                mock_get.return_value = mock_response

                spec = _load_swagger_spec(None)

                assert spec == mock_spec
                mock_get.assert_called_once()

    def test_load_spec_file_not_found(self):
        """Test behavior when swagger file is not found."""
        mock_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {},
        }

        # Mock all the path checking methods to return False
        with patch("os.path.isfile", return_value=False):
            with patch("pathlib.Path.is_file", return_value=False):
                with patch("requests.get") as mock_get:
                    mock_response = Mock()
                    mock_response.json.return_value = mock_spec
                    mock_response.raise_for_status.return_value = None
                    mock_get.return_value = mock_response

                    # Should fall back to URL loading when no local files found
                    spec = _load_swagger_spec(None)

                    assert spec == mock_spec
                    mock_get.assert_called_once()


@pytest.mark.unit
class TestOpenAPISpecFiltering:
    """Test OpenAPI specification filtering functionality."""

    def test_filter_spec_with_allowed_paths(self):
        """Test filtering OpenAPI spec to include only allowed paths."""
        original_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/incidents": {"get": {"operationId": "listIncidents"}},
                "/teams": {"get": {"operationId": "listTeams"}},
                "/forbidden": {"get": {"operationId": "forbiddenEndpoint"}},
            },
            "components": {"schemas": {}},
        }

        allowed_paths = ["/incidents", "/teams"]
        filtered_spec = _filter_openapi_spec(original_spec, allowed_paths)

        assert len(filtered_spec["paths"]) == 2
        assert "/incidents" in filtered_spec["paths"]
        assert "/teams" in filtered_spec["paths"]
        assert "/forbidden" not in filtered_spec["paths"]

        # Verify pagination parameters were added to /incidents endpoint
        incidents_get = filtered_spec["paths"]["/incidents"]["get"]
        assert "parameters" in incidents_get
        param_names = [p["name"] for p in incidents_get["parameters"]]
        assert "page[size]" in param_names
        assert "page[number]" in param_names

        # Verify /teams endpoint does not get pagination (doesn't contain "incidents" or "alerts")
        teams_get = filtered_spec["paths"]["/teams"]["get"]
        if "parameters" in teams_get:
            param_names = [p["name"] for p in teams_get["parameters"]]
            assert "page[size]" not in param_names

        # Verify other properties are preserved
        assert filtered_spec["openapi"] == original_spec["openapi"]
        assert filtered_spec["info"] == original_spec["info"]

    def test_filter_spec_no_paths_match(self):
        """Test filtering when no paths match allowed list."""
        original_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {"/other": {"get": {}}},
            "components": {"schemas": {}},
        }

        allowed_paths = ["/incidents"]
        filtered_spec = _filter_openapi_spec(original_spec, allowed_paths)

        assert len(filtered_spec["paths"]) == 0

    def test_filter_spec_preserve_structure(self):
        """Test that filtering preserves OpenAPI spec structure."""
        original_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {"/incidents": {"get": {"operationId": "listIncidents"}}},
            "components": {
                "schemas": {"Incident": {"type": "object"}},
                "securitySchemes": {"bearer": {"type": "http"}},
            },
        }

        filtered_spec = _filter_openapi_spec(original_spec, ["/incidents"])

        # Verify all sections are preserved
        assert "openapi" in filtered_spec
        assert "info" in filtered_spec
        assert "servers" in filtered_spec
        assert "components" in filtered_spec
        assert filtered_spec["servers"] == original_spec["servers"]

        # Verify pagination parameters were added to /incidents endpoint
        incidents_get = filtered_spec["paths"]["/incidents"]["get"]
        assert "parameters" in incidents_get
        param_names = [p["name"] for p in incidents_get["parameters"]]
        assert "page[size]" in param_names
        assert "page[number]" in param_names

    def test_filter_spec_adds_pagination_to_alerts(self):
        """Test that pagination parameters are added to alerts endpoints."""
        original_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/alerts": {"get": {"operationId": "listAlerts"}},
                "/incidents/123/alerts": {"get": {"operationId": "listIncidentAlerts"}},
                "/users": {"get": {"operationId": "listUsers"}},
            },
            "components": {"schemas": {}},
        }

        allowed_paths = ["/alerts", "/incidents/123/alerts", "/users"]
        filtered_spec = _filter_openapi_spec(original_spec, allowed_paths)

        # Verify pagination was added to alerts endpoints
        alerts_get = filtered_spec["paths"]["/alerts"]["get"]
        assert "parameters" in alerts_get
        param_names = [p["name"] for p in alerts_get["parameters"]]
        assert "page[size]" in param_names
        assert "page[number]" in param_names

        incident_alerts_get = filtered_spec["paths"]["/incidents/123/alerts"]["get"]
        assert "parameters" in incident_alerts_get
        param_names = [p["name"] for p in incident_alerts_get["parameters"]]
        assert "page[size]" in param_names
        assert "page[number]" in param_names

        # Verify pagination was NOT added to /users (no "incident" or "alerts" in path)
        users_get = filtered_spec["paths"]["/users"]["get"]
        if "parameters" in users_get:
            param_names = [p["name"] for p in users_get["parameters"]]
            assert "page[size]" not in param_names

    def test_filter_spec_adds_pagination_to_incident_types(self):
        """Test that pagination parameters are added to incident-related endpoints."""
        original_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/incident_types": {"get": {"operationId": "listIncidentTypes"}},
                "/incident_action_items": {"get": {"operationId": "listIncidentActionItems"}},
                "/services": {"get": {"operationId": "listServices"}},
            },
            "components": {"schemas": {}},
        }

        allowed_paths = ["/incident_types", "/incident_action_items", "/services"]
        filtered_spec = _filter_openapi_spec(original_spec, allowed_paths)

        # Verify pagination was added to incident-related endpoints
        incident_types_get = filtered_spec["paths"]["/incident_types"]["get"]
        assert "parameters" in incident_types_get
        param_names = [p["name"] for p in incident_types_get["parameters"]]
        assert "page[size]" in param_names
        assert "page[number]" in param_names

        incident_action_items_get = filtered_spec["paths"]["/incident_action_items"]["get"]
        assert "parameters" in incident_action_items_get
        param_names = [p["name"] for p in incident_action_items_get["parameters"]]
        assert "page[size]" in param_names
        assert "page[number]" in param_names

        # Verify pagination was NOT added to /services (no "incident" or "alerts" in path)
        services_get = filtered_spec["paths"]["/services"]["get"]
        if "parameters" in services_get:
            param_names = [p["name"] for p in services_get["parameters"]]
            assert "page[size]" not in param_names


@pytest.mark.unit
class TestDefaultConfiguration:
    """Test default configuration values."""

    def test_default_allowed_paths_exist(self):
        """Test that default allowed paths are defined."""
        assert DEFAULT_ALLOWED_PATHS is not None
        assert isinstance(DEFAULT_ALLOWED_PATHS, list)
        assert len(DEFAULT_ALLOWED_PATHS) > 0

        # Verify some expected paths are included
        path_strings = str(DEFAULT_ALLOWED_PATHS)
        assert "incidents" in path_strings
        assert "teams" in path_strings

    def test_default_swagger_url(self):
        """Test that default swagger URL is properly defined."""
        from rootly_mcp_server.server import SWAGGER_URL

        assert SWAGGER_URL is not None
        assert isinstance(SWAGGER_URL, str)
        assert SWAGGER_URL.startswith("https://")
        assert "swagger" in SWAGGER_URL.lower()
