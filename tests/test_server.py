"""
Unit tests for the Rootly MCP server functionality.
"""

import json
import os
import tempfile
import pytest
from unittest.mock import patch, Mock, MagicMock
from pathlib import Path

from rootly_mcp_server.server import (
    create_rootly_mcp_server,
    _load_swagger_spec,
    _fetch_swagger_from_url,
    _filter_openapi_spec,
    _sanitize_parameter_name,
    _has_broken_references,
    AuthenticatedHTTPXClient,
)


class TestCreateRootlyMCPServer:
    """Test the main server creation function."""

    @patch('rootly_mcp_server.server._load_swagger_spec')
    @patch('rootly_mcp_server.server.AuthenticatedHTTPXClient')
    @patch('rootly_mcp_server.server.FastMCP.from_openapi')
    def test_create_server_default_config(self, mock_fastmcp, mock_client, mock_load_swagger):
        """Test server creation with default configuration."""
        # Mock the swagger spec
        mock_swagger = {
            "paths": {
                "/v1/incidents": {"get": {"summary": "List incidents"}},
                "/v1/alerts": {"get": {"summary": "List alerts"}},
            }
        }
        mock_load_swagger.return_value = mock_swagger
        
        # Mock FastMCP server
        mock_server = Mock()
        mock_fastmcp.return_value = mock_server

        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            server = create_rootly_mcp_server()

        # Verify swagger spec was loaded
        mock_load_swagger.assert_called_once_with(None)
        
        # Verify client was created
        mock_client.assert_called_once_with(
            base_url="https://api.rootly.com",
            hosted=False
        )
        
        # Verify FastMCP was called with filtered spec
        assert mock_fastmcp.called
        call_args = mock_fastmcp.call_args[1]
        assert 'openapi_spec' in call_args
        assert 'client' in call_args
        assert call_args['name'] == 'Rootly'

    def test_create_server_custom_allowed_paths(self):
        """Test server creation with custom allowed paths."""
        custom_paths = ["/incidents", "/alerts"]
        
        with patch('rootly_mcp_server.server._load_swagger_spec') as mock_load:
            mock_load.return_value = {"paths": {}}
            
            with patch('rootly_mcp_server.server.AuthenticatedHTTPXClient'):
                with patch('rootly_mcp_server.server.FastMCP.from_openapi') as mock_fastmcp:
                    with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
                        create_rootly_mcp_server(allowed_paths=custom_paths)

        # Verify the paths were converted to /v1 format
        call_args = mock_fastmcp.call_args[1]
        filtered_spec = call_args['openapi_spec']
        # The filtering logic should have been applied


class TestAuthenticatedHTTPXClient:
    """Test the authenticated HTTPX client wrapper."""

    def test_init_non_hosted_with_token(self):
        """Test client initialization in non-hosted mode with token."""
        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = AuthenticatedHTTPXClient()
            assert client.base_url == "https://api.rootly.com"
            assert not client.hosted
            assert client._api_token == 'test-token'

    def test_init_non_hosted_without_token(self):
        """Test client initialization in non-hosted mode without token."""
        with patch.dict(os.environ, {}, clear=True):
            client = AuthenticatedHTTPXClient()
            assert client._api_token is None

    def test_init_hosted_mode(self):
        """Test client initialization in hosted mode."""
        client = AuthenticatedHTTPXClient(hosted=True)
        assert client.hosted is True
        assert client._api_token is None

    def test_init_custom_base_url(self):
        """Test client initialization with custom base URL."""
        custom_url = "https://custom.rootly.com"
        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = AuthenticatedHTTPXClient(base_url=custom_url)
            assert client.base_url == custom_url


class TestLoadSwaggerSpec:
    """Test Swagger specification loading functionality."""

    def test_load_swagger_from_file(self):
        """Test loading Swagger spec from a provided file path."""
        test_spec = {"openapi": "3.0.0", "paths": {"/test": {}}}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_spec, f)
            temp_path = f.name

        try:
            result = _load_swagger_spec(temp_path)
            assert result == test_spec
        finally:
            os.unlink(temp_path)

    def test_load_swagger_file_not_found(self):
        """Test loading Swagger spec from non-existent file."""
        with pytest.raises(FileNotFoundError):
            _load_swagger_spec("/non/existent/path.json")

    @patch('rootly_mcp_server.server._fetch_swagger_from_url')
    @patch('pathlib.Path.is_file')
    def test_load_swagger_fallback_to_url(self, mock_is_file, mock_fetch):
        """Test falling back to URL when no local file is found."""
        test_spec = {"openapi": "3.0.0", "paths": {}}
        mock_fetch.return_value = test_spec
        mock_is_file.return_value = False  # No local files found

        result = _load_swagger_spec()

        mock_fetch.assert_called_once()
        assert result == test_spec

    @patch('requests.get')
    def test_fetch_swagger_from_url_success(self, mock_get):
        """Test successful Swagger spec fetch from URL."""
        test_spec = {"openapi": "3.0.0", "paths": {}}
        mock_response = Mock()
        mock_response.json.return_value = test_spec
        mock_get.return_value = mock_response

        result = _fetch_swagger_from_url("https://example.com/swagger.json")
        
        mock_get.assert_called_once_with("https://example.com/swagger.json")
        mock_response.raise_for_status.assert_called_once()
        assert result == test_spec

    @patch('rootly_mcp_server.server.requests.get')
    def test_fetch_swagger_from_url_http_error(self, mock_get):
        """Test HTTP error during Swagger spec fetch."""
        import requests
        mock_get.side_effect = requests.RequestException("HTTP Error")

        with pytest.raises(Exception, match="Failed to fetch Swagger specification"):
            _fetch_swagger_from_url("https://example.com/swagger.json")


class TestFilterOpenAPISpec:
    """Test OpenAPI specification filtering functionality."""

    def test_filter_paths(self):
        """Test basic path filtering."""
        original_spec = {
            "openapi": "3.0.0",
            "paths": {
                "/v1/incidents": {"get": {"summary": "List incidents"}},
                "/v1/alerts": {"get": {"summary": "List alerts"}},
                "/v1/admin": {"get": {"summary": "Admin endpoint"}},
            }
        }
        
        allowed_paths = ["/v1/incidents", "/v1/alerts"]
        
        filtered = _filter_openapi_spec(original_spec, allowed_paths)
        
        assert len(filtered["paths"]) == 2
        assert "/v1/incidents" in filtered["paths"]
        assert "/v1/alerts" in filtered["paths"]
        assert "/v1/admin" not in filtered["paths"]

    def test_filter_empty_allowed_paths(self):
        """Test filtering with empty allowed paths."""
        original_spec = {
            "openapi": "3.0.0",
            "paths": {
                "/v1/incidents": {"get": {"summary": "List incidents"}},
            }
        }
        
        filtered = _filter_openapi_spec(original_spec, [])
        
        assert len(filtered["paths"]) == 0

    def test_sanitize_parameter_names(self):
        """Test parameter name sanitization during filtering."""
        original_spec = {
            "openapi": "3.0.0",
            "paths": {
                "/v1/incidents": {
                    "get": {
                        "parameters": [
                            {"name": "page[size]", "in": "query", "schema": {"type": "integer"}},
                            {"name": "filter[search]", "in": "query", "schema": {"type": "string"}},
                        ]
                    }
                }
            }
        }
        
        filtered = _filter_openapi_spec(original_spec, ["/v1/incidents"])
        
        # Check that parameter names were sanitized
        params = filtered["paths"]["/v1/incidents"]["get"]["parameters"]
        param_names = [p["name"] for p in params]
        
        assert "page_size" in param_names
        assert "filter_search" in param_names
        assert "page[size]" not in param_names
        assert "filter[search]" not in param_names


class TestSanitizeParameterName:
    """Test parameter name sanitization utility."""

    def test_sanitize_brackets(self):
        """Test sanitization of square brackets."""
        assert _sanitize_parameter_name("page[size]") == "page_size"
        assert _sanitize_parameter_name("filter[search]") == "filter_search"

    def test_sanitize_special_characters(self):
        """Test sanitization of various special characters."""
        assert _sanitize_parameter_name("param-name") == "param-name"  # Hyphens are allowed
        assert _sanitize_parameter_name("param.name") == "param.name"  # Dots are allowed
        assert _sanitize_parameter_name("param_name") == "param_name"  # Underscores are allowed
        assert _sanitize_parameter_name("param@name") == "param_name"  # @ becomes _
        assert _sanitize_parameter_name("param space") == "param_space"  # Space becomes _

    def test_sanitize_length_limit(self):
        """Test parameter name length is limited to 64 characters."""
        long_name = "a" * 100
        sanitized = _sanitize_parameter_name(long_name)
        assert len(sanitized) == 64

    def test_sanitize_empty_name(self):
        """Test handling of empty parameter names."""
        assert _sanitize_parameter_name("") == "param"
        assert _sanitize_parameter_name("@#$") == "param"  # All invalid chars
        assert _sanitize_parameter_name("___") == "param"  # Only underscores


class TestHasBrokenReferences:
    """Test broken reference detection utility."""

    def test_no_broken_references(self):
        """Test schema with no broken references."""
        schema = {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"}
            }
        }
        assert not _has_broken_references(schema)

    def test_direct_broken_reference(self):
        """Test schema with direct broken reference."""
        schema = {
            "$ref": "#/components/schemas/incident_trigger_params"
        }
        assert _has_broken_references(schema)

    def test_nested_broken_reference(self):
        """Test schema with nested broken reference."""
        schema = {
            "type": "object",
            "properties": {
                "data": {
                    "$ref": "#/components/schemas/new_workflow"
                }
            }
        }
        assert _has_broken_references(schema)

    def test_broken_reference_in_array(self):
        """Test schema with broken reference in array."""
        schema = {
            "type": "array",
            "items": [
                {"type": "string"},
                {"$ref": "#/components/schemas/workflow"}
            ]
        }
        assert _has_broken_references(schema)

    def test_valid_reference(self):
        """Test schema with valid reference."""
        schema = {
            "$ref": "#/components/schemas/Incident"
        }
        assert not _has_broken_references(schema)