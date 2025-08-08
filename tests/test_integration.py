"""
Integration tests for the Rootly MCP server.

These tests verify that the different components work together properly.
"""

import json
import pytest
from unittest.mock import patch, Mock
import tempfile
import os

from rootly_mcp_server.server import create_rootly_mcp_server


class TestIntegration:
    """Integration tests for the complete MCP server setup."""

    @patch('rootly_mcp_server.server.AuthenticatedHTTPXClient')
    @patch('rootly_mcp_server.server.FastMCP.from_openapi')
    def test_end_to_end_server_creation(self, mock_fastmcp, mock_client, mock_swagger_spec):
        """Test complete server creation flow."""
        # Setup mocks
        mock_server = Mock()
        mock_fastmcp.return_value = mock_server
        
        # Create a temporary swagger file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(mock_swagger_spec, f)
            temp_path = f.name

        try:
            with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
                server = create_rootly_mcp_server(
                    swagger_path=temp_path,
                    name="TestServer",
                    allowed_paths=["/incidents", "/alerts"]
                )

            # Verify server was created
            assert server is not None
            assert server == mock_server
            
            # Verify FastMCP was called with correct parameters
            mock_fastmcp.assert_called_once()
            call_kwargs = mock_fastmcp.call_args[1]
            
            assert call_kwargs['name'] == 'TestServer'
            assert 'openapi_spec' in call_kwargs
            assert 'client' in call_kwargs
            
            # Verify the spec was filtered correctly
            filtered_spec = call_kwargs['openapi_spec']
            assert 'paths' in filtered_spec
            
            # Check that only allowed paths are included
            allowed_v1_paths = ['/v1/incidents', '/v1/alerts']
            for path in filtered_spec['paths'].keys():
                assert path in allowed_v1_paths
                
        finally:
            # Cleanup
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass

    @patch('rootly_mcp_server.server._load_swagger_spec')
    @patch('rootly_mcp_server.server.AuthenticatedHTTPXClient')  
    @patch('rootly_mcp_server.server.FastMCP.from_openapi')
    def test_server_with_broken_swagger_references(self, mock_fastmcp, mock_client, mock_load_swagger):
        """Test server creation handles broken Swagger references gracefully."""
        # Create a spec with broken references
        broken_spec = {
            "openapi": "3.0.0",
            "paths": {
                "/v1/incidents": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/incident_trigger_params"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "incident_trigger_params": {
                        "$ref": "#/components/schemas/non_existent_schema"
                    }
                }
            }
        }
        
        mock_load_swagger.return_value = broken_spec
        mock_server = Mock()
        mock_fastmcp.return_value = mock_server

        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            server = create_rootly_mcp_server(allowed_paths=["/incidents"])

        # Verify server was still created despite broken references
        assert server is not None
        mock_fastmcp.assert_called_once()
        
        # Verify the broken schema reference was cleaned up
        call_kwargs = mock_fastmcp.call_args[1] 
        filtered_spec = call_kwargs['openapi_spec']
        
        # The broken reference should have been replaced with a generic schema
        request_schema = (filtered_spec['paths']['/v1/incidents']['post']
                         ['requestBody']['content']['application/json']['schema'])
        assert request_schema['type'] == 'object'
        assert request_schema['additionalProperties'] is True

    @patch('rootly_mcp_server.server._load_swagger_spec')
    @patch('rootly_mcp_server.server.AuthenticatedHTTPXClient')
    @patch('rootly_mcp_server.server.FastMCP.from_openapi')
    def test_parameter_name_sanitization_integration(self, mock_fastmcp, mock_client, mock_load_swagger):
        """Test that parameter names are properly sanitized during server creation."""
        spec_with_invalid_params = {
            "openapi": "3.0.0", 
            "paths": {
                "/v1/incidents": {
                    "get": {
                        "parameters": [
                            {
                                "name": "page[size]",
                                "in": "query",
                                "schema": {"type": "integer"}
                            },
                            {
                                "name": "filter[search]", 
                                "in": "query",
                                "schema": {"type": "string"}
                            }
                        ]
                    }
                }
            }
        }
        
        mock_load_swagger.return_value = spec_with_invalid_params
        mock_server = Mock()
        mock_fastmcp.return_value = mock_server

        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            create_rootly_mcp_server(allowed_paths=["/incidents"])

        # Verify parameters were sanitized
        call_kwargs = mock_fastmcp.call_args[1]
        filtered_spec = call_kwargs['openapi_spec']
        
        parameters = filtered_spec['paths']['/v1/incidents']['get']['parameters']
        param_names = [p['name'] for p in parameters]
        
        assert 'page_size' in param_names
        assert 'filter_search' in param_names
        assert 'page[size]' not in param_names
        assert 'filter[search]' not in param_names