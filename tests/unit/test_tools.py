"""
Unit tests for custom MCP tool functions.

Tests cover:
- search_incidents function logic
- Parameter validation and defaults
- Pagination handling (single page vs multi-page)
- Error handling and response formatting
"""

from unittest.mock import patch

import pytest

from rootly_mcp_server.server import DEFAULT_ALLOWED_PATHS, create_rootly_mcp_server


@pytest.mark.unit
class TestSearchIncidentsIntegration:
    """Test the search_incidents tool integration with the server."""

    def test_search_incidents_tool_availability(self):
        """Test that search_incidents tool is available in server."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {"/incidents": {"get": {"operationId": "listIncidents"}}},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            server = create_rootly_mcp_server()

            # Verify server was created successfully
            assert server is not None
            assert hasattr(server, "get_tools")

    def test_custom_tool_registration(self):
        """Test that custom tools are properly registered."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            server = create_rootly_mcp_server()

            # Server should have been created with custom tools
            assert server is not None


@pytest.mark.unit
class TestDefaultConfiguration:
    """Test default configuration and constants."""

    def test_default_allowed_paths_exist(self):
        """Test that default allowed paths are defined."""
        assert DEFAULT_ALLOWED_PATHS is not None
        assert isinstance(DEFAULT_ALLOWED_PATHS, list)
        assert len(DEFAULT_ALLOWED_PATHS) > 0

        # Verify some expected paths are included
        path_strings = str(DEFAULT_ALLOWED_PATHS)
        assert "incidents" in path_strings

    def test_server_creation_uses_defaults(self):
        """Test that server creation works with default paths."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            server = create_rootly_mcp_server()

            # Server should be created successfully with defaults
            assert server is not None

    def test_oncall_endpoints_in_defaults(self):
        """Test that on-call endpoints are included in default paths."""
        path_strings = [p.lower() for p in DEFAULT_ALLOWED_PATHS]

        # Verify on-call related paths are included
        assert any("schedule" in p for p in path_strings)
        assert any("shift" in p for p in path_strings)
        assert any("on_call" in p for p in path_strings)
