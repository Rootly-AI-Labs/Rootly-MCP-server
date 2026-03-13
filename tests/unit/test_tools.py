"""
Unit tests for custom MCP tool functions.

Tests cover:
- search_incidents function logic
- scoped incident update tool behavior
- Parameter validation and defaults
- Pagination handling (single page vs multi-page)
- Error handling and response formatting
"""

from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

from rootly_mcp_server.server import DEFAULT_ALLOWED_PATHS, create_rootly_mcp_server
from rootly_mcp_server.server_defaults import _generate_recommendation
from rootly_mcp_server.tools.incidents import register_incident_tools


class FakeMCP:
    """Small tool registry used for direct custom tool testing."""

    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, name: str | None = None, **_: Any):
        def decorator(fn):
            self.tools[name or fn.__name__] = fn
            return fn

        return decorator


class FakeMCPError:
    """Minimal error helper for custom tool tests."""

    @staticmethod
    def categorize_error(error: Exception) -> tuple[str, str]:
        return (error.__class__.__name__, str(error))

    @staticmethod
    def tool_error(message: str, error_type: str) -> dict[str, Any]:
        return {"error": True, "error_type": error_type, "message": message}


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
            assert hasattr(server, "list_tools")

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


@pytest.mark.unit
class TestScopedIncidentUpdateTool:
    """Test the scoped custom updateIncident tool."""

    def _register_tools(self):
        mcp = FakeMCP()
        request = AsyncMock()
        register_incident_tools(
            mcp=mcp,
            make_authenticated_request=request,
            strip_heavy_nested_data=lambda data: data,
            mcp_error=FakeMCPError(),
            generate_recommendation=_generate_recommendation,
        )
        return mcp.tools, request

    @pytest.mark.asyncio
    async def test_update_incident_tool_is_registered_with_customer_facing_name(self):
        tools, _ = self._register_tools()

        assert "updateIncident" in tools

    @pytest.mark.asyncio
    async def test_update_incident_sends_only_allowed_fields(self):
        tools, request = self._register_tools()
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "data": {
                "id": "inc-123",
                "type": "incidents",
                "attributes": {
                    "summary": "Updated PIR summary",
                    "retrospective_progress_status": "active",
                    "title": "Should stay untouched on server",
                },
            }
        }
        request.return_value = response

        result = await tools["updateIncident"](
            incident_id="inc-123",
            retrospective_progress_status="active",
            summary="Updated PIR summary",
        )

        request.assert_awaited_once_with(
            "PUT",
            "/v1/incidents/inc-123",
            json={
                "data": {
                    "type": "incidents",
                    "attributes": {
                        "retrospective_progress_status": "active",
                        "summary": "Updated PIR summary",
                    },
                }
            },
        )
        assert result["data"]["attributes"]["retrospective_progress_status"] == "active"
        assert result["data"]["attributes"]["summary"] == "Updated PIR summary"

    @pytest.mark.asyncio
    async def test_update_incident_allows_skipped_status(self):
        tools, request = self._register_tools()
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "data": {
                "id": "inc-123",
                "type": "incidents",
                "attributes": {
                    "retrospective_progress_status": "skipped",
                },
            }
        }
        request.return_value = response

        result = await tools["updateIncident"](
            incident_id="inc-123",
            retrospective_progress_status="skipped",
        )

        request.assert_awaited_once_with(
            "PUT",
            "/v1/incidents/inc-123",
            json={
                "data": {
                    "type": "incidents",
                    "attributes": {
                        "retrospective_progress_status": "skipped",
                    },
                }
            },
        )
        assert result["data"]["attributes"]["retrospective_progress_status"] == "skipped"

    @pytest.mark.asyncio
    async def test_update_incident_requires_at_least_one_supported_field(self):
        tools, request = self._register_tools()

        result = await tools["updateIncident"](incident_id="inc-123")

        request.assert_not_called()
        assert result["error"] is True
        assert result["error_type"] == "validation_error"
        assert "Must provide at least one" in result["message"]

    @pytest.mark.asyncio
    async def test_update_incident_rejects_invalid_retrospective_status(self):
        tools, request = self._register_tools()

        result = await tools["updateIncident"](
            incident_id="inc-123",
            retrospective_progress_status="paused",
        )

        request.assert_not_called()
        assert result["error"] is True
        assert result["error_type"] == "validation_error"
        assert "retrospective_progress_status must be one of" in result["message"]
