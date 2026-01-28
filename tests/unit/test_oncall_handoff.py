"""Unit tests for on-call handoff tools."""

from unittest.mock import patch

import pytest


@pytest.mark.unit
@pytest.mark.asyncio
class TestGetOncallHandoffSummary:
    """Test get_oncall_handoff_summary tool."""

    async def test_tool_registered(self):
        """Test that get_oncall_handoff_summary is registered."""
        from rootly_mcp_server.server import create_rootly_mcp_server

        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            server = create_rootly_mcp_server()
            assert server is not None

            tools = await server.get_tools()
            tool_names = []
            for t in tools:
                if hasattr(t, "name"):
                    tool_names.append(t.name)  # type: ignore[attr-defined]
                else:
                    tool_names.append(str(t))

            assert "get_oncall_handoff_summary" in tool_names


@pytest.mark.unit
@pytest.mark.asyncio
class TestGetShiftIncidents:
    """Test get_shift_incidents tool."""

    async def test_tool_registered(self):
        """Test that get_shift_incidents is registered."""
        from rootly_mcp_server.server import create_rootly_mcp_server

        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            server = create_rootly_mcp_server()
            assert server is not None

            tools = await server.get_tools()
            tool_names = []
            for t in tools:
                if hasattr(t, "name"):
                    tool_names.append(t.name)  # type: ignore[attr-defined]
                else:
                    tool_names.append(str(t))

            assert "get_shift_incidents" in tool_names
