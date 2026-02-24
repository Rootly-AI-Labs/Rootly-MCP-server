"""
Tests that MCP tools in hosted mode correctly forward auth tokens.

This catches the exact bug where OpenAPI-generated tools (listAlerts, listTeams, etc.)
got 401 Unauthorized because FastMCP 3.x calls client.send() instead of client.request(),
bypassing ContextVar auth injection.

Tests exercise the FULL tool execution path:
  tool.run() → AuthenticatedHTTPXClient.request()/send() → ContextVar injection → outgoing HTTP

Both hand-written tools (search_incidents) and OpenAPI-generated tools (listAlerts)
must inject the auth token from the ContextVar in hosted mode.
"""

from unittest.mock import patch

import httpx
import pytest

from rootly_mcp_server.server import (
    _session_auth_token,
    create_rootly_mcp_server,
)

TEST_TOKEN = "Bearer rootly_test_token_abc123"


def _make_json_api_response(data=None):
    """Create a realistic Rootly JSON-API response."""
    if data is None:
        data = []
    return {
        "data": data,
        "links": {"self": "https://api.rootly.com/v1/test"},
        "meta": {"current_page": 1, "total_count": 0, "total_pages": 1},
    }


@pytest.fixture
def hosted_server():
    """Create a hosted-mode MCP server with a minimal OpenAPI spec."""
    minimal_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Rootly API", "version": "1.0.0"},
        "servers": [{"url": "https://api.rootly.com"}],
        "paths": {
            "/v1/alerts": {
                "get": {
                    "operationId": "listAlerts",
                    "summary": "List alerts",
                    "parameters": [],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {"application/vnd.api+json": {"schema": {"type": "object"}}},
                        }
                    },
                }
            },
            "/v1/environments": {
                "get": {
                    "operationId": "listEnvironments",
                    "summary": "List environments",
                    "parameters": [],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {"application/vnd.api+json": {"schema": {"type": "object"}}},
                        }
                    },
                }
            },
        },
        "components": {"schemas": {}},
    }

    with patch("rootly_mcp_server.server._load_swagger_spec", return_value=minimal_spec):
        server = create_rootly_mcp_server(
            hosted=True,
            allowed_paths=["/v1/alerts", "/v1/environments"],
        )
    return server


@pytest.fixture(autouse=True)
def reset_contextvar():
    """Reset the ContextVar before and after each test."""
    token = _session_auth_token.set("")
    yield
    _session_auth_token.reset(token)


@pytest.mark.unit
class TestHostedToolAuth:
    """Test that tools forward auth tokens in hosted mode.

    These tests exercise the full tool execution path, catching regressions
    where a FastMCP version change breaks auth forwarding for specific tool types.
    """

    @pytest.mark.asyncio
    async def test_openapi_tool_forwards_auth_via_send(self, hosted_server):
        """OpenAPI-generated tools must forward auth from ContextVar.

        This is the exact regression test for the FastMCP 3.x bug:
        OpenAPI tools call client.send() which previously bypassed
        ContextVar auth injection, causing 401 errors.
        """
        _session_auth_token.set(TEST_TOKEN)
        captured_requests = []

        async def capture_transport(request: httpx.Request):
            captured_requests.append(request)
            return httpx.Response(
                200,
                json=_make_json_api_response(),
                headers={"content-type": "application/vnd.api+json"},
            )

        tools = await hosted_server.get_tools()
        # Find an OpenAPI-generated tool
        openapi_tool = tools.get("listAlerts") or tools.get("listEnvironments")
        assert (
            openapi_tool is not None
        ), f"No OpenAPI tool found. Available tools: {list(tools.keys())}"

        # Replace the inner httpx client's transport to capture outgoing requests
        openapi_tool._client.client = httpx.AsyncClient(
            transport=httpx.MockTransport(capture_transport),
            base_url="https://api.rootly.com",
        )

        await openapi_tool.run({})

        assert len(captured_requests) >= 1, "No outgoing HTTP request was made"
        outgoing = captured_requests[0]
        assert (
            "authorization" in outgoing.headers
        ), f"Auth header missing from outgoing request. Headers: {dict(outgoing.headers)}"
        assert outgoing.headers["authorization"] == TEST_TOKEN

    @pytest.mark.asyncio
    async def test_handwritten_tool_forwards_auth_via_request(self, hosted_server):
        """Hand-written tools (search_incidents) must forward auth from ContextVar."""
        _session_auth_token.set(TEST_TOKEN)
        captured_requests = []

        async def capture_transport(request: httpx.Request):
            captured_requests.append(request)
            return httpx.Response(
                200,
                json=_make_json_api_response(),
                headers={"content-type": "application/vnd.api+json"},
            )

        tools = await hosted_server.get_tools()
        search_tool = tools.get("search_incidents")
        assert (
            search_tool is not None
        ), f"search_incidents not found. Available tools: {list(tools.keys())}"

        # Replace the inner httpx client transport.
        # Hand-written tools use make_authenticated_request() → http_client.request()
        # → AuthenticatedHTTPXClient.request() → self.client.request()
        # Access the shared http_client wrapper via an OpenAPI tool's _client.
        openapi_tool = tools.get("listAlerts") or tools.get("listEnvironments")
        if openapi_tool:
            http_client_wrapper = openapi_tool._client
            http_client_wrapper.client = httpx.AsyncClient(
                transport=httpx.MockTransport(capture_transport),
                base_url="https://api.rootly.com",
            )

            # search_incidents uses make_authenticated_request which calls http_client.request()
            # Both OpenAPI and hand-written tools share the same http_client wrapper
            await search_tool.run({"page_size": 1})

            assert len(captured_requests) >= 1, "No outgoing HTTP request was made"
            outgoing = captured_requests[0]
            assert (
                "authorization" in outgoing.headers
            ), f"Auth header missing from outgoing request. Headers: {dict(outgoing.headers)}"
            assert outgoing.headers["authorization"] == TEST_TOKEN

    @pytest.mark.asyncio
    async def test_multiple_openapi_tools_all_forward_auth(self, hosted_server):
        """ALL OpenAPI-generated tools must forward auth, not just one."""
        _session_auth_token.set(TEST_TOKEN)

        tools = await hosted_server.get_tools()
        openapi_tools = {
            name: tool
            for name, tool in tools.items()
            if hasattr(tool, "_client") and hasattr(tool, "_route")
        }

        assert len(openapi_tools) >= 1, "No OpenAPI tools found"

        for tool_name, tool in openapi_tools.items():
            captured = []

            def _make_transport(reqs=captured):
                async def handler(request: httpx.Request):
                    reqs.append(request)
                    return httpx.Response(
                        200,
                        json=_make_json_api_response(),
                        headers={"content-type": "application/vnd.api+json"},
                    )

                return handler

            tool._client.client = httpx.AsyncClient(
                transport=httpx.MockTransport(_make_transport()),
                base_url="https://api.rootly.com",
            )

            await tool.run({})

            assert len(captured) >= 1, f"Tool '{tool_name}' made no outgoing HTTP request"
            outgoing = captured[0]
            assert (
                "authorization" in outgoing.headers
            ), f"Tool '{tool_name}' missing auth header. Headers: {dict(outgoing.headers)}"
            assert (
                outgoing.headers["authorization"] == TEST_TOKEN
            ), f"Tool '{tool_name}' has wrong auth token"

    @pytest.mark.asyncio
    async def test_no_auth_injection_without_contextvar(self, hosted_server):
        """Tools should NOT have auth when ContextVar is empty (no SSE connection)."""
        # ContextVar is empty (reset by fixture)
        captured_requests = []

        async def capture_transport(request: httpx.Request):
            captured_requests.append(request)
            return httpx.Response(
                200,
                json=_make_json_api_response(),
                headers={"content-type": "application/vnd.api+json"},
            )

        tools = await hosted_server.get_tools()
        openapi_tool = tools.get("listAlerts") or tools.get("listEnvironments")
        assert openapi_tool is not None

        openapi_tool._client.client = httpx.AsyncClient(
            transport=httpx.MockTransport(capture_transport),
            base_url="https://api.rootly.com",
        )

        await openapi_tool.run({})

        assert len(captured_requests) >= 1
        outgoing = captured_requests[0]
        # No auth should be injected when ContextVar is empty
        assert (
            outgoing.headers.get("authorization", "") == ""
        ), "Auth was injected despite empty ContextVar"
