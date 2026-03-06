"""Focused tests for transport module."""

from unittest.mock import patch

import pytest

from rootly_mcp_server import transport


class TestTransportModule:
    """Direct tests for extracted transport/auth helpers."""

    @pytest.mark.asyncio
    async def test_auth_capture_middleware_sets_token_for_sse(self):
        async def app(scope, receive, send):
            return None

        middleware = transport.AuthCaptureMiddleware(app)
        scope = {
            "type": "http",
            "path": "/sse",
            "headers": [(b"authorization", b"Bearer test-token")],
        }

        # Ensure a known baseline in this context.
        transport._session_auth_token.set("")
        transport._session_transport.set("")

        async def receive():
            return {"type": "http.request"}

        async def send(_message):
            return None

        await middleware(scope, receive, send)
        assert transport._session_auth_token.get() == "Bearer test-token"
        assert transport._session_transport.get() == "sse"

    @pytest.mark.asyncio
    async def test_auth_capture_middleware_sets_token_for_streamable_http(self):
        async def app(scope, receive, send):
            return None

        middleware = transport.AuthCaptureMiddleware(app)
        scope = {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"authorization", b"Bearer streamable-token")],
        }

        transport._session_auth_token.set("")
        transport._session_transport.set("")

        async def receive():
            return {"type": "http.request"}

        async def send(_message):
            return None

        await middleware(scope, receive, send)
        assert transport._session_auth_token.get() == "Bearer streamable-token"
        assert transport._session_transport.get() == "streamable-http"

    @pytest.mark.asyncio
    async def test_auth_capture_middleware_sets_transport_for_messages_path(self):
        async def app(scope, receive, send):
            return None

        middleware = transport.AuthCaptureMiddleware(app)
        scope = {
            "type": "http",
            "path": "/messages",
            "headers": [(b"authorization", b"Bearer sse-message-token")],
        }

        transport._session_auth_token.set("")
        transport._session_transport.set("")

        async def receive():
            return {"type": "http.request"}

        async def send(_message):
            return None

        await middleware(scope, receive, send)
        assert transport._session_auth_token.get() == "Bearer sse-message-token"
        assert transport._session_transport.get() == "sse"

    @pytest.mark.asyncio
    async def test_auth_capture_middleware_sets_transport_for_code_mode_path(self):
        async def app(scope, receive, send):
            return None

        middleware = transport.AuthCaptureMiddleware(app)
        scope = {
            "type": "http",
            "path": "/mcp-codemode",
            "headers": [(b"authorization", b"Bearer codemode-token")],
        }

        transport._session_auth_token.set("")
        transport._session_transport.set("")

        async def receive():
            return {"type": "http.request"}

        async def send(_message):
            return None

        await middleware(scope, receive, send)
        assert transport._session_auth_token.get() == "Bearer codemode-token"
        assert transport._session_transport.get() == "streamable-http"

    @pytest.mark.asyncio
    async def test_auth_capture_middleware_ignores_non_mcp_paths(self):
        async def app(scope, receive, send):
            return None

        middleware = transport.AuthCaptureMiddleware(app)
        scope = {
            "type": "http",
            "path": "/healthz",
            "headers": [(b"authorization", b"Bearer should-not-be-used")],
        }

        transport._session_auth_token.set("")
        transport._session_transport.set("")

        async def receive():
            return {"type": "http.request"}

        async def send(_message):
            return None

        await middleware(scope, receive, send)
        assert transport._session_auth_token.get() == ""
        assert transport._session_transport.get() == ""

    @pytest.mark.asyncio
    async def test_auth_capture_middleware_respects_custom_paths(self):
        async def app(scope, receive, send):
            return None

        with patch.dict(
            "os.environ",
            {
                "FASTMCP_SSE_PATH": "/custom-sse",
                "FASTMCP_MESSAGE_PATH": "/custom-messages",
                "FASTMCP_STREAMABLE_HTTP_PATH": "/custom-mcp",
                "ROOTLY_CODE_MODE_PATH": "/custom-codemode",
            },
        ):
            middleware = transport.AuthCaptureMiddleware(app)

        transport._session_auth_token.set("")
        transport._session_transport.set("")

        async def receive():
            return {"type": "http.request"}

        async def send(_message):
            return None

        custom_scope = {
            "type": "http",
            "path": "/custom-mcp",
            "headers": [(b"authorization", b"Bearer custom-token")],
        }
        await middleware(custom_scope, receive, send)
        assert transport._session_auth_token.get() == "Bearer custom-token"
        assert transport._session_transport.get() == "streamable-http"

        custom_message_scope = {
            "type": "http",
            "path": "/custom-messages",
            "headers": [(b"authorization", b"Bearer custom-message-token")],
        }
        await middleware(custom_message_scope, receive, send)
        assert transport._session_auth_token.get() == "Bearer custom-message-token"
        assert transport._session_transport.get() == "sse"

        custom_code_mode_scope = {
            "type": "http",
            "path": "/custom-codemode",
            "headers": [(b"authorization", b"Bearer custom-codemode-token")],
        }
        await middleware(custom_code_mode_scope, receive, send)
        assert transport._session_auth_token.get() == "Bearer custom-codemode-token"
        assert transport._session_transport.get() == "streamable-http"

    def test_infer_transport_from_path(self):
        assert (
            transport._infer_transport_from_path(
                "/sse", "/sse", "/messages", "/mcp", "/mcp-codemode"
            )
            == "sse"
        )
        assert (
            transport._infer_transport_from_path(
                "/messages", "/sse", "/messages", "/mcp", "/mcp-codemode"
            )
            == "sse"
        )
        assert (
            transport._infer_transport_from_path(
                "/mcp", "/sse", "/messages", "/mcp", "/mcp-codemode"
            )
            == "streamable-http"
        )
        assert (
            transport._infer_transport_from_path(
                "/mcp-codemode", "/sse", "/messages", "/mcp", "/mcp-codemode"
            )
            == "streamable-http"
        )
        assert (
            transport._infer_transport_from_path(
                "/healthz", "/sse", "/messages", "/mcp", "/mcp-codemode"
            )
            == ""
        )

    def test_authenticated_client_user_agent_contains_mode(self):
        with patch.object(transport.AuthenticatedHTTPXClient, "_get_api_token", return_value="token"):
            local_client = transport.AuthenticatedHTTPXClient(hosted=False, transport="stdio")
            hosted_client = transport.AuthenticatedHTTPXClient(hosted=True, transport="sse")

        local_ua = local_client.client.headers.get("User-Agent")
        hosted_ua = hosted_client.client.headers.get("User-Agent")

        assert local_ua is not None
        assert hosted_ua is not None
        assert "(stdio; self-hosted)" in local_ua
        assert "(sse; hosted)" in hosted_ua

    def test_strip_heavy_alert_data_keeps_whitelist_fields(self):
        data = {
            "data": [
                {
                    "id": "a-1",
                    "attributes": {
                        "short_id": "ABCD",
                        "summary": "CPU alarm",
                        "status": "triggered",
                        "source": "datadog",
                        "created_at": "2026-02-20T00:00:00Z",
                        "labels": [{"name": "prod"}],
                        "extra": "remove-me",
                    },
                    "relationships": {"alerts": {"data": [{"id": "x-1"}, {"id": "x-2"}]}},
                }
            ],
            "included": [{"id": "heavy"}],
        }

        result = transport.strip_heavy_alert_data(data)
        attrs = result["data"][0]["attributes"]
        assert attrs["short_id"] == "ABCD"
        assert attrs["summary"] == "CPU alarm"
        assert "extra" not in attrs
        assert "labels" not in attrs
        assert result["data"][0]["relationships"]["alerts"] == {"count": 2}
        assert "included" not in result
