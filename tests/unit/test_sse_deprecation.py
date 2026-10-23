"""SSE deprecation: headers, per-connection logging, instructions and CLI warning."""

from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import httpx2 as httpx
import pytest
from fastmcp import FastMCP
from starlette.middleware import Middleware

from rootly_mcp_server import sse_deprecation
from rootly_mcp_server.__main__ import build_dual_http_app, main
from rootly_mcp_server.sse_deprecation import (
    DEPRECATION_HEADER_VALUE,
    LINK_HEADER_VALUE,
    SSE_DEPRECATION_NOTICE,
    SUNSET_HEADER_VALUE,
    SSEDeprecationMiddleware,
    with_sse_deprecation_instructions,
)
from rootly_mcp_server.transport import AuthCaptureMiddleware

VALID_AUTH = "Bearer rootly_valid_token"
DEPRECATION_HEADERS = ("deprecation", "sunset", "link")


def test_header_values_follow_the_rfcs():
    # RFC 9745 Structured Field Date for 2026-10-21T00:00:00Z.
    assert DEPRECATION_HEADER_VALUE == "@1792540800"
    # RFC 8594 HTTP-date.
    assert SUNSET_HEADER_VALUE == "Fri, 20 Nov 2026 00:00:00 GMT"
    assert LINK_HEADER_VALUE == '<https://mcp.rootly.com/mcp>; rel="successor-version"'


def _scope(path: str, method: str = "GET", headers: list | None = None) -> dict[str, Any]:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": headers or [],
    }


def _headers(message: dict[str, Any]) -> dict[str, str]:
    return {k.decode(): v.decode() for k, v in message["headers"]}


@pytest.fixture
def json_log():
    with patch.object(sse_deprecation._deprecation_json_logger, "warning") as warning:
        yield warning


# --- Middleware in isolation -------------------------------------------------


async def test_middleware_streams_chunks_without_buffering(json_log):
    """Each body chunk reaches the client before the app produces the next."""
    forwarded: list[dict[str, Any]] = []
    chunk_seen = asyncio.Event()

    async def streaming_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/event-stream")],
            }
        )
        await send({"type": "http.response.body", "body": b"event: one\n\n", "more_body": True})
        # The wrapper must have forwarded chunk one already; a buffering
        # wrapper would deadlock here and trip the timeout.
        await asyncio.wait_for(chunk_seen.wait(), timeout=2)
        await send({"type": "http.response.body", "body": b"event: two\n\n", "more_body": False})

    async def send(message):
        forwarded.append(message)
        if message.get("body") == b"event: one\n\n":
            chunk_seen.set()

    app = SSEDeprecationMiddleware(streaming_app, sse_path="/sse", message_path="/messages/")
    await app(_scope("/sse"), AsyncMock(), send)

    assert [m["type"] for m in forwarded] == [
        "http.response.start",
        "http.response.body",
        "http.response.body",
    ]
    headers = _headers(forwarded[0])
    assert headers["content-type"] == "text/event-stream"
    assert headers["deprecation"] == DEPRECATION_HEADER_VALUE
    assert headers["sunset"] == SUNSET_HEADER_VALUE
    assert headers["link"] == LINK_HEADER_VALUE
    assert forwarded[1]["body"] == b"event: one\n\n"
    assert forwarded[2]["body"] == b"event: two\n\n"
    json_log.assert_called_once()


@pytest.mark.parametrize("path", ["/messages/", "/messages"])
async def test_middleware_marks_message_endpoint_without_logging_a_connection(path, json_log):
    sent: list[dict[str, Any]] = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 202, "headers": []})
        await send({"type": "http.response.body", "body": b"Accepted"})

    async def send(message):
        sent.append(message)

    middleware = SSEDeprecationMiddleware(app, sse_path="/sse", message_path="/messages/")
    await middleware(_scope(path, method="POST"), AsyncMock(), send)

    assert set(DEPRECATION_HEADERS) <= set(_headers(sent[0]))
    json_log.assert_not_called()


@pytest.mark.parametrize("path", ["/mcp", "/mcp-codemode", "/healthz", "/ssex"])
async def test_middleware_leaves_other_paths_alone(path, json_log):
    sent: list[dict[str, Any]] = []
    start = {"type": "http.response.start", "status": 200, "headers": [(b"x", b"y")]}

    async def app(scope, receive, send):
        await send(start)

    async def send(message):
        sent.append(message)

    await SSEDeprecationMiddleware(app)(_scope(path), AsyncMock(), send)

    assert sent == [start]
    json_log.assert_not_called()


async def test_connection_log_is_structured(json_log):
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})

    scope = _scope(
        "/sse",
        headers=[
            (b"user-agent", b"claude-desktop/1.2.3"),
            (b"x-forwarded-for", b"203.0.113.7, 10.0.0.1"),
            (b"x-request-id", b"req-123"),
            (b"authorization", VALID_AUTH.encode()),
        ],
    )
    scope["query_string"] = b"tool_profile=slim"
    await SSEDeprecationMiddleware(app)(scope, AsyncMock(), AsyncMock())

    json_log.assert_called_once()
    payload = json.loads(json_log.call_args.args[0])
    assert payload["event"] == "sse_deprecated_connection"
    assert payload["transport"] == "sse"
    assert payload["user_agent"] == "claude-desktop/1.2.3"
    assert payload["client_ip"] == "203.0.113.7"
    assert payload["request_id"] == "req-123"
    assert payload["tool_profile"] == "slim"
    assert payload["sunset"] == "2026-11-20"
    assert len(payload["token_fingerprint"]) == 16
    assert "rootly_valid_token" not in json_log.call_args.args[0]


async def test_rejected_stream_is_not_logged_as_a_connection(json_log):
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 401, "headers": []})

    await SSEDeprecationMiddleware(app)(_scope("/sse"), AsyncMock(), AsyncMock())
    json_log.assert_not_called()


def test_instructions_note_is_appended_to_existing_instructions():
    from mcp.server.models import InitializationOptions
    from mcp.types import ServerCapabilities

    base = InitializationOptions(
        server_name="Rootly",
        server_version="1",
        capabilities=ServerCapabilities(),
        instructions="Use the incident tools.",
    )
    updated = with_sse_deprecation_instructions(base)
    assert updated.instructions == f"Use the incident tools.\n\n{SSE_DEPRECATION_NOTICE}"
    assert base.instructions == "Use the incident tools."
    assert with_sse_deprecation_instructions(
        base.model_copy(update={"instructions": None})
    ).instructions == (SSE_DEPRECATION_NOTICE)


# --- The real dual-transport app ---------------------------------------------


@pytest.fixture
def dual_app():
    async def fake_validate(self, auth_header):
        if auth_header == VALID_AUTH:
            return {"id": "1", "email": "user@example.com"}
        return None

    server = FastMCP("Rootly test")

    @server.tool
    def ping() -> str:
        return "pong"

    code_mode = FastMCP("Rootly test Code Mode")
    with patch.object(AuthCaptureMiddleware, "_validate_token_upstream", fake_validate):
        yield build_dual_http_app(
            server,
            middleware=[Middleware(AuthCaptureMiddleware)],
            code_mode_server=code_mode,
            code_mode_path="/mcp-codemode",
        )


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/sse"), ("POST", "/messages/?session_id=00000000000000000000000000000000")],
)
async def test_unauthenticated_sse_responses_carry_deprecation_headers(dual_app, method, path):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=dual_app), base_url="http://test"
    ) as client:
        response = await client.request(method, path)

    assert response.status_code == 401
    assert response.headers["deprecation"] == DEPRECATION_HEADER_VALUE
    assert response.headers["sunset"] == SUNSET_HEADER_VALUE
    assert response.headers["link"] == LINK_HEADER_VALUE
    assert "www-authenticate" in response.headers


async def test_unknown_sse_session_post_carries_deprecation_headers(dual_app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=dual_app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/messages/?session_id=00000000000000000000000000000000",
            headers={"Authorization": VALID_AUTH},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )

    assert response.status_code == 404
    assert response.headers["sunset"] == SUNSET_HEADER_VALUE


@pytest.mark.parametrize("path", ["/mcp", "/mcp-codemode"])
async def test_streamable_http_surfaces_have_no_deprecation_headers(dual_app, path):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=dual_app), base_url="http://test"
    ) as client:
        response = await client.post(path, json={})

    assert response.status_code == 401
    for header in DEPRECATION_HEADERS:
        assert header not in response.headers


class _ASGIStream:
    """Drive a long-lived ASGI response by hand (httpx's ASGITransport buffers)."""

    def __init__(self, app, scope):
        self.app = app
        self.scope = scope
        self.messages: list[dict[str, Any]] = []
        self.body = b""
        self._disconnect = asyncio.Event()
        self._progress = asyncio.Condition()
        self.task: asyncio.Task | None = None

    async def _receive(self):
        await self._disconnect.wait()
        return {"type": "http.disconnect"}

    async def _send(self, message):
        async with self._progress:
            self.messages.append(message)
            if message["type"] == "http.response.body":
                self.body += message.get("body", b"")
            self._progress.notify_all()

    def start(self):
        self.task = asyncio.create_task(self.app(self.scope, self._receive, self._send))

    async def wait_for_body(self, needle: bytes, timeout: float = 5.0):
        async def _wait():
            async with self._progress:
                await self._progress.wait_for(lambda: needle in self.body)

        await asyncio.wait_for(_wait(), timeout)

    async def close(self):
        self._disconnect.set()
        assert self.task is not None
        try:
            await asyncio.wait_for(self.task, timeout=5)
        except (asyncio.CancelledError, Exception):
            pass


async def test_sse_stream_still_delivers_events_and_instructions(dual_app, json_log):
    stream = _ASGIStream(
        dual_app,
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/sse",
            "raw_path": b"/sse",
            "root_path": "",
            "query_string": b"",
            "server": ("test", 80),
            "client": ("127.0.0.1", 1234),
            "headers": [
                (b"host", b"test"),
                (b"accept", b"text/event-stream"),
                (b"authorization", VALID_AUTH.encode()),
                (b"user-agent", b"legacy-sse-client/0.1"),
            ],
        },
    )
    stream.start()
    try:
        await stream.wait_for_body(b"event: endpoint")
        start = next(m for m in stream.messages if m["type"] == "http.response.start")
        assert start["status"] == 200
        headers = _headers(start)
        assert headers["content-type"].startswith("text/event-stream")
        assert headers["deprecation"] == DEPRECATION_HEADER_VALUE
        assert headers["sunset"] == SUNSET_HEADER_VALUE

        endpoint_line = next(
            line
            for line in stream.body.decode().splitlines()
            if line.startswith("data: /messages/")
        )
        message_uri = endpoint_line.removeprefix("data: ").strip()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=dual_app), base_url="http://test"
        ) as client:
            response = await client.post(
                message_uri,
                headers={"Authorization": VALID_AUTH},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "legacy", "version": "0.1"},
                    },
                },
            )
        assert response.status_code == 202
        assert response.headers["deprecation"] == DEPRECATION_HEADER_VALUE

        await stream.wait_for_body(b'"instructions"')
        message_line = next(
            line
            for line in stream.body.decode().splitlines()
            if line.startswith("data: {") and '"instructions"' in line
        )
        result = json.loads(message_line.removeprefix("data: "))["result"]
        assert result["instructions"] == SSE_DEPRECATION_NOTICE
    finally:
        await stream.close()

    # One connection, two requests (stream + POST): exactly one warning.
    json_log.assert_called_once()
    assert json.loads(json_log.call_args.args[0])["user_agent"] == "legacy-sse-client/0.1"


# --- CLI ---------------------------------------------------------------------


def _cli_args(transport: str) -> SimpleNamespace:
    return SimpleNamespace(
        swagger_path=None,
        log_level="ERROR",
        name="Rootly",
        transport=transport,
        debug=False,
        base_url=None,
        allowed_paths=None,
        hosted=False,
        enable_code_mode=False,
        enable_write_tools=True,
        enabled_tools=None,
        list_tools=False,
        code_mode_path=None,
        host=False,
    )


@pytest.mark.parametrize("transport", ["sse", "streamable-http"])
def test_cli_warns_only_for_sse_transport_and_keeps_it_working(transport, caplog):
    main_server = SimpleNamespace(run=Mock())
    with patch.dict("os.environ", {"ROOTLY_API_TOKEN": "rootly_test"}, clear=True):
        with patch("rootly_mcp_server.__main__.parse_args", return_value=_cli_args(transport)):
            with patch("rootly_mcp_server.__main__.setup_logging"):
                with patch("rootly_mcp_server.__main__.check_api_token"):
                    with patch(
                        "rootly_mcp_server.__main__.create_rootly_mcp_server",
                        return_value=main_server,
                    ):
                        with patch(
                            "rootly_mcp_server.__main__.get_hosted_auth_middleware",
                            return_value=None,
                        ):
                            with caplog.at_level(logging.WARNING, "rootly_mcp_server"):
                                main()

    warned = [r for r in caplog.records if "transport is deprecated" in r.getMessage()]
    main_server.run.assert_called_once()
    run_kwargs = main_server.run.call_args.kwargs
    assert run_kwargs["transport"] == transport
    if transport == "sse":
        assert len(warned) == 1
        assert "2026-11-20" in warned[0].getMessage()
        assert "--transport streamable-http" in warned[0].getMessage()
        assert run_kwargs["middleware"][0].cls is SSEDeprecationMiddleware
    else:
        assert warned == []
        assert run_kwargs["middleware"] is None
