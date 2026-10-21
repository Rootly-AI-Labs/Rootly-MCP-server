"""The Rootly API client is httpx2, as FastMCP 4's OpenAPI provider expects.

FastMCP 4 types the OpenAPI client as ``httpx2.AsyncClient`` and deprecates
legacy ``httpx`` clients there. These tests pin that the client we hand it is
httpx2 all the way down, and that the swap did not change what goes on the
wire or how failures surface.
"""

import ssl
import warnings
from unittest.mock import patch

import certifi
import httpx2
import pytest
from fastmcp._warnings import FastMCPDeprecationWarning
from fastmcp.server.providers.openapi.provider import _is_legacy_httpx_client

from rootly_mcp_server import transport
from rootly_mcp_server.server import create_rootly_mcp_server
from rootly_mcp_server.transport import AuthenticatedHTTPXClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(AuthenticatedHTTPXClient, "_get_api_token", lambda _: "test-token")
    return AuthenticatedHTTPXClient(base_url="https://api.rootly.com")


def _capture(client: AuthenticatedHTTPXClient) -> list[httpx2.Request]:
    """Route the inner client through a MockTransport and record each request."""
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(
            200, json={"data": []}, headers={"content-type": "application/vnd.api+json"}
        )

    client.client._transport = httpx2.MockTransport(handler)
    return seen


def test_inner_client_is_httpx2(client):
    assert isinstance(client.client, httpx2.AsyncClient)
    # The check FastMCP uses to decide whether to warn and, later, to refuse.
    assert not _is_legacy_httpx_client(client.client)
    assert not _is_legacy_httpx_client(client)


def test_requests_fastmcp_builds_through_the_wrapper_are_httpx2(client):
    request = client.build_request("GET", "/v1/incidents", params=[("page[size]", "5")])
    assert isinstance(request, httpx2.Request)


def test_creating_the_server_emits_no_fastmcp_deprecation(monkeypatch):
    monkeypatch.setenv("ROOTLY_API_TOKEN", "test-token")
    with warnings.catch_warnings():
        warnings.simplefilter("error", FastMCPDeprecationWarning)
        create_rootly_mcp_server(enabled_tools={"list_teams"})


def test_accept_encoding_matches_legacy_httpx(client):
    # httpx2 would add zstd on Python 3.14; legacy httpx never advertised it.
    assert client.client.headers["accept-encoding"] == "gzip, deflate, br"


@pytest.mark.asyncio
async def test_autogen_path_sends_the_same_headers_as_before(client):
    seen = _capture(client)
    built = client.build_request("GET", "/v1/teams", params=[("filter_name", "Platform")])
    await client.send(built)

    (sent,) = seen
    assert str(sent.url) == "https://api.rootly.com/v1/teams?filter_name=Platform"
    assert sorted((k.lower(), v) for k, v in sent.headers.items()) == [
        ("accept", "application/vnd.api+json"),
        ("accept-encoding", "gzip, deflate, br"),
        ("authorization", "Bearer test-token"),
        ("connection", "keep-alive"),
        ("content-type", "application/vnd.api+json"),
        ("host", "api.rootly.com"),
        ("user-agent", sent.headers["user-agent"]),
    ]
    assert sent.headers["user-agent"].startswith("rootly-mcp-server/")


@pytest.mark.asyncio
async def test_curated_path_sends_the_same_headers_as_before(client):
    seen = _capture(client)
    await client.request("POST", "/v1/incidents", json={"data": {"type": "incidents"}})

    (sent,) = seen
    assert sent.headers["content-type"] == "application/vnd.api+json"
    assert sent.headers["accept"] == "application/vnd.api+json"
    assert sent.headers["accept-encoding"] == "gzip, deflate, br"
    assert sent.headers["authorization"] == "Bearer test-token"
    assert sent.content == b'{"data":{"type":"incidents"}}'


@pytest.mark.asyncio
async def test_transport_errors_are_httpx2_errors(client):
    # FastMCP's OpenAPI tools and our shift-page retry both catch httpx2
    # exception types, so the client must raise those, not legacy httpx ones.
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("connection reset", request=request)

    client.client._transport = httpx2.MockTransport(handler)
    with pytest.raises(httpx2.TransportError):
        await client.send(client.build_request("GET", "/v1/teams"))
    with pytest.raises(httpx2.TransportError):
        await client.request("GET", "/v1/teams")


class TestUpstreamSSLContext:
    """httpx2 defaults to the OS trust store; we keep legacy httpx's certifi roots."""

    def test_defaults_to_certifi(self, monkeypatch):
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        with patch.object(ssl, "create_default_context", wraps=ssl.create_default_context) as ctx:
            transport._upstream_ssl_context()
        ctx.assert_called_once_with(cafile=certifi.where())

    def test_honors_ssl_cert_file(self, monkeypatch):
        monkeypatch.setenv("SSL_CERT_FILE", certifi.where())
        monkeypatch.setenv("SSL_CERT_DIR", "/nonexistent")
        with patch.object(ssl, "create_default_context", wraps=ssl.create_default_context) as ctx:
            transport._upstream_ssl_context()
        ctx.assert_called_once_with(cafile=certifi.where())

    def test_honors_ssl_cert_dir(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
        with patch.object(ssl, "create_default_context", wraps=ssl.create_default_context) as ctx:
            transport._upstream_ssl_context()
        ctx.assert_called_once_with(capath=str(tmp_path))
