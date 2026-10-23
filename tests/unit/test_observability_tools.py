"""Observability logs, log counts and patterns tools, end to end.

The tools are generated from the bundled swagger, so these drive the server
built from it with the HTTP client stubbed and check what reaches the API:
the filters, the time window, pagination and ``filter[flagged]=false``, plus
the ``meta`` and ``logs_query`` fields the follow-up calls depend on.
"""

from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest
from fastmcp import Client, FastMCP

from rootly_mcp_server.server import _provider_tool_inventory, create_rootly_mcp_server

pytestmark = pytest.mark.unit

SWAGGER_PATH = "src/rootly_mcp_server/data/swagger.json"
FROM = "2026-10-20T03:00:00Z"
TO = "2026-10-20T09:00:00Z"


def _body_for(path: str) -> dict[str, Any]:
    if path == "/v1/observability/logs/counts":
        return {
            "data": [
                {
                    "id": "service:checkout",
                    "type": "observability_log_counts",
                    "attributes": {
                        "value": "checkout",
                        "count": 1204,
                        "logs_query": "severity:error service:checkout",
                    },
                }
            ],
            "meta": {"group_by": "service", "total": 1204, "truncated": False},
        }
    if path == "/v1/observability/patterns":
        return {
            "data": [
                {
                    "id": "checkout:123",
                    "type": "observability_log_patterns",
                    "attributes": {
                        "template": "payment failed for <*>",
                        "logs_query": "service:checkout pattern:123",
                    },
                }
            ],
            "meta": {"flagged": False, "sort": "change", "truncated": False},
        }
    return {
        "data": [{"id": "log-1", "type": "observability_logs", "attributes": {"body": "x"}}],
        "meta": {"page": {"size": 10, "next_cursor": "next-1"}, "truncated": True},
    }


@pytest.fixture
def server(monkeypatch) -> FastMCP:
    monkeypatch.setenv("ROOTLY_API_TOKEN", "test-token")
    return create_rootly_mcp_server(swagger_path=SWAGGER_PATH, hosted=False)


@pytest.fixture
def sent(server) -> list[httpx2.Request]:
    """Capture every upstream request instead of hitting the network."""
    _, provider, _ = _provider_tool_inventory(server)
    requests: list[httpx2.Request] = []

    async def fake_send(request, **kwargs):
        requests.append(request)
        return httpx2.Response(200, request=request, json=_body_for(request.url.path))

    next(iter(provider._tools.values()))._client.client.send = fake_send
    return requests


async def _call(server: FastMCP, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    async with Client(server) as client:
        result = await client.call_tool(tool, arguments, raise_on_error=False)
    text = " ".join(getattr(block, "text", "") for block in result.content)
    assert not result.is_error, text
    return json.loads(text)


def _params(sent: list[httpx2.Request], path: str) -> dict[str, str]:
    requests = [r for r in sent if r.url.path == path]
    assert len(requests) == 1, [str(r.url) for r in sent]
    return dict(requests[0].url.params)


async def test_list_logs_sends_filters_window_and_cursor(server, sent):
    body = await _call(
        server,
        "list_observability_logs",
        {
            "filter_query": "service:checkout severity:error",
            "filter_from": FROM,
            "filter_to": TO,
            "page_size": 10,
            "page_cursor": "cursor-1",
        },
    )

    assert _params(sent, "/v1/observability/logs") == {
        "filter[query]": "service:checkout severity:error",
        "filter[from]": FROM,
        "filter[to]": TO,
        "page[size]": "10",
        "page[cursor]": "cursor-1",
    }
    assert body["meta"]["page"]["next_cursor"] == "next-1"
    assert body["meta"]["truncated"] is True


async def test_count_logs_sends_group_by_and_returns_follow_up_queries(server, sent):
    body = await _call(
        server,
        "count_observability_logs",
        {"group_by": "service", "filter_query": "severity:error", "filter_from": FROM},
    )

    params = _params(sent, "/v1/observability/logs/counts")
    assert params["group_by"] == "service"
    assert params["filter[query]"] == "severity:error"
    assert params["filter[from]"] == FROM
    assert "filter[to]" not in params
    assert body["data"][0]["attributes"]["logs_query"] == "severity:error service:checkout"
    assert body["meta"]["total"] == 1204


async def test_list_patterns_sends_flagged_false_and_sort(server, sent):
    body = await _call(
        server,
        "list_observability_patterns",
        {
            "filter_query": "service:checkout",
            "filter_from": FROM,
            "filter_to": TO,
            "filter_flagged": False,
            "sort": "change",
            "page_size": 5,
        },
    )

    assert _params(sent, "/v1/observability/patterns") == {
        "filter[query]": "service:checkout",
        "filter[from]": FROM,
        "filter[to]": TO,
        "filter[flagged]": "false",
        "sort": "change",
        "page[size]": "5",
    }
    assert body["data"][0]["attributes"]["logs_query"] == "service:checkout pattern:123"
    assert body["meta"]["flagged"] is False
