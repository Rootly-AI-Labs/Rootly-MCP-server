"""Direct tools/call argument repair for curated tools (ToolArgumentAliasMiddleware).

Sentry showed ~43 direct ``list_incidents`` calls a day failing with pydantic's
bare "Unexpected keyword argument": models send the raw Rootly API's query
shapes (``filter[status]``, ``page[size]``, ``filter_started_at={"gte": ...}``,
``filters={...}``) or near-miss names (``search``, ``start_time``). These drive
the production server built from the bundled swagger with the HTTP client
stubbed, so each rewrite is checked end to end: the call succeeds and the
upstream request carries the filter the caller meant.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated, Any

import httpx2
import pytest
from fastmcp import Client, FastMCP
from pydantic import AliasChoices, Field

from rootly_mcp_server.server import (
    ToolArgumentAliasMiddleware,
    _provider_tool_inventory,
    create_rootly_mcp_server,
)
from rootly_mcp_server.tool_arguments import normalize_tool_arguments, validation_aliases

pytestmark = pytest.mark.unit

SWAGGER_PATH = "src/rootly_mcp_server/data/swagger.json"


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
        return httpx2.Response(200, request=request, json={"data": [], "meta": {}})

    # Curated and autogen tools share the same wrapper client.
    next(iter(provider._tools.values()))._client.client.send = fake_send
    return requests


def _text(result: Any) -> str:
    return " ".join(getattr(block, "text", "") for block in result.content)


async def _call(server: FastMCP, tool: str, arguments: dict[str, Any]) -> Any:
    async with Client(server) as client:
        return await client.call_tool(tool, arguments, raise_on_error=False)


def _incident_params(sent: list[httpx2.Request]) -> dict[str, str]:
    requests = [r for r in sent if r.url.path == "/v1/incidents"]
    assert requests, [str(r.url) for r in sent]
    return dict(requests[-1].url.params)


# ---------------------------------------------------------------------------
# Every Sentry shape, end to end against list_incidents
# ---------------------------------------------------------------------------

_TS1 = "2026-10-01T00:00:00Z"
_TS2 = "2026-10-21T00:00:00Z"
_STRICT_AFTER = "started_after is inclusive (>=); there is no strict-after filter"
_STRICT_BEFORE = "started_before is inclusive (<=); there is no strict-before filter"


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ({"filter[status]": "resolved"}, {"filter[status]": "resolved"}),
        ({"filter_status": "resolved"}, {"filter[status]": "resolved"}),
        ({"page[size]": 5}, {"page[size]": "5"}),
        ({"page[number]": 3}, {"page[number]": "3"}),
        ({"filter_started_at_gte": _TS1}, {"filter[started_at][gte]": _TS1}),
        ({"filter[started_at][gte]": _TS1}, {"filter[started_at][gte]": _TS1}),
        (
            {"filter_started_at": {"gte": _TS1, "lte": _TS2}},
            {"filter[started_at][gte]": _TS1, "filter[started_at][lte]": _TS2},
        ),
        (
            {"start_time": _TS1, "end_time": _TS2},
            {"filter[started_at][gte]": _TS1, "filter[started_at][lte]": _TS2},
        ),
        ({"filter_services": ["svc-1", "svc-2"]}, {"filter[service_ids]": "svc-1,svc-2"}),
        ({"filter_service_ids": ["svc-1", "svc-2"]}, {"filter[service_ids]": "svc-1,svc-2"}),
        ({"service_ids": ["svc-1", "svc-2"]}, {"filter[service_ids]": "svc-1,svc-2"}),
        (
            {
                "filters": {
                    "status": "resolved",
                    "started_at": {"gte": _TS1},
                    "service_ids": ["svc-1"],
                }
            },
            {
                "filter[status]": "resolved",
                "filter[started_at][gte]": _TS1,
                "filter[service_ids]": "svc-1",
            },
        ),
        (
            {"filter": {"filter[status]": "mitigated", "page[size]": 7}},
            {"filter[status]": "mitigated", "page[size]": "7"},
        ),
        ({"search": "database"}, {"filter[search]": "database"}),
        ({"max_results": 4}, {"page[size]": "4"}),
    ],
    ids=[
        "filter[status]",
        "filter_status",
        "page[size]",
        "page[number]",
        "filter_started_at_gte",
        "filter[started_at][gte]",
        "filter_started_at-range-dict",
        "start_time+end_time",
        "filter_services-list",
        "filter_service_ids-list",
        "service_ids-list",
        "filters-dict",
        "filter-dict-of-api-keys",
        "search",
        "max_results",
    ],
)
async def test_sentry_shapes_are_rewritten_and_the_call_succeeds(server, sent, arguments, expected):
    result = await _call(server, "list_incidents", arguments)

    assert not result.is_error, _text(result)
    params = _incident_params(sent)
    for key, value in expected.items():
        assert params.get(key) == value, (key, params)


async def test_max_results_reaches_page_size_on_a_tool_without_its_own_alias(server, sent):
    # list_incident_post_mortems takes page_size but declares no max_results
    # alias, so the generic repair has to cover it.
    result = await _call(server, "list_incident_post_mortems", {"max_results": 5})

    assert not result.is_error, _text(result)
    requests = [r for r in sent if r.url.path == "/v1/post_mortems"]
    assert requests, [str(r.url) for r in sent]
    assert dict(requests[-1].url.params).get("page[size]") == "5"


async def test_max_results_inside_a_filters_dict_reaches_page_size(server, sent):
    # Keys inside filters={...} never see pydantic validation aliases.
    result = await _call(server, "list_incidents", {"filters": {"max_results": 6}})

    assert not result.is_error, _text(result)
    assert _incident_params(sent).get("page[size]") == "6"


async def test_explicit_value_is_never_overwritten(server, sent):
    result = await _call(
        server, "list_incidents", {"status": "resolved", "filter[status]": "resolved"}
    )
    assert not result.is_error, _text(result)
    assert _incident_params(sent)["filter[status]"] == "resolved"

    result = await _call(
        server, "list_incidents", {"status": "resolved", "filter_status": "started"}
    )
    text = _text(result)
    assert result.is_error
    assert "'filter_status' (conflicts with 'status', which is also set)" in text
    # Nothing reached the API with either value.
    assert len([r for r in sent if r.url.path == "/v1/incidents"]) == 1


async def test_range_dict_does_not_overwrite_an_explicit_bound(server, sent):
    result = await _call(
        server,
        "list_incidents",
        {"started_after": _TS1, "filter_started_at": {"gte": _TS2, "lte": _TS2}},
    )

    assert result.is_error
    assert "conflicts with 'started_after'" in _text(result)
    assert not sent


# ---------------------------------------------------------------------------
# What cannot be mapped is explained, never guessed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (
            {"filter_updated_at": {"gte": _TS1}},
            "'filter_updated_at' (there is no updated-time filter)",
        ),
        (
            {"filter[updated_at][gte]": _TS1},
            "'filter[updated_at][gte]' (there is no updated-time filter)",
        ),
        (
            {"filters": {"updated_at": {"gte": _TS1}}},
            "'filters.updated_at' (there is no updated-time filter)",
        ),
        ({"include": "services"}, "'include' (related records cannot be side-loaded"),
        (
            {"filter_started_at": _TS1},
            "'filter_started_at' (use 'started_after' and/or 'started_before'",
        ),
        ({"since": _TS1}, "'since' (did you mean 'started_after'?)"),
        ({"bogus": 1}, "list_incidents does not accept 'bogus'."),
        # Strict bounds: started_after/started_before are inclusive, so a
        # gt/lt cannot be rewritten without widening the range.
        ({"filter[started_at][gt]": _TS1}, f"'filter[started_at][gt]' ({_STRICT_AFTER}"),
        ({"filter[started_at][lt]": _TS2}, f"'filter[started_at][lt]' ({_STRICT_BEFORE}"),
        ({"filter_started_at_gt": _TS1}, f"'filter_started_at_gt' ({_STRICT_AFTER}"),
        ({"started_at_lt": _TS2}, f"'started_at_lt' ({_STRICT_BEFORE}"),
        ({"filter_started_at": {"gt": _TS1}}, f"'filter_started_at' ({_STRICT_AFTER}"),
        (
            {"filter_started_at": {"gte": _TS1, "lt": _TS2}},
            f"'filter_started_at' ({_STRICT_BEFORE}",
        ),
        ({"filters": {"started_at": {"gt": _TS1}}}, f"'filters.started_at' ({_STRICT_AFTER}"),
    ],
)
async def test_unmappable_arguments_get_a_legible_error(server, sent, arguments, expected):
    result = await _call(server, "list_incidents", arguments)

    text = _text(result)
    assert result.is_error
    assert text.startswith("list_incidents does not accept "), text
    assert expected in text
    assert "Valid parameters for list_incidents (* = required): query, teams," in text
    assert "errors.pydantic.dev" not in text
    assert not sent


async def test_updated_filter_points_at_the_sort_that_exists(server, sent):
    result = await _call(server, "list_incidents", {"filter_updated_at": {"gte": _TS1}})

    assert "pass sort='-updated_at'" in _text(result)


async def test_partially_mappable_call_is_rejected_whole(server, sent):
    result = await _call(server, "list_incidents", {"filter[status]": "resolved", "include": "x"})

    text = _text(result)
    assert result.is_error
    assert "'include'" in text
    assert "filter[status]" not in text
    assert not sent


async def test_required_parameters_are_starred(server, sent):
    result = await _call(server, "get_incident", {"incident_id": "1", "bogus": True})

    text = _text(result)
    assert result.is_error
    assert "get_incident does not accept 'bogus'." in text
    assert "Valid parameters for get_incident (* = required): incident_id*" in text


# ---------------------------------------------------------------------------
# Names a tool already accepts through pydantic validation aliases
# ---------------------------------------------------------------------------


def _rejected_by_middleware(text: str) -> bool:
    return " does not accept " in text or "Unexpected keyword argument" in text


def _sample_value(spec: dict[str, Any], name: str) -> Any:
    if spec.get("type") == "integer":
        return 2
    if spec.get("type") == "number":
        return 0.5
    if spec.get("type") == "boolean":
        return False
    if "date" in name or name.endswith(("_at", "_after", "_before")) or "time" in name:
        return _TS1
    return "1"


async def _alias_cases(server: FastMCP) -> list[tuple[str, str, str, dict[str, Any]]]:
    """(tool, alias, parameter, arguments) for every curated tool's every alias."""
    curated, _, _ = _provider_tool_inventory(server)
    cases: list[tuple[str, str, str, dict[str, Any]]] = []
    for name in sorted(curated):
        tool = await server.get_tool(name)
        if tool is None:
            continue
        schema = tool.parameters or {}
        properties = schema.get("properties") or {}
        required = {
            param: _sample_value(properties.get(param) or {}, param)
            for param in schema.get("required") or []
        }
        for alias, parameter in validation_aliases(getattr(tool, "fn", None)).items():
            arguments = {k: v for k, v in required.items() if k != parameter}
            arguments[alias] = _sample_value(properties.get(parameter) or {}, parameter)
            cases.append((name, alias, parameter, arguments))
    return cases


async def test_every_declared_validation_alias_is_accepted(server, sent):
    cases = await _alias_cases(server)
    # The aliases declared in tools/ today; a new one is picked up automatically.
    declared = {(tool, alias) for tool, alias, _, _ in cases}
    assert {
        ("get_schedule_shifts", "from_date"),
        ("get_schedule_shifts", "to"),
        ("list_shifts", "start_date"),
        ("list_shifts", "end_date"),
        ("get_incident_meeting_transcripts", "id"),
        ("list_incidents", "max_results"),
        ("list_incidents", "limit"),
        ("suggest_solutions", "max_results"),
    } <= declared

    rejected = []
    async with Client(server) as client:
        for tool, alias, parameter, arguments in cases:
            result = await client.call_tool(tool, arguments, raise_on_error=False)
            if result.is_error and _rejected_by_middleware(_text(result)):
                rejected.append((tool, alias, parameter, _text(result)))
    assert rejected == []


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("get_schedule_shifts", {"id": "s1", "from_date": _TS1, "to_date": _TS2}),
        ("list_shifts", {"start_date": _TS1, "end_date": _TS2}),
        ("get_incident_meeting_transcripts", {"id": "inc-1"}),
    ],
)
async def test_reported_alias_calls_are_not_rejected(server, sent, tool, arguments):
    result = await _call(server, tool, arguments)

    assert not _rejected_by_middleware(_text(result)), _text(result)
    assert sent, "the call should reach the API"


async def test_accepted_alias_is_neither_rewritten_nor_overridden(server, sent):
    # `limit` is list_incidents' own alias of page_size: kept as sent, and a
    # page[size] alias for the same parameter cannot overwrite it.
    result = await _call(server, "list_incidents", {"limit": 3})
    assert not result.is_error, _text(result)
    assert _incident_params(sent)["page[size]"] == "3"

    result = await _call(server, "list_incidents", {"limit": 3, "page[size]": 9})
    assert result.is_error
    assert "'page[size]' (conflicts with 'page_size', which is also set)" in _text(result)


def test_validation_aliases_reads_annotated_field_metadata():
    def tool(
        start: Annotated[str, Field(validation_alias=AliasChoices("start", "from"))] = "",
        size: Annotated[int, Field(alias="limit")] = 1,
        plain: str = "",
    ) -> str:
        return ""

    assert validation_aliases(tool) == {"from": "start", "limit": "size"}
    assert validation_aliases(None) == {}


# ---------------------------------------------------------------------------
# Scope: curated tools only, no double handling
# ---------------------------------------------------------------------------


async def test_openapi_tools_are_untouched(server, sent):
    # Autogen tools take the API's own filter names; this middleware must not
    # rename them nor reject what FastMCP's OpenAPI layer accepts.
    result = await _call(server, "list_services", {"filter_name": "api", "bogus": 1})

    assert not result.is_error, _text(result)
    services = [r for r in sent if r.url.path == "/v1/services"]
    assert services and services[-1].url.params.get("filter[name]") == "api"


async def test_openapi_missing_path_argument_keeps_its_own_error(server, sent):
    result = await _call(server, "get_alert", {"alert_id": "a1"})

    text = _text(result)
    assert result.is_error
    assert text.startswith("get_alert requires the path argument 'id'"), text


def test_scope_is_the_registered_curated_tools(server):
    middleware = next(m for m in server.middleware if isinstance(m, ToolArgumentAliasMiddleware))
    curated, _, autogen = _provider_tool_inventory(server)

    scope = middleware.tool_names
    assert scope is not None
    assert scope == frozenset(curated)
    assert "list_incidents" in scope
    assert not set(scope) & autogen


async def test_valid_call_passes_through_unchanged(server, sent):
    result = await _call(server, "list_incidents", {"status": "resolved", "page_size": 2})

    assert not result.is_error, _text(result)
    params = _incident_params(sent)
    assert params["filter[status]"] == "resolved"
    assert params["page[size]"] == "2"


# ---------------------------------------------------------------------------
# Measurement: rewrites are logged
# ---------------------------------------------------------------------------


async def test_rewrites_are_recorded_in_tool_usage_log(server, sent, caplog, monkeypatch):
    monkeypatch.setenv("ROOTLY_TOOL_USAGE_LOGGING", "true")
    records: list[str] = []
    usage_logger = logging.getLogger("rootly_mcp_server.tool_usage_json")

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    handler = _Capture()
    usage_logger.addHandler(handler)
    try:
        with caplog.at_level(logging.DEBUG, logger="rootly_mcp_server.server"):
            result = await _call(
                server, "list_incidents", {"filter[status]": "resolved", "page[size]": 3}
            )
    finally:
        usage_logger.removeHandler(handler)

    assert not result.is_error, _text(result)
    assert any(
        "Normalized list_incidents arguments: filter[status]->status, page[size]->page_size"
        in message
        for message in caplog.messages
    )
    events = [json.loads(message) for message in records if '"mcp_tool_call"' in message]
    assert events, records
    # The raw keys the caller sent, next to what they were rewritten to.
    assert events[-1]["tool_arg_keys"] == ["filter[status]", "page[size]"]
    assert events[-1]["tool_arg_rewrites"] == [
        "filter[status]->status",
        "page[size]->page_size",
    ]


# ---------------------------------------------------------------------------
# Unit: the normalizer against a schema
# ---------------------------------------------------------------------------

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "query": {"type": "string"},
        "status": {"type": "string"},
        "service_ids": {"type": "string", "description": "Comma-separated service IDs"},
        "labels": {"type": "string", "description": "Free text"},
        "started_after": {"type": "string"},
        "page_size": {"type": "integer"},
    },
}


def test_normalizer_only_targets_declared_parameters():
    result = normalize_tool_arguments(
        {"filter_started_at": {"gte": _TS1, "lte": _TS2}, "page[number]": 2}, _SCHEMA
    )

    # started_before and page_number are not declared: nothing is invented.
    assert set(result.unknown) == {"filter_started_at", "page[number]"}
    assert "started_after" not in result.arguments


def test_normalizer_coerces_lists_only_for_comma_separated_strings():
    result = normalize_tool_arguments({"service_ids": ["a", 1], "labels": ["x", "y"]}, _SCHEMA)

    assert result.arguments["service_ids"] == "a,1"
    assert result.arguments["labels"] == ["x", "y"]
    assert result.rewrites == ["service_ids:list->csv"]


def test_normalizer_keeps_declared_names_verbatim():
    schema = {**_SCHEMA, "properties": {**_SCHEMA["properties"], "filter_status": {}}}
    result = normalize_tool_arguments({"filter_status": "x"}, schema)

    assert result.arguments == {"filter_status": "x"}
    assert not result.rewrites and not result.unknown


# ---------------------------------------------------------------------------
# Without a curated-name scope, any non-OpenAPI tool is handled
# ---------------------------------------------------------------------------


async def test_bare_server_handles_every_function_tool():
    server = FastMCP("test")
    server.add_middleware(ToolArgumentAliasMiddleware())

    @server.tool
    def list_things(query: str = "", page_size: int = 10) -> str:
        return f"query={query} page_size={page_size}"

    async with Client(server) as client:
        result = await client.call_tool("list_things", {"search": "db", "page[size]": 3})

    assert result.data == "query=db page_size=3"


# ---------------------------------------------------------------------------
# Code Mode: call_tool reaches the same middleware chain
# ---------------------------------------------------------------------------


async def test_code_mode_call_tool_gets_the_same_rewrites(monkeypatch):
    from rootly_mcp_server.code_mode import create_rootly_codemode_server

    monkeypatch.setenv("ROOTLY_API_TOKEN", "test-token")
    server = create_rootly_codemode_server(swagger_path=SWAGGER_PATH, hosted=False)
    _, provider, _ = _provider_tool_inventory(server)
    requests: list[httpx2.Request] = []

    async def fake_send(request, **kwargs):
        requests.append(request)
        return httpx2.Response(200, request=request, json={"data": [], "meta": {}})

    next(iter(provider._tools.values()))._client.client.send = fake_send
    code = (
        "return await call_tool('list_incidents', "
        f"{{'filter[status]': 'resolved', 'start_time': '{_TS1}'}})"
    )

    result = await _call(server, "execute", {"code": code})

    assert not result.is_error, _text(result)
    params = _incident_params(requests)
    assert params["filter[status]"] == "resolved"
    assert params["filter[started_at][gte]"] == _TS1
