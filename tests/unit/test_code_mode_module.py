"""Tests for Rootly Code Mode helpers."""

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.experimental.transforms.code_mode import CodeMode, MontySandboxProvider
from fastmcp.tools.function_tool import FunctionTool

from rootly_mcp_server.code_mode import (
    DEFAULT_CODE_MODE_PATH,
    _format_execute_exception,
    build_code_mode_transform,
    code_mode_enabled_from_env,
    code_mode_path_from_env,
    create_rootly_codemode_server,
    resolve_tool_name,
)


def test_code_mode_enabled_from_env_defaults_true():
    with patch.dict("os.environ", {}, clear=True):
        assert code_mode_enabled_from_env() is True


def test_code_mode_enabled_from_env_accepts_truthy_values():
    with patch.dict("os.environ", {"ROOTLY_CODE_MODE_ENABLED": "true"}, clear=True):
        assert code_mode_enabled_from_env() is True


def test_code_mode_enabled_from_env_accepts_false_override():
    with patch.dict("os.environ", {"ROOTLY_CODE_MODE_ENABLED": "false"}, clear=True):
        assert code_mode_enabled_from_env() is False


def test_code_mode_path_from_env_uses_default_and_normalizes():
    with patch.dict("os.environ", {}, clear=True):
        assert code_mode_path_from_env() == DEFAULT_CODE_MODE_PATH

    with patch.dict("os.environ", {"ROOTLY_CODE_MODE_PATH": "custom-codemode/"}, clear=True):
        assert code_mode_path_from_env() == "/custom-codemode"


def test_build_code_mode_transform_uses_expected_discovery_tools():
    transform = build_code_mode_transform()

    assert isinstance(transform, CodeMode)
    assert isinstance(transform.sandbox_provider, MontySandboxProvider)
    discovery_names = [tool.name for tool in transform._build_discovery_tools()]  # noqa: SLF001
    assert discovery_names == ["list_tools", "tool_search", "get_schema", "tags"]


def test_build_code_mode_transform_includes_pagination_guidance():
    transform = build_code_mode_transform()
    assert transform.execute_description is not None

    assert "tool_search only to discover tools" in transform.execute_description
    assert "page_size, page_number, and max_results" in transform.execute_description
    assert "per_page" in transform.execute_description
    assert "mcp__rootly-codemode__tool_search" in transform.execute_description
    assert "rootly:get_current_user" in transform.execute_description
    assert "Avoid imports such as json or asyncio" in transform.execute_description
    assert "await call_tool('search_incidents'" in transform.execute_description


def test_create_rootly_codemode_server_adds_code_mode_transform():
    mock_transform_server = type(
        "TransformServer",
        (),
        {
            "add_transform": lambda self, transform: setattr(self, "_transform", transform),
        },
    )()

    with patch(
        "rootly_mcp_server.code_mode.create_rootly_mcp_server", return_value=mock_transform_server
    ) as mock_create:
        server = create_rootly_codemode_server(
            swagger_path="swagger.json",
            name="Rootly Code Mode",
            allowed_paths=["/incidents"],
            hosted=True,
            base_url="https://api.rootly.com",
            enable_write_tools=True,
            enabled_tools={"list_incidents", "getIncident"},
        )

    assert server is mock_transform_server
    assert isinstance(server._transform, CodeMode)  # type: ignore[attr-defined]  # noqa: SLF001
    mock_create.assert_called_once_with(
        swagger_path="swagger.json",
        name="Rootly Code Mode",
        allowed_paths=["/incidents"],
        hosted=True,
        base_url="https://api.rootly.com",
        transport="streamable-http",
        enable_write_tools=True,
        enabled_tools={"list_incidents", "getIncident"},
    )


@pytest.mark.asyncio
async def test_sandbox_provider_runs_code_in_the_real_monty_runtime():
    # No fakes: this drives the installed pydantic-monty, so a Monty API change
    # that breaks execute fails here instead of only in a deployed Code Mode.
    provider = build_code_mode_transform().sandbox_provider
    calls: list[dict[str, Any]] = []

    async def call_tool(name: str, params: dict[str, Any]) -> dict[str, Any]:
        calls.append({"name": name, "params": params})
        return {"version": "1.2.3"}

    result = await provider.run(
        "result = await call_tool('get_server_version', {'verbose': True})\n"
        "return result['version']",
        external_functions={"call_tool": call_tool},
    )

    assert result == "1.2.3"
    assert calls == [{"name": "get_server_version", "params": {"verbose": True}}]


def _tools(*names: str) -> list[Any]:
    # `meta` is read by the catalog's visibility check; None means visible.
    return [SimpleNamespace(name=name, version=None, meta=None) for name in names]


def _resolved(requested: str, tools: list[Any]) -> str | None:
    tool = resolve_tool_name(requested, tools).tool
    return tool.name if tool is not None else None


def test_resolve_tool_name_handles_prefixes_and_aliases():
    tools = _tools("tool_search", "getCurrentUser", "list_teams")
    assert _resolved("mcp__rootly-codemode__tool_search", tools) == "tool_search"
    assert _resolved("rootly:getCurrentUser", tools) == "getCurrentUser"
    assert _resolved("search", tools) == "tool_search"
    assert _resolved("  list_teams ", tools) == "list_teams"


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        # Sentry: `Unknown tool: getIncidentEvents`
        ("getIncidentEvents", "get_incident_events"),
        ("GetIncidentEvents", "get_incident_events"),
        # Sentry: `Unknown tool: rootly_list_teams`
        ("rootly_list_teams", "list_teams"),
        ("rootly.list_teams", "list_teams"),
        ("rootly:listTeams", "list_teams"),
        ("mcp__rootly__list_teams", "list_teams"),
        ("mcp__claude_ai_Rootly__listTeams", "list_teams"),
        ("mcp__rootly-codemode__search", "tool_search"),
    ],
)
def test_resolve_tool_name_normalizes_sentry_shapes(requested: str, expected: str):
    tools = _tools("tool_search", "get_incident_events", "list_teams", "list_shifts")
    assert _resolved(requested, tools) == expected


def test_resolve_tool_name_prefers_exact_match_over_stripped_form():
    tools = _tools("rootly_list_teams", "list_teams")
    assert _resolved("rootly_list_teams", tools) == "rootly_list_teams"


def test_resolve_tool_name_refuses_to_guess_between_tools_that_normalize_alike():
    tools = _tools("getIncident", "get_incident")
    resolution = resolve_tool_name("GetIncident", tools)
    assert resolution.tool is None
    assert resolution.ambiguous == ("getIncident", "get_incident")
    assert "ambiguous" in resolution.error_message()
    assert "'getIncident', 'get_incident'" in resolution.error_message()


def test_resolve_tool_name_refuses_to_guess_between_stripped_and_unstripped_forms():
    # `rootly_listTeams` folds to both `rootly_list_teams` (prefix kept) and
    # `list_teams` (prefix stripped); each names a different tool here.
    tools = _tools("rootly_list_teams", "list_teams")
    resolution = resolve_tool_name("rootly_listTeams", tools)
    assert resolution.tool is None
    assert resolution.ambiguous == ("list_teams", "rootly_list_teams")


def test_resolve_tool_name_suggests_up_to_three_close_matches():
    tools = _tools("list_incidents", "list_incident_types", "list_incident_roles", "list_teams")
    resolution = resolve_tool_name("rootly_listIncidentz", tools)
    assert resolution.tool is None
    assert 0 < len(resolution.suggestions) <= 3
    assert resolution.suggestions[0] == "list_incidents"
    assert "did you mean 'list_incidents'" in resolution.error_message()


def test_resolve_tool_name_never_reaches_tools_outside_the_catalog():
    # The session's allowlist exposes only list_teams; a prefixed or camelCase
    # name for a filtered-out tool must not resolve, even though it is a real
    # Rootly tool elsewhere.
    tools = _tools("tool_search", "list_teams")
    assert _resolved("rootly_delete_incident", tools) is None
    assert _resolved("deleteIncident", tools) is None
    assert _resolved("mcp__rootly__delete_incident", tools) is None


def test_format_execute_exception_returns_friendlier_messages():
    unknown_tool = _format_execute_exception(
        Exception("Unknown tool: mcp__rootly-codemode__tool_search")
    )
    assert unknown_tool is not None
    assert "Use tool_search to discover available tools" in unknown_tool

    missing_import = _format_execute_exception(
        Exception("ModuleNotFoundError: No module named 'json'")
    )
    assert missing_import is not None
    assert "restricted sandbox" in missing_import

    asyncio_sleep = _format_execute_exception(
        Exception("AttributeError: module 'asyncio' has no attribute 'sleep'")
    )
    assert asyncio_sleep is not None
    assert "does not provide `asyncio.sleep()`" in asyncio_sleep

    parser_error = _format_execute_exception(Exception("Expected name, got Subscript(...)"))
    assert parser_error is not None
    assert "restricted Python subset" in parser_error


@pytest.mark.asyncio
async def test_execute_normalizes_namespaced_discovery_tool_calls():
    class FakeSandboxProvider:
        async def run(self, code, *, inputs=None, external_functions=None):
            assert external_functions is not None
            return await external_functions["call_tool"](
                "mcp__rootly-codemode__tool_search",
                {"query": "alerts"},
            )

    transform = build_code_mode_transform()
    transform.sandbox_provider = FakeSandboxProvider()
    execute_tool = cast(FunctionTool, transform._get_execute_tool())  # noqa: SLF001

    fake_fastmcp = SimpleNamespace(
        list_tools=AsyncMock(return_value=[]),
        call_tool=AsyncMock(
            return_value=SimpleNamespace(structured_content={"ok": True}, content=[])
        ),
    )
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    result = await execute_tool.fn("return 1", ctx=ctx)

    assert result == {"ok": True}
    fake_fastmcp.call_tool.assert_awaited_once_with("tool_search", {"query": "alerts"})


@pytest.mark.asyncio
async def test_execute_normalizes_namespaced_backend_tool_calls():
    class FakeSandboxProvider:
        async def run(self, code, *, inputs=None, external_functions=None):
            assert external_functions is not None
            return await external_functions["call_tool"]("rootly:getCurrentUser", {})

    transform = build_code_mode_transform()
    transform.sandbox_provider = FakeSandboxProvider()
    execute_tool = cast(FunctionTool, transform._get_execute_tool())  # noqa: SLF001

    # `meta` is read by the catalog's visibility check. A component without it
    # is visible, which is what this double has always stood for -- fastmcp 4
    # just asks the question explicitly now.
    backend_tools = [SimpleNamespace(name="getCurrentUser", version=None, meta=None)]
    fake_fastmcp = SimpleNamespace(
        list_tools=AsyncMock(return_value=backend_tools),
        call_tool=AsyncMock(
            return_value=SimpleNamespace(structured_content={"id": "u_1"}, content=[])
        ),
    )
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    result = await execute_tool.fn("return 1", ctx=ctx)

    assert result == {"id": "u_1"}
    fake_fastmcp.call_tool.assert_awaited_once_with("getCurrentUser", {})


@pytest.mark.asyncio
async def test_execute_returns_friendlier_unknown_tool_errors():
    class FakeSandboxProvider:
        async def run(self, code, *, inputs=None, external_functions=None):
            assert external_functions is not None
            return await external_functions["call_tool"](
                "mcp__rootly-codemode__missing_tool",
                {},
            )

    transform = build_code_mode_transform()
    transform.sandbox_provider = FakeSandboxProvider()
    execute_tool = cast(FunctionTool, transform._get_execute_tool())  # noqa: SLF001

    fake_fastmcp = SimpleNamespace(
        list_tools=AsyncMock(return_value=[]),
        call_tool=AsyncMock(),
    )
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    with pytest.raises(ValueError, match="Use tool_search to discover available tools"):
        await execute_tool.fn("return 1", ctx=ctx)

    fake_fastmcp.call_tool.assert_not_awaited()


def _real_execute(*backend_names: str) -> tuple[FunctionTool, Any]:
    """An execute tool over the real Monty sandbox and a fake backend catalog.

    The catalog stands for whatever the session may call -- allowlist and
    hosted-profile filtering happen before it, in `list_tools`.
    """
    transform = build_code_mode_transform()
    execute_tool = cast(FunctionTool, transform._get_execute_tool())  # noqa: SLF001
    fake_fastmcp = SimpleNamespace(
        list_tools=AsyncMock(return_value=_tools(*backend_names)),
        call_tool=AsyncMock(
            side_effect=lambda name, params: SimpleNamespace(
                structured_content={"tool": name, "params": params}, content=[]
            )
        ),
    )
    return execute_tool, fake_fastmcp


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        ("getIncidentEvents", "get_incident_events"),
        ("rootly_list_teams", "list_teams"),
        ("mcp__rootly-codemode__list_teams", "list_teams"),
    ],
)
async def test_execute_resolves_non_canonical_call_tool_names(requested: str, expected: str):
    execute_tool, fake_fastmcp = _real_execute("get_incident_events", "list_teams")
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    result = await execute_tool.fn(
        f"return await call_tool({requested!r}, {{'page_size': 1}})", ctx=ctx
    )

    assert result == {"tool": expected, "params": {"page_size": 1}}
    fake_fastmcp.call_tool.assert_awaited_once_with(expected, {"page_size": 1})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("code", "expected_tool", "expected_params"),
    [
        # Sentry: NameError: name 'list_shifts' is not defined
        ("return await list_shifts(page_size=5)", "list_shifts", {"page_size": 5}),
        # Sentry: NameError: name 'list_alerts' is not defined
        ("return await list_alerts({'page_size': 2})", "list_alerts", {"page_size": 2}),
        ("return await list_alerts()", "list_alerts", {}),
        # Sentry: NameError: name 'tool_search' is not defined
        ("return await tool_search(query='shifts')", "tool_search", {"query": "shifts"}),
    ],
)
async def test_execute_exposes_tools_as_bare_functions(
    code: str, expected_tool: str, expected_params: dict[str, Any]
):
    execute_tool, fake_fastmcp = _real_execute("list_shifts", "list_alerts")
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    result = await execute_tool.fn(code, ctx=ctx)

    assert result == {"tool": expected_tool, "params": expected_params}
    fake_fastmcp.call_tool.assert_awaited_once_with(expected_tool, expected_params)


@pytest.mark.asyncio
async def test_execute_bare_functions_never_shadow_builtins_or_script_names():
    execute_tool, fake_fastmcp = _real_execute("len", "list_alerts")
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    result = await execute_tool.fn(
        "list_alerts = [1, 2, 3]\nreturn len(list_alerts)",
        ctx=ctx,
    )

    assert result == 3
    fake_fastmcp.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_bare_name_for_filtered_tool_stays_undefined():
    # The allowlist leaves out list_shifts: no callable is injected, so the
    # script gets a NameError instead of reaching the tool.
    execute_tool, fake_fastmcp = _real_execute("list_alerts")
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    with pytest.raises(Exception, match="name 'list_shifts' is not defined"):
        await execute_tool.fn("return await list_shifts()", ctx=ctx)

    fake_fastmcp.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_camelcase_bare_name_teaches_the_call_convention():
    execute_tool, fake_fastmcp = _real_execute("get_incident_events")
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    with pytest.raises(ValueError) as excinfo:
        await execute_tool.fn("return await getIncidentEvents(incident_id='1')", ctx=ctx)

    message = str(excinfo.value)
    assert "name 'getIncidentEvents' is not defined" in message
    assert "await call_tool('get_incident_events'," in message
    fake_fastmcp.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_prefix_strip_cannot_reach_tools_outside_the_allowlist():
    execute_tool, fake_fastmcp = _real_execute("list_teams")
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    with pytest.raises(ValueError, match="Unknown tool: rootly_delete_incident"):
        await execute_tool.fn("return await call_tool('rootly_delete_incident', {})", ctx=ctx)

    fake_fastmcp.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_does_not_guess_between_tools_that_normalize_alike():
    execute_tool, fake_fastmcp = _real_execute("getIncident", "get_incident")
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    with pytest.raises(ValueError, match="ambiguous") as excinfo:
        await execute_tool.fn("return await call_tool('GetIncident', {})", ctx=ctx)

    assert "Use tool_search to discover available tools" in str(excinfo.value)
    fake_fastmcp.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_unknown_tool_error_lists_close_matches():
    execute_tool, fake_fastmcp = _real_execute("list_incidents", "list_teams")
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    with pytest.raises(ValueError, match="did you mean 'list_incidents'"):
        await execute_tool.fn("return await call_tool('list_incident', {})", ctx=ctx)

    fake_fastmcp.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_bare_function_rejects_positional_non_dict_arguments():
    execute_tool, fake_fastmcp = _real_execute("list_alerts")
    ctx = SimpleNamespace(fastmcp=fake_fastmcp)

    with pytest.raises(Exception, match=r"takes one params dict or keyword arguments"):
        await execute_tool.fn("return await list_alerts('a', 'b')", ctx=ctx)

    fake_fastmcp.call_tool.assert_not_awaited()


def test_format_execute_exception_maps_undefined_tool_names():
    tools = _tools("list_shifts", "get_incident_events")

    canonical = _format_execute_exception(
        Exception("NameError: name 'getIncidentEvents' is not defined"), tools
    )
    assert canonical is not None
    assert "Rootly tool 'get_incident_events'" in canonical
    assert "await call_tool('get_incident_events', {})" in canonical

    close = _format_execute_exception(
        Exception("NameError: name 'list_shift' is not defined"), tools
    )
    assert close is not None
    assert "'list_shifts'" in close

    # A plain script typo that resembles no tool keeps the original error.
    assert (
        _format_execute_exception(Exception("NameError: name 'qqq' is not defined"), tools) is None
    )


def test_undefined_name_hint_builds_the_example_from_the_tool_schema():
    get_incident = SimpleNamespace(
        name="get_incident",
        version=None,
        meta=None,
        parameters={
            "type": "object",
            "properties": {"incident_id": {"type": "string"}, "include": {"type": "string"}},
            "required": ["incident_id"],
        },
    )
    list_alerts = SimpleNamespace(
        name="list_alerts",
        version=None,
        meta=None,
        parameters={"type": "object", "properties": {"page_size": {"type": "integer"}}},
    )
    tools: list[Any] = [get_incident, list_alerts]

    required = _format_execute_exception(
        Exception("NameError: name 'getIncident' is not defined"), tools
    )
    assert required is not None
    assert "await call_tool('get_incident', {'incident_id': '<incident_id>'})" in required
    assert "page_size" not in required

    paged = _format_execute_exception(
        Exception("NameError: name 'listAlerts' is not defined"), tools
    )
    assert paged is not None
    assert "await call_tool('list_alerts', {'page_size': 10})" in paged
