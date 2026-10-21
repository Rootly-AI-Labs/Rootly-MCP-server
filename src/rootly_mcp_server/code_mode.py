"""Code Mode helpers for exposing a third MCP endpoint."""

from __future__ import annotations

import builtins
import difflib
import keyword
import logging
import os
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any

from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.experimental.transforms.code_mode import (
    CodeMode,
    GetSchemas,
    GetTags,
    ListTools,
    MontySandboxProvider,
    Search,
    _unwrap_tool_result,
)
from fastmcp.server.context import Context
from fastmcp.tools import Tool
from mcp.types import ToolAnnotations
from pydantic import Field

from .server import create_rootly_mcp_server
from .spec_transform import to_snake_case

if TYPE_CHECKING:
    from fastmcp import FastMCP

logger = logging.getLogger(__name__)

# Discovery tools (list_tools, tool_search, get_schema, tags) only read the tool
# catalog — safe, idempotent, no external side effects.
_DISCOVERY_TOOL_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
# execute is a gateway that can invoke ANY Rootly tool, including writes and
# destructive actions, so it gets the most conservative annotations.
_EXECUTE_TOOL_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=True,
)
_EXECUTE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"result": {}},
    "required": ["result"],
    "x-fastmcp-wrap-result": True,
}

DEFAULT_CODE_MODE_PATH = "/mcp-codemode"
# Same per-execute budget fastmcp's CodeMode applies by default.
DEFAULT_CODE_MODE_MAX_TOOL_CALLS = 50
CODE_MODE_MAX_TOOL_CALLS_ENV = "ROOTLY_CODE_MODE_MAX_TOOL_CALLS"
_TOOL_CALL_LIMIT_MARKER = "Tool call limit exceeded"
_TOOL_NAME_PREFIXES = (
    "mcp__rootly-codemode__",
    "mcp__rootly__",
    "rootly-codemode:",
    "rootly:",
    "rootly.",
    "rootly_",
)
# Any other MCP client namespace, e.g. `mcp__claude_ai_Rootly__list_teams`.
_GENERIC_MCP_PREFIX = re.compile(r"^mcp__.+?__(?=.)")
_MAX_TOOL_SUGGESTIONS = 3
_UNDEFINED_NAME = re.compile(r"name '([^']+)' is not defined")
_TOOL_NAME_ALIASES = {
    "search": "tool_search",
}


def _normalize_http_path(path: str) -> str:
    """Normalize hosted HTTP path values for reliable comparisons."""
    if not path:
        return "/"
    normalized = path if path.startswith("/") else f"/{path}"
    if len(normalized) > 1:
        normalized = normalized.rstrip("/")
    return normalized


def normalize_code_mode_path(path: str) -> str:
    """Normalize a hosted Code Mode path value."""
    return _normalize_http_path(path)


def code_mode_enabled_from_env(default: bool = True) -> bool:
    """Return whether hosted Code Mode exposure is enabled.

    Code Mode defaults on for hosted dual-transport deployments unless explicitly disabled.
    """
    raw = os.getenv("ROOTLY_CODE_MODE_ENABLED")
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes")


def code_mode_path_from_env() -> str:
    """Return the configured hosted Code Mode path."""
    return normalize_code_mode_path(os.getenv("ROOTLY_CODE_MODE_PATH", DEFAULT_CODE_MODE_PATH))


def code_mode_max_tool_calls_from_env(default: int = DEFAULT_CODE_MODE_MAX_TOOL_CALLS) -> int:
    """Return the per-execute tool call budget for hosted Code Mode.

    Only a positive integer is accepted; anything else logs a warning and
    keeps ``default``, so a bad value can never lift the limit.
    """
    raw = os.getenv(CODE_MODE_MAX_TOOL_CALLS_ENV)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        value = 0
    if value < 1:
        logger.warning(
            "Invalid %s=%r (expected a positive integer); falling back to %d",
            CODE_MODE_MAX_TOOL_CALLS_ENV,
            raw,
            default,
        )
        return default
    return value


def _strip_tool_name_prefixes(tool_name: str) -> list[str]:
    """Return every form of ``tool_name`` with one known client prefix removed."""
    stripped: list[str] = []
    for prefix in _TOOL_NAME_PREFIXES:
        if tool_name.startswith(prefix) and len(tool_name) > len(prefix):
            stripped.append(tool_name[len(prefix) :])
    generic = _GENERIC_MCP_PREFIX.match(tool_name)
    if generic:
        stripped.append(tool_name[generic.end() :])
    return [_TOOL_NAME_ALIASES.get(name, name) for name in dict.fromkeys(stripped)]


@dataclass(frozen=True)
class ToolNameResolution:
    """Outcome of resolving a requested name against the session's tool catalog."""

    requested: str
    tool: Tool | None = None
    ambiguous: tuple[str, ...] = ()
    suggestions: tuple[str, ...] = ()

    def error_message(self) -> str:
        """Describe why the name did not resolve, naming candidates when known."""
        if self.ambiguous:
            options = ", ".join(repr(name) for name in self.ambiguous)
            return (
                f"Unknown tool: {self.requested} (ambiguous: it could mean {options}; "
                "call one of them by its exact name)"
            )
        message = f"Unknown tool: {self.requested}"
        if self.suggestions:
            options = ", ".join(repr(name) for name in self.suggestions)
            message += f" (did you mean {options}?)"
        return message


def resolve_tool_name(requested: str, tools: Sequence[Tool]) -> ToolNameResolution:
    """Resolve a model-written tool name to exactly one tool in ``tools``.

    ``tools`` must be the catalog the current session is allowed to call, so
    no normalization can ever reach a tool outside it. Stages run in order and
    the first stage that matches anything decides:

    1. exact name (plus the ``search`` -> ``tool_search`` alias)
    2. one known client prefix stripped (``mcp__<server>__``, ``rootly:``, ...)
    3. camelCase/PascalCase folded to snake_case -- the normalization the
       server applies to operationIds -- compared against the folded catalog

    A stage that matches more than one distinct tool resolves nothing: the
    caller gets the candidates back instead of a guess.
    """
    name = (requested or "").strip()
    stripped = _strip_tool_name_prefixes(name)
    folded = {to_snake_case(candidate) for candidate in (name, *stripped)}
    exact = {name, _TOOL_NAME_ALIASES.get(name, name)}

    stages: tuple[Callable[[Tool], bool], ...] = (
        lambda tool: tool.name in exact,
        lambda tool: tool.name in stripped,
        lambda tool: to_snake_case(tool.name) in folded,
    )
    for matches_stage in stages:
        # Keyed by name: an exact-name tie (discovery tool listed before a
        # backend tool) keeps the first entry rather than counting as two.
        matches = {tool.name: tool for tool in reversed(tools) if matches_stage(tool)}
        if len(matches) == 1:
            return ToolNameResolution(name, tool=next(iter(matches.values())))
        if len(matches) > 1:
            return ToolNameResolution(name, ambiguous=tuple(sorted(matches)))

    names = [tool.name for tool in tools]
    suggestions: list[str] = []
    for candidate in sorted(folded, key=len):
        for match in difflib.get_close_matches(candidate, names, n=_MAX_TOOL_SUGGESTIONS):
            if match not in suggestions:
                suggestions.append(match)
    return ToolNameResolution(name, suggestions=tuple(suggestions[:_MAX_TOOL_SUGGESTIONS]))


# Names a bare tool callable must never shadow inside the sandbox.
_RESERVED_SANDBOX_NAMES = frozenset(dir(builtins)) | {"call_tool"}


def _is_injectable_tool_name(name: str) -> bool:
    return (
        name.isidentifier() and not keyword.iskeyword(name) and name not in _RESERVED_SANDBOX_NAMES
    )


def _example_arguments(tool: Tool) -> str:
    """Render a call_tool params example from the tool's own input schema.

    Required parameters become `<name>` placeholders so following the hint
    can't fail on a missing argument; `page_size` is shown only when the tool
    takes it.
    """
    parameters = getattr(tool, "parameters", None)
    schema = parameters if isinstance(parameters, dict) else {}
    properties = schema.get("properties") or {}
    required = [name for name in schema.get("required") or [] if name in properties]
    example: dict[str, Any] = {name: f"<{name}>" for name in required}
    if not example and "page_size" in properties:
        example["page_size"] = 10
    return repr(example)


def _undefined_name_message(missing: str, tools: Sequence[Tool]) -> str | None:
    """Teach the call convention when a script used a tool name as a bare name."""
    resolution = resolve_tool_name(missing, tools)
    if resolution.tool is not None:
        canonical = resolution.tool.name
        return (
            f"NameError: name '{missing}' is not defined. It refers to the Rootly tool "
            f"'{canonical}'; call it as "
            f"`await call_tool('{canonical}', {_example_arguments(resolution.tool)})`"
            " with the parameters from its schema (get_schema / tool_search)."
        )
    candidates = resolution.ambiguous or resolution.suggestions
    if not candidates:
        return None
    options = ", ".join(repr(name) for name in candidates)
    lead = (
        f"It could mean the Rootly tools {options}"
        if resolution.ambiguous
        else f"If you meant a Rootly tool, the closest are {options}"
    )
    return (
        f"NameError: name '{missing}' is not defined. {lead}. Pick the right one "
        "(tool_search / get_schema) and call it by its exact name with "
        "`await call_tool('<exact_tool_name>', {...})`."
    )


def _format_execute_exception(exc: Exception, tools: Sequence[Tool] = ()) -> str | None:
    """Return a friendlier execute error message for known sandbox failures.

    ``tools`` is the session's callable catalog; it lets an undefined-name
    error point at the tool the script most likely meant.
    """
    message = str(exc).strip()
    if not message:
        return None

    undefined = _UNDEFINED_NAME.search(message)
    if undefined and (isinstance(exc, NameError) or "NameError" in message):
        return _undefined_name_message(undefined.group(1), tools)

    if _TOOL_CALL_LIMIT_MARKER in message:
        return (
            f"{message} Do the work in fewer calls: use list tools with filters and a "
            "larger page_size instead of one call per item, or split the workflow across "
            "several execute calls and return intermediate results."
        )

    if isinstance(exc, NotFoundError) or "Unknown tool:" in message:
        return (
            f"{message}. Use tool_search to discover available tools and call them "
            "without client prefixes like 'mcp__rootly-codemode__' or 'rootly:'."
        )

    if isinstance(exc, ModuleNotFoundError) or "No module named" in message:
        return (
            f"{message}. Code Mode runs in a restricted sandbox, so imports like "
            "`json` or `asyncio` are not available. Return native Python dict/list/str "
            "values and use `await call_tool(name, params)` for Rootly operations."
        )

    if (
        isinstance(exc, AttributeError) and "asyncio" in message and "sleep" in message
    ) or "asyncio' has no attribute 'sleep'" in message:
        return (
            f"{message}. Code Mode does not provide `asyncio.sleep()`. Avoid manual "
            "sleep/retry loops inside execute; call Rootly tools directly and return "
            "the final result."
        )

    if message.startswith("Expected ") or "got Subscript(" in message:
        return (
            f"{message}. Code Mode supports a restricted Python subset. Keep the block "
            "simple: assign intermediate values to variables, call `await call_tool(...)`, "
            "and `return` the final value."
        )

    if isinstance(exc, TypeError) and "NoneType" in message and "subscriptable" in message:
        return (
            f"{message}. Code Mode tried to read a field from a missing result. Check "
            "that each `call_tool(...)` response contains the keys you expect before "
            "indexing into it."
        )

    return None


class RootlyCodeMode(CodeMode):
    """Rootly-specific Code Mode transform with friendlier execute ergonomics."""

    def _build_discovery_tools(self) -> list[Tool]:
        # Attach read-only annotations to the actual Tool objects FastMCP exposes
        # (list_tools, tool_search, get_schema, tags). The base result is cached,
        # so we annotate the concrete objects the runtime returns.
        tools = super()._build_discovery_tools()
        for tool in tools:
            tool.annotations = _DISCOVERY_TOOL_ANNOTATIONS
        return tools

    def _make_execute_tool(self) -> Tool:
        transform = self
        # fastmcp's CodeMode stores this from its `max_tool_calls` constructor
        # argument (default 50; None disables the limit).
        max_tool_calls = self.max_tool_calls

        async def execute(
            code: Annotated[
                str,
                Field(
                    description=(
                        "Python async code to execute tool calls via call_tool(name, arguments)"
                    )
                ),
            ],
            ctx: Context = None,  # type: ignore[assignment]
        ) -> Any:
            """Execute tool calls using Python code."""
            # Discovery tools first so they win an exact-name tie, then the
            # session-filtered backend catalog (allowlists, hosted profiles,
            # visibility). Every name resolution runs against this list only.
            tools: list[Tool] = [
                *transform._build_discovery_tools(),
                *await transform.get_tool_catalog(ctx),
            ]
            # Per execute(): every call_tool() invocation counts, including the
            # bare tool functions (they route through call_tool), discovery
            # tools and unknown names -- the same semantics as fastmcp's own
            # execute, which counts before resolving the name.
            call_count = 0

            async def call_tool(tool_name: str, params: dict[str, Any] | None = None) -> Any:
                nonlocal call_count
                if max_tool_calls is not None:
                    call_count += 1
                    if call_count > max_tool_calls:
                        raise ToolError(
                            f"{_TOOL_CALL_LIMIT_MARKER}: at most {max_tool_calls} "
                            "call_tool() invocations are allowed per execute()."
                        )

                resolution = resolve_tool_name(tool_name, tools)
                if resolution.tool is None:
                    raise NotFoundError(resolution.error_message())

                result = await ctx.fastmcp.call_tool(resolution.tool.name, params or {})
                return _unwrap_tool_result(result)

            def bare_tool_function(tool: Tool) -> Callable[..., Any]:
                name = tool.name

                async def tool_function(*args: Any, **kwargs: Any) -> Any:
                    if len(args) > 1 or (args and not isinstance(args[0], dict)):
                        example = _example_arguments(tool)
                        raise TypeError(
                            f"{name}() takes one params dict or keyword arguments, e.g. "
                            f"`await {name}({example})` or "
                            f"`await call_tool('{name}', {example})`."
                        )
                    return await call_tool(name, {**(args[0] if args else {}), **kwargs})

                return tool_function

            # Scripts often call tools as plain functions (`await list_shifts()`).
            # Monty consults these only for names the script leaves undefined,
            # so builtins and the script's own variables always win, and each
            # one routes through call_tool, so it reaches nothing call_tool
            # could not.
            external_functions: dict[str, Callable[..., Any]] = {
                tool.name: bare_tool_function(tool)
                for tool in tools
                if _is_injectable_tool_name(tool.name)
            }
            external_functions["call_tool"] = call_tool

            try:
                return await transform.sandbox_provider.run(
                    code,
                    external_functions=external_functions,
                )
            except Exception as exc:
                friendly_message = _format_execute_exception(exc, tools)
                if friendly_message is None:
                    raise
                raise ValueError(friendly_message) from exc

        return Tool.from_function(
            fn=execute,
            name=self.execute_tool_name,
            description=self._build_execute_description(),
            annotations=_EXECUTE_TOOL_ANNOTATIONS,
            output_schema=_EXECUTE_OUTPUT_SCHEMA,
        )


def build_code_mode_transform(max_tool_calls: int | None = None) -> CodeMode:
    """Build the shared Code Mode transform used by hosted deployments.

    ``max_tool_calls`` caps call_tool() invocations per execute(); when omitted
    it comes from ``ROOTLY_CODE_MODE_MAX_TOOL_CALLS`` (default 50).
    """
    return RootlyCodeMode(
        sandbox_provider=MontySandboxProvider(),
        max_tool_calls=(
            max_tool_calls if max_tool_calls is not None else code_mode_max_tool_calls_from_env()
        ),
        discovery_tools=[
            ListTools(default_detail="brief"),
            Search(name="tool_search", default_detail="detailed", default_limit=12),
            GetSchemas(default_detail="detailed"),
            GetTags(default_detail="brief"),
        ],
        execute_description=(
            "Write a short async Python block and chain await call_tool(name, params) calls "
            "to complete a Rootly workflow. Use tool_search only to discover tools and their "
            "schemas, then call the actual Rootly tool with the exact parameter names shown in "
            "the schema. For paginated data tools, pass pagination arguments like page_size, "
            "page_number, and max_results exactly as documented by that tool instead of inventing "
            "alternatives like per_page. Prefer Rootly's higher-level custom tools when they fit "
            "the task, then fall back to lower-level API tools as needed. Use list_incidents for "
            "structured incident queries with filters like teams, team_ids, start_time, end_time, "
            "severity, or status; use search_incidents for lightweight free-text lookups. Do not use client "
            "prefixes like mcp__rootly-codemode__tool_search or rootly:get_current_user inside "
            "execute; call tool_search or the raw Rootly tool name directly. Avoid imports "
            "such as json or asyncio inside the sandbox and return native Python values instead. Example: "
            "await call_tool('search_incidents', {'query': '', 'page_size': 1, 'page_number': 1, "
            "'max_results': 1}). Use return to emit the final result."
        ),
    )


def create_rootly_codemode_server(
    swagger_path: str | None = None,
    name: str = "Rootly Code Mode",
    allowed_paths: list[str] | None = None,
    hosted: bool = False,
    base_url: str | None = None,
    enable_write_tools: bool | None = None,
    enabled_tools: set[str] | None = None,
) -> FastMCP:
    """Create a Rootly MCP server instance wrapped with Code Mode."""
    mcp: FastMCP = create_rootly_mcp_server(
        swagger_path=swagger_path,
        name=name,
        allowed_paths=allowed_paths,
        hosted=hosted,
        base_url=base_url,
        transport="streamable-http",
        enable_write_tools=enable_write_tools,
        enabled_tools=enabled_tools,
    )
    mcp.add_transform(build_code_mode_transform())
    return mcp
