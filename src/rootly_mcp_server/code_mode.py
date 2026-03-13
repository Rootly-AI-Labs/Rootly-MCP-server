"""Code Mode helpers for exposing a third MCP endpoint."""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastmcp.experimental.transforms.code_mode import (
    CodeMode,
    GetSchemas,
    GetTags,
    ListTools,
    MontySandboxProvider,
    Search,
    _ensure_async,
)

from .server import create_rootly_mcp_server

if TYPE_CHECKING:
    from fastmcp import FastMCP


DEFAULT_CODE_MODE_PATH = "/mcp-codemode"


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


class CompatibleMontySandboxProvider(MontySandboxProvider):
    """Monty sandbox provider that tolerates older constructor signatures.

    Some deployed environments can end up with a Monty runtime that supports
    ``run_monty_async(..., external_functions=...)`` but still rejects the
    newer ``Monty(..., external_functions=[...])`` constructor argument. This
    provider falls back to the older constructor form so Code Mode execution
    continues to work during mixed-version rollouts.
    """

    @staticmethod
    def _build_monty_runner(
        pydantic_monty: Any,
        code: str,
        *,
        input_names: list[str],
        external_function_names: list[str],
    ) -> Any:
        try:
            return pydantic_monty.Monty(
                code,
                inputs=input_names,
                external_functions=external_function_names,
            )
        except TypeError as exc:
            if "external_functions" not in str(exc):
                raise
            return pydantic_monty.Monty(code, inputs=input_names)

    async def run(
        self,
        code: str,
        *,
        inputs: dict[str, Any] | None = None,
        external_functions: dict[str, Callable[..., Any]] | None = None,
    ) -> Any:
        try:
            pydantic_monty = importlib.import_module("pydantic_monty")
        except ModuleNotFoundError as exc:
            raise ImportError(
                "CodeMode requires pydantic-monty for the Monty sandbox provider. "
                "Install it with `fastmcp[code-mode]` or pass a custom SandboxProvider."
            ) from exc

        inputs = inputs or {}
        async_functions = {
            key: _ensure_async(value)
            for key, value in (external_functions or {}).items()
        }

        monty = self._build_monty_runner(
            pydantic_monty,
            code,
            input_names=list(inputs.keys()),
            external_function_names=list(async_functions.keys()),
        )
        run_kwargs: dict[str, Any] = {"external_functions": async_functions}
        if inputs:
            run_kwargs["inputs"] = inputs
        if self.limits is not None:
            run_kwargs["limits"] = self.limits
        return await pydantic_monty.run_monty_async(monty, **run_kwargs)


def build_code_mode_transform() -> CodeMode:
    """Build the shared Code Mode transform used by hosted deployments."""
    return CodeMode(
        sandbox_provider=CompatibleMontySandboxProvider(),
        discovery_tools=[
            ListTools(default_detail="brief"),
            Search(default_detail="detailed", default_limit=12),
            GetSchemas(default_detail="detailed"),
            GetTags(default_detail="brief"),
        ],
        execute_description=(
            "Write a short async Python block and chain await call_tool(name, params) calls "
            "to complete a Rootly workflow. Prefer Rootly's higher-level custom tools when "
            "they fit the task, then fall back to lower-level API tools as needed. Use return "
            "to emit the final result."
        ),
    )


def create_rootly_codemode_server(
    swagger_path: str | None = None,
    name: str = "Rootly Code Mode",
    allowed_paths: list[str] | None = None,
    hosted: bool = False,
    base_url: str | None = None,
) -> FastMCP:
    """Create a Rootly MCP server instance wrapped with Code Mode."""
    mcp: FastMCP = create_rootly_mcp_server(
        swagger_path=swagger_path,
        name=name,
        allowed_paths=allowed_paths,
        hosted=hosted,
        base_url=base_url,
        transport="streamable-http",
    )
    mcp.add_transform(build_code_mode_transform())
    return mcp
