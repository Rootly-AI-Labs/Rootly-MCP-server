"""Code Mode helpers for exposing a third MCP endpoint."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from fastmcp.experimental.transforms.code_mode import (
    CodeMode,
    GetSchemas,
    GetTags,
    ListTools,
    Search,
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


def code_mode_enabled_from_env() -> bool:
    """Return whether hosted Code Mode exposure is enabled."""
    return os.getenv("ROOTLY_CODE_MODE_ENABLED", "false").lower() in ("1", "true", "yes")


def code_mode_path_from_env() -> str:
    """Return the configured hosted Code Mode path."""
    return normalize_code_mode_path(os.getenv("ROOTLY_CODE_MODE_PATH", DEFAULT_CODE_MODE_PATH))


def build_code_mode_transform() -> CodeMode:
    """Build the shared Code Mode transform used by hosted deployments."""
    return CodeMode(
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
