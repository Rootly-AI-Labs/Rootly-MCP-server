"""Legacy Rootly MCP server class for backwards compatibility."""

from __future__ import annotations

import logging
from typing import Any

from fastmcp import FastMCP

logger = logging.getLogger(__name__)


class RootlyMCPServer(FastMCP):
    """
    Legacy Rootly MCP Server class for backward compatibility.

    This class is deprecated. Use create_rootly_mcp_server() instead.
    """

    def __init__(
        self,
        swagger_path: str | None = None,
        name: str = "Rootly",
        default_page_size: int = 10,
        allowed_paths: list[str] | None = None,
        hosted: bool = False,
        *args,
        **kwargs,
    ):
        # Preserve legacy constructor signature; parameter is intentionally unused.
        _ = default_page_size

        logger.warning(
            "RootlyMCPServer class is deprecated. Use create_rootly_mcp_server() function instead."
        )

        # Import here to avoid module import cycles.
        from .server import create_rootly_mcp_server

        server = create_rootly_mcp_server(
            swagger_path=swagger_path, name=name, allowed_paths=allowed_paths, hosted=hosted
        )

        # Copy the server's state to this instance.
        super().__init__(name, *args, **kwargs)
        self._server = server
        self._tools: dict[str, Any] = {}
        self._resources = getattr(server, "_resources", {})
        self._prompts = getattr(server, "_prompts", {})
