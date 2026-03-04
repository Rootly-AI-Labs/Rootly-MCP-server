"""MCP protocol/tool error helpers for Rootly MCP server."""

from __future__ import annotations

from typing import Any


class MCPError:
    """Enhanced error handling for MCP protocol compliance."""

    @staticmethod
    def protocol_error(
        code: int, message: str, data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Create a JSON-RPC protocol-level error response."""
        error_response: dict[str, Any] = {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
        }
        if data:
            error_response["error"]["data"] = data
        return error_response

    @staticmethod
    def tool_error(
        error_message: str,
        error_type: str = "execution_error",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a tool-level error response (returned as successful tool result)."""
        error_response: dict[str, Any] = {
            "error": True,
            "error_type": error_type,
            "message": error_message,
        }
        if details:
            error_response["details"] = details
        return error_response

    @staticmethod
    def categorize_error(exception: Exception) -> tuple[str, str]:
        """Categorize an exception into error type and appropriate message."""
        error_str = str(exception)
        exception_type = type(exception).__name__

        # Authentication/Authorization errors
        if any(
            keyword in error_str.lower()
            for keyword in ["401", "unauthorized", "authentication", "token", "forbidden"]
        ):
            return "authentication_error", f"Authentication failed: {error_str}"

        # Network/Connection errors
        if any(
            keyword in exception_type.lower() for keyword in ["connection", "timeout", "network"]
        ):
            return "network_error", f"Network error: {error_str}"

        # HTTP errors
        if "40" in error_str[:10]:  # 4xx client errors
            return "client_error", f"Client error: {error_str}"
        elif "50" in error_str[:10]:  # 5xx server errors
            return "server_error", f"Server error: {error_str}"

        # Validation errors
        if any(
            keyword in exception_type.lower() for keyword in ["validation", "pydantic", "field"]
        ):
            return "validation_error", f"Input validation error: {error_str}"

        # Generic execution errors
        return "execution_error", f"Tool execution error: {error_str}"
