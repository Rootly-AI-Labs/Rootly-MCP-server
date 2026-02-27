"""
Rootly MCP Server - A Model Context Protocol server for Rootly API integration.

This module implements a server that dynamically generates MCP tools based on
the Rootly API's OpenAPI (Swagger) specification using FastMCP's OpenAPI integration.
"""

import logging
import os

from fastmcp import FastMCP

from . import legacy_server, payload_stripping, server_defaults, spec_transform, transport
from .mcp_error import MCPError
from .tools.alerts import register_alert_tools
from .tools.incidents import register_incident_tools
from .tools.oncall import register_oncall_tools
from .tools.resources import register_resource_handlers
from .utils import sanitize_parameters_in_spec

# Set up logger
logger = logging.getLogger(__name__)

# Module-level storage for hosted auth middleware, set by create_rootly_mcp_server().
_hosted_auth_middleware: list | None = None


def get_hosted_auth_middleware() -> list | None:
    """Return the ASGI auth middleware list if in hosted mode, else None."""
    return _hosted_auth_middleware


# Re-export spec helpers for backward compatibility with existing tests/imports.
SWAGGER_URL = spec_transform.SWAGGER_URL
_load_swagger_spec = spec_transform._load_swagger_spec
_fetch_swagger_from_url = spec_transform._fetch_swagger_from_url
_filter_openapi_spec = spec_transform._filter_openapi_spec
_has_broken_references = spec_transform._has_broken_references

# Re-export transport/auth internals for backward compatibility with existing tests/imports.
ALERT_ESSENTIAL_ATTRIBUTES = transport.ALERT_ESSENTIAL_ATTRIBUTES
strip_heavy_alert_data = transport.strip_heavy_alert_data
AuthenticatedHTTPXClient = transport.AuthenticatedHTTPXClient
AuthCaptureMiddleware = transport.AuthCaptureMiddleware
_session_auth_token = transport._session_auth_token

# Re-export payload/default helpers for backward compatibility with existing tests/imports.
strip_heavy_nested_data = payload_stripping.strip_heavy_nested_data
_generate_recommendation = server_defaults._generate_recommendation
DEFAULT_ALLOWED_PATHS = server_defaults.DEFAULT_ALLOWED_PATHS
RootlyMCPServer = legacy_server.RootlyMCPServer


def create_rootly_mcp_server(
    swagger_path: str | None = None,
    name: str = "Rootly",
    allowed_paths: list[str] | None = None,
    hosted: bool = False,
    base_url: str | None = None,
    transport: str = "stdio",
) -> FastMCP:
    """
    Create a Rootly MCP Server using FastMCP's OpenAPI integration.

    Args:
        swagger_path: Path to the Swagger JSON file. If None, will fetch from URL.
        name: Name of the MCP server.
        allowed_paths: List of API paths to include. If None, includes default paths.
        hosted: Whether the server is hosted (affects authentication).
        base_url: Base URL for Rootly API. If None, uses ROOTLY_BASE_URL env var or default.
        transport: Transport protocol (stdio, sse, or streamable-http).

    Returns:
        A FastMCP server instance.
    """
    # Set default allowed paths if none provided
    if allowed_paths is None:
        allowed_paths = DEFAULT_ALLOWED_PATHS

    # Add /v1 prefix to paths if not present
    allowed_paths_v1 = [
        f"/v1{path}" if not path.startswith("/v1") else path for path in allowed_paths
    ]

    logger.info(f"Creating Rootly MCP Server with allowed paths: {allowed_paths_v1}")

    # Load the Swagger specification
    swagger_spec = _load_swagger_spec(swagger_path)
    logger.info(f"Loaded Swagger spec with {len(swagger_spec.get('paths', {}))} total paths")

    # Filter the OpenAPI spec to only include allowed paths
    filtered_spec = _filter_openapi_spec(swagger_spec, allowed_paths_v1)
    logger.info(f"Filtered spec to {len(filtered_spec.get('paths', {}))} allowed paths")

    # Sanitize all parameter names in the filtered spec to be MCP-compliant
    parameter_mapping = sanitize_parameters_in_spec(filtered_spec)
    logger.info(
        f"Sanitized parameter names for MCP compatibility (mapped {len(parameter_mapping)} parameters)"
    )

    # Determine the base URL
    if base_url is None:
        base_url = os.getenv("ROOTLY_BASE_URL", "https://api.rootly.com")

    logger.info(f"Using Rootly API base URL: {base_url}")

    # Create the authenticated HTTP client with parameter mapping

    http_client = AuthenticatedHTTPXClient(
        base_url=base_url, hosted=hosted, parameter_mapping=parameter_mapping, transport=transport
    )

    # Create the MCP server using OpenAPI integration
    # By default, all routes become tools which is what we want
    # NOTE: We pass http_client (the wrapper) instead of http_client.client (the inner httpx client)
    # so that parameter transformation (e.g., filter_status -> filter[status]) is applied.
    # The wrapper implements the same interface as httpx.AsyncClient (duck typing).
    mcp = FastMCP.from_openapi(
        openapi_spec=filtered_spec,
        client=http_client,  # type: ignore[arg-type]
        name=name,
        tags={"rootly", "incident-management"},
    )

    @mcp.custom_route("/healthz", methods=["GET"])
    @mcp.custom_route("/health", methods=["GET"])
    async def health_check(request):
        from starlette.responses import PlainTextResponse

        return PlainTextResponse("OK")

    # Add some custom tools for enhanced functionality

    @mcp.tool()
    def list_endpoints() -> list:
        """List all available Rootly API endpoints with their descriptions."""
        endpoints = []
        for path, path_item in filtered_spec.get("paths", {}).items():
            for method, operation in path_item.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue

                summary = operation.get("summary", "")
                description = operation.get("description", "")

                endpoints.append(
                    {
                        "path": path,
                        "method": method.upper(),
                        "summary": summary,
                        "description": description,
                    }
                )

        return endpoints

    @mcp.tool()
    def get_server_version() -> dict:
        """Get the Rootly MCP server version.

        Returns the current version of the deployed MCP server.
        Useful for checking if the server has been updated.
        """
        from rootly_mcp_server import __version__

        return {
            "version": __version__,
            "package": "rootly-mcp-server",
        }

    async def make_authenticated_request(method: str, url: str, **kwargs):
        """Make an authenticated request, extracting token from MCP headers in hosted mode."""
        # In hosted mode, get token from MCP request headers
        if hosted:
            try:
                from fastmcp.server.dependencies import get_http_headers

                request_headers = get_http_headers()
                # Get client IP from headers (may be in x-forwarded-for or similar)
                client_ip = (
                    request_headers.get("x-forwarded-for", "unknown")
                    if request_headers
                    else "unknown"
                )
                logger.debug(
                    f"make_authenticated_request: client_ip={client_ip}, headers_keys={list(request_headers.keys()) if request_headers else []}"
                )
                auth_header = request_headers.get("authorization", "") if request_headers else ""
                if auth_header:
                    logger.debug("make_authenticated_request: Found auth header, adding to request")
                    # Add authorization header to the request
                    if "headers" not in kwargs:
                        kwargs["headers"] = {}
                    kwargs["headers"]["Authorization"] = auth_header
                else:
                    logger.warning(
                        "make_authenticated_request: No authorization header found in MCP headers"
                    )
            except Exception as e:
                logger.warning(f"make_authenticated_request: Failed to get headers: {e}")

        # Use our custom client with proper error handling instead of bypassing it
        return await http_client.request(method, url, **kwargs)

    register_incident_tools(
        mcp=mcp,
        make_authenticated_request=make_authenticated_request,
        strip_heavy_nested_data=strip_heavy_nested_data,
        mcp_error=MCPError,
        generate_recommendation=_generate_recommendation,
    )

    register_oncall_tools(
        mcp=mcp,
        make_authenticated_request=make_authenticated_request,
        mcp_error=MCPError,
    )

    register_resource_handlers(
        mcp=mcp,
        make_authenticated_request=make_authenticated_request,
        strip_heavy_nested_data=strip_heavy_nested_data,
        mcp_error=MCPError,
    )

    register_alert_tools(
        mcp=mcp,
        make_authenticated_request=make_authenticated_request,
        mcp_error=MCPError,
    )

    # In hosted HTTP modes, configure ASGI middleware for auth token capture.
    # Callers retrieve via get_hosted_auth_middleware() and pass to server.run(middleware=...).
    global _hosted_auth_middleware
    if hosted:
        from starlette.middleware import Middleware

        _hosted_auth_middleware = [Middleware(AuthCaptureMiddleware)]
    else:
        _hosted_auth_middleware = None

    # Log server creation (tool count will be shown when tools are accessed)
    logger.info("Created Rootly MCP Server successfully")
    return mcp
