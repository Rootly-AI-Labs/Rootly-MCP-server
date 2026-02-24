"""
Rootly MCP Server - A Model Context Protocol server for Rootly API integration.

This module implements a server that dynamically generates MCP tools based on
the Rootly API's OpenAPI (Swagger) specification using FastMCP's OpenAPI integration.
"""

import asyncio
import json
import logging
import os
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import httpx
import requests
from fastmcp import FastMCP
from pydantic import Field

from .och_client import OnCallHealthClient
from .smart_utils import SolutionExtractor, TextSimilarityAnalyzer
from .utils import sanitize_parameters_in_spec

# Set up logger
logger = logging.getLogger(__name__)


def strip_heavy_nested_data(data: dict[str, Any]) -> dict[str, Any]:
    """
    Strip heavy nested relationship data from incident responses to reduce payload size.
    Removes embedded user objects, roles, permissions, schedules, etc.
    """
    if not isinstance(data, dict):
        return data

    if "data" in data and isinstance(data["data"], list):
        # Process list of incidents
        for incident in data["data"]:
            if "attributes" in incident:
                attrs = incident["attributes"]
                # Strip heavy embedded user objects
                for user_field in [
                    "user",
                    "started_by",
                    "mitigated_by",
                    "resolved_by",
                    "closed_by",
                    "cancelled_by",
                    "in_triage_by",
                ]:
                    if user_field in attrs and isinstance(attrs[user_field], dict):
                        user_data = attrs[user_field].get("data", {})
                        if "attributes" in user_data:
                            # Keep only basic user info
                            attrs[user_field] = {
                                "data": {
                                    "id": user_data.get("id"),
                                    "type": user_data.get("type"),
                                    "attributes": {
                                        "name": user_data.get("attributes", {}).get("name"),
                                        "email": user_data.get("attributes", {}).get("email"),
                                    },
                                }
                            }

                # Strip heavy severity object, keep only essential info
                if "severity" in attrs and isinstance(attrs["severity"], dict):
                    sev_data = attrs["severity"].get("data", {})
                    if sev_data and "attributes" in sev_data:
                        # Simplify to just name and slug
                        attrs["severity"] = {
                            "name": sev_data.get("attributes", {}).get("name"),
                            "slug": sev_data.get("attributes", {}).get("slug"),
                        }
                    elif not sev_data:
                        # Severity is null/empty
                        attrs["severity"] = None

                # Remove heavy integration fields (50+ fields with IDs/URLs)
                integration_fields = [
                    "zoom_meeting_start_url",
                    "zoom_meeting_global_dial_in_numbers",
                    "shortcut_story_id",
                    "shortcut_story_url",
                    "shortcut_task_id",
                    "shortcut_task_url",
                    "asana_task_id",
                    "asana_task_url",
                    "github_issue_id",
                    "github_issue_url",
                    "gitlab_issue_id",
                    "gitlab_issue_url",
                    "google_meeting_id",
                    "trello_card_id",
                    "trello_card_url",
                    "linear_issue_id",
                    "linear_issue_url",
                    "zendesk_ticket_id",
                    "zendesk_ticket_url",
                    "motion_task_id",
                    "motion_task_url",
                    "clickup_task_id",
                    "clickup_task_url",
                    "slack_channel_deep_link",
                    "service_now_incident_id",
                    "service_now_incident_key",
                    "service_now_incident_url",
                    "opsgenie_incident_id",
                    "opsgenie_incident_url",
                    "opsgenie_alert_id",
                    "opsgenie_alert_url",
                    "victor_ops_incident_id",
                    "victor_ops_incident_url",
                    "pagerduty_incident_id",
                    "pagerduty_incident_number",
                    "pagerduty_incident_url",
                    "mattermost_channel_id",
                    "mattermost_channel_name",
                    "mattermost_channel_url",
                    "confluence_page_id",
                    "quip_page_id",
                    "quip_page_url",
                    "airtable_base_key",
                    "airtable_table_name",
                    "airtable_record_id",
                    "airtable_record_url",
                    "google_drive_id",
                    "google_drive_parent_id",
                    "google_drive_url",
                    "sharepoint_page_id",
                    "sharepoint_page_url",
                    "datadog_notebook_id",
                    "datadog_notebook_url",
                    "freshservice_ticket_id",
                    "freshservice_ticket_url",
                    "freshservice_task_id",
                    "freshservice_task_url",
                    "zoom_meeting_password",
                    "zoom_meeting_pstn_password",
                    "zoom_meeting_h323_password",
                    "labels",
                    "slack_last_message_ts",
                ]
                for field in integration_fields:
                    attrs.pop(field, None)

            # Remove heavy relationships data
            if "relationships" in incident:
                rels = incident["relationships"]
                # Keep only counts for heavy relationships, remove the actual data
                for rel_key in [
                    "events",
                    "action_items",
                    "subscribers",
                    "roles",
                    "slack_messages",
                    "alerts",
                ]:
                    if (
                        rel_key in rels
                        and isinstance(rels[rel_key], dict)
                        and "data" in rels[rel_key]
                    ):
                        # Replace with just count
                        rels[rel_key] = {"count": len(rels[rel_key]["data"])}

    return data


# Essential alert attributes to keep (whitelist approach).
# Everything else is stripped to reduce payload size.
ALERT_ESSENTIAL_ATTRIBUTES = {
    "source",
    "status",
    "summary",
    "description",
    "noise",
    "alert_urgency_id",
    "short_id",
    "url",
    "external_url",
    "created_at",
    "updated_at",
    "started_at",
    "ended_at",
}


def strip_heavy_alert_data(data: dict[str, Any]) -> dict[str, Any]:
    """
    Strip heavy nested data from alert responses to reduce payload size.
    Uses a whitelist approach: only essential attributes are kept.
    Handles both list responses (data: [...]) and single-resource responses (data: {...}).
    """
    if not isinstance(data, dict) or "data" not in data:
        return data

    def _strip_single_alert(alert: dict[str, Any]) -> None:
        if not isinstance(alert, dict):
            return
        if "attributes" in alert:
            attrs = alert["attributes"]
            keys_to_remove = [k for k in attrs if k not in ALERT_ESSENTIAL_ATTRIBUTES]
            for k in keys_to_remove:
                del attrs[k]
        # Collapse relationships to counts
        if "relationships" in alert:
            rels = alert["relationships"]
            for rel_key in list(rels.keys()):
                if (
                    isinstance(rels[rel_key], dict)
                    and "data" in rels[rel_key]
                    and isinstance(rels[rel_key]["data"], list)
                ):
                    rels[rel_key] = {"count": len(rels[rel_key]["data"])}

    if isinstance(data["data"], list):
        for alert in data["data"]:
            _strip_single_alert(alert)
    elif isinstance(data["data"], dict):
        _strip_single_alert(data["data"])

    # Remove sideloaded relationship data
    data.pop("included", None)

    return data


class MCPError:
    """Enhanced error handling for MCP protocol compliance."""

    @staticmethod
    def protocol_error(code: int, message: str, data: dict | None = None):
        """Create a JSON-RPC protocol-level error response."""
        error_response = {"jsonrpc": "2.0", "error": {"code": code, "message": message}}
        if data:
            error_response["error"]["data"] = data
        return error_response

    @staticmethod
    def tool_error(
        error_message: str, error_type: str = "execution_error", details: dict | None = None
    ):
        """Create a tool-level error response (returned as successful tool result)."""
        error_response = {"error": True, "error_type": error_type, "message": error_message}
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


# Default Swagger URL
SWAGGER_URL = "https://rootly-heroku.s3.amazonaws.com/swagger/v1/swagger.json"


# Default allowed API paths
def _generate_recommendation(solution_data: dict) -> str:
    """Generate a high-level recommendation based on solution analysis."""
    solutions = solution_data.get("solutions", [])
    avg_time = solution_data.get("average_resolution_time")

    if not solutions:
        return "No similar incidents found. This may be a novel issue requiring escalation."

    recommendation_parts = []

    # Time expectation
    if avg_time:
        if avg_time < 1:
            recommendation_parts.append("Similar incidents typically resolve quickly (< 1 hour).")
        elif avg_time > 4:
            recommendation_parts.append(
                "Similar incidents typically require more time (> 4 hours)."
            )

    # Top solution
    if solutions:
        top_solution = solutions[0]
        if top_solution.get("suggested_actions"):
            actions = top_solution["suggested_actions"][:2]  # Top 2 actions
            recommendation_parts.append(f"Consider trying: {', '.join(actions)}")

    # Pattern insights
    patterns = solution_data.get("common_patterns", [])
    if patterns:
        recommendation_parts.append(f"Common patterns: {patterns[0]}")

    return (
        " ".join(recommendation_parts)
        if recommendation_parts
        else "Review similar incidents above for resolution guidance."
    )


# Default allowed API paths
DEFAULT_ALLOWED_PATHS = [
    "/incidents/{incident_id}/alerts",
    "/alerts",
    "/alerts/{id}",
    "/severities",
    "/severities/{severity_id}",
    "/teams",
    "/teams/{team_id}",
    "/services",
    "/services/{service_id}",
    "/functionalities",
    "/functionalities/{functionality_id}",
    # Incident types
    "/incident_types",
    "/incident_types/{incident_type_id}",
    # Action items (all, by id, by incident)
    "/incident_action_items",
    "/incident_action_items/{incident_action_item_id}",
    "/incidents/{incident_id}/action_items",
    # Workflows
    "/workflows",
    "/workflows/{workflow_id}",
    # Workflow runs
    "/workflow_runs",
    "/workflow_runs/{workflow_run_id}",
    # Environments
    "/environments",
    "/environments/{environment_id}",
    # Users
    "/users",
    "/users/{user_id}",
    "/users/me",
    # Status pages
    "/status_pages",
    "/status_pages/{status_page_id}",
    # On-call schedules and shifts
    "/schedules",
    "/schedules/{schedule_id}",
    "/schedules/{schedule_id}/shifts",
    "/shifts",
    "/schedule_rotations/{schedule_rotation_id}",
    "/schedule_rotations/{schedule_rotation_id}/schedule_rotation_users",
    "/schedule_rotations/{schedule_rotation_id}/schedule_rotation_active_days",
    # On-call overrides
    "/schedules/{schedule_id}/override_shifts",
    "/override_shifts/{override_shift_id}",
    # On-call shadows and roles
    "/schedules/{schedule_id}/on_call_shadows",
    "/on_call_shadows/{on_call_shadow_id}",
    "/on_call_roles",
    "/on_call_roles/{on_call_role_id}",
]


class AuthenticatedHTTPXClient:
    """An HTTPX client wrapper that handles Rootly API authentication and parameter transformation."""

    def __init__(
        self,
        base_url: str = "https://api.rootly.com",
        hosted: bool = False,
        parameter_mapping: dict[str, str] | None = None,
        transport: str = "stdio",
    ):
        self._base_url = base_url
        self.hosted = hosted
        self._api_token = None
        self.parameter_mapping = parameter_mapping or {}

        if not self.hosted:
            self._api_token = self._get_api_token()

        # Create the HTTPX client
        from rootly_mcp_server import __version__

        mode = "hosted" if hosted else "self-hosted"
        headers = {
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
            "User-Agent": f"rootly-mcp-server/{__version__} ({transport}; {mode})",
        }
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"

        logger.info(
            f"AuthenticatedHTTPXClient init: hosted={hosted}, has_api_token={bool(self._api_token)}"
        )

        self.client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=30.0,
            follow_redirects=True,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            event_hooks={"request": [self._enforce_jsonapi_headers]},
        )

    @staticmethod
    async def _enforce_jsonapi_headers(request: httpx.Request):
        """Event hook to enforce JSON-API Content-Type and Accept on every outgoing request.

        This runs on ALL requests regardless of how they are initiated (request(), send(), etc.),
        ensuring the Rootly API always receives the correct Content-Type header.
        """
        has_auth = "authorization" in request.headers
        logger.info(f"Outgoing request to {request.url} - has authorization: {has_auth}")
        request.headers["content-type"] = "application/vnd.api+json"
        request.headers["accept"] = "application/vnd.api+json"

    def _get_api_token(self) -> str | None:
        """Get the API token from environment variables."""
        api_token = os.getenv("ROOTLY_API_TOKEN")
        if not api_token:
            logger.warning("ROOTLY_API_TOKEN environment variable is not set")
            return None
        return api_token

    def _transform_params(self, params: dict[str, Any] | None) -> dict[str, Any] | None:
        """Transform sanitized parameter names back to original names."""
        if not params or not self.parameter_mapping:
            return params

        transformed = {}
        for key, value in params.items():
            # Use the original name if we have a mapping, otherwise keep the sanitized name
            original_key = self.parameter_mapping.get(key, key)
            transformed[original_key] = value
            if original_key != key:
                logger.debug(f"Transformed parameter: '{key}' -> '{original_key}'")
        return transformed

    async def request(self, method: str, url: str, **kwargs):
        """Override request to transform parameters and ensure correct headers."""
        # Transform query parameters
        if "params" in kwargs:
            kwargs["params"] = self._transform_params(kwargs["params"])

        # Log incoming headers for debugging (before transformation)
        incoming_headers = kwargs.get("headers", {})
        if incoming_headers:
            logger.debug(f"Incoming headers for {method} {url}: {list(incoming_headers.keys())}")

        # ALWAYS ensure Content-Type and Accept headers are set correctly for Rootly API
        # This is critical because:
        # 1. FastMCP's get_http_headers() returns LOWERCASE header keys (e.g., "content-type")
        # 2. We must remove any existing content-type/accept and set the correct JSON-API values
        # 3. Handle both lowercase and mixed-case variants to be safe
        headers = dict(kwargs.get("headers") or {})
        # Remove any existing content-type and accept headers (case-insensitive)
        headers_to_remove = [k for k in headers if k.lower() in ("content-type", "accept")]
        for key in headers_to_remove:
            logger.debug(f"Removing header '{key}' with value '{headers[key]}'")
            del headers[key]
        # Set the correct JSON-API headers
        headers["Content-Type"] = "application/vnd.api+json"
        headers["Accept"] = "application/vnd.api+json"
        kwargs["headers"] = headers

        # Log outgoing request
        logger.debug(f"Request: {method} {url}")

        response = await self.client.request(method, url, **kwargs)
        logger.debug(f"Response: {method} {url} -> {response.status_code}")

        # Log error responses (4xx/5xx)
        if response.is_error:
            logger.error(
                f"HTTP {response.status_code} error for {method} {url}: "
                f"{response.text[:500] if response.text else 'No response body'}"
            )

        # Post-process alert GET responses to reduce payload size.
        # Modifies response._content (private httpx attr) because FastMCP's
        # OpenAPITool.run() calls response.json() after this returns, and
        # there is no other interception point for auto-generated tools.
        response = self._maybe_strip_alert_response(method, url, response)

        return response

    @staticmethod
    def _is_alert_endpoint(url: str) -> bool:
        """Check if a URL is an alert endpoint (but not alert sub-resources like events)."""
        url_str = str(url)
        # Match /alerts or /alerts/{id} but not /alert_urgencies, /alert_events, etc.
        # Also matches /incidents/{id}/alerts
        return "/alerts" in url_str and not any(
            sub in url_str
            for sub in ["/alert_urgencies", "/alert_events", "/alert_sources", "/alert_routing"]
        )

    @staticmethod
    def _maybe_strip_alert_response(
        method: str, url: str, response: httpx.Response
    ) -> httpx.Response:
        """Strip heavy data from alert GET responses."""
        if method.upper() != "GET":
            return response
        if not response.is_success:
            return response
        if not AuthenticatedHTTPXClient._is_alert_endpoint(url):
            return response
        try:
            data = response.json()
            stripped = strip_heavy_alert_data(data)
            response._content = json.dumps(stripped).encode()  # noqa: SLF001
        except Exception:
            logger.debug(f"Could not strip alert response for {url}", exc_info=True)
        return response

    async def get(self, url: str, **kwargs):
        """Proxy to request with GET method."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        """Proxy to request with POST method."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs):
        """Proxy to request with PUT method."""
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs):
        """Proxy to request with PATCH method."""
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs):
        """Proxy to request with DELETE method."""
        return await self.request("DELETE", url, **kwargs)

    async def send(self, request: httpx.Request, **kwargs):
        """Proxy send() for newer fastmcp versions that build requests and call send() directly.

        Headers are enforced by the event hook, so we just delegate to the inner client.
        Alert response stripping is also applied here for forward compatibility.
        """
        # Transform URL query parameters from sanitized names to original names
        # FastMCP builds requests with sanitized parameter names (e.g., filter_status)
        # but the API expects original names (e.g., filter[status])
        if request.url.params:
            original_params = {}
            for key, value in request.url.params.items():
                original_key = self.parameter_mapping.get(key, key)
                original_params[original_key] = value
            # Rebuild URL with transformed parameters
            new_url = str(request.url).split("?")[0]
            if original_params:
                from urllib.parse import urlencode

                new_url += "?" + urlencode(original_params, doseq=True)
            # Create new request with transformed URL
            new_request = httpx.Request(
                method=request.method,
                url=httpx.URL(new_url),
                headers=request.headers,
                content=request.content,
            )
            request = new_request

        response = await self.client.send(request, **kwargs)
        response = self._maybe_strip_alert_response(request.method, str(request.url), response)
        return response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    def __getattr__(self, name):
        # Delegate all other attributes to the underlying client, except for request methods
        if name in ["request", "get", "post", "put", "patch", "delete"]:
            # Use our overridden methods instead
            return getattr(self, name)
        return getattr(self.client, name)

    @property
    def base_url(self):
        return self.client.base_url

    @property
    def headers(self):
        return self.client.headers


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
        transport: Transport protocol (stdio or sse).

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
                logger.info(
                    f"make_authenticated_request: client_ip={client_ip}, headers_keys={list(request_headers.keys()) if request_headers else []}"
                )
                auth_header = request_headers.get("authorization", "") if request_headers else ""
                if auth_header:
                    logger.info("make_authenticated_request: Found auth header, adding to request")
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

    @mcp.tool()
    async def search_incidents(
        query: Annotated[
            str, Field(description="Search query to filter incidents by title/summary")
        ] = "",
        page_size: Annotated[
            int, Field(description="Number of results per page (max: 20)", ge=1, le=20)
        ] = 10,
        page_number: Annotated[
            int, Field(description="Page number to retrieve (use 0 for all pages)", ge=0)
        ] = 1,
        max_results: Annotated[
            int,
            Field(
                description="Maximum total results when fetching all pages (ignored if page_number > 0)",
                ge=1,
                le=10,
            ),
        ] = 5,
    ) -> dict:
        """
        Search incidents with flexible pagination control.

        Use page_number=0 to fetch all matching results across multiple pages up to max_results.
        Use page_number>0 to fetch a specific page.
        """
        # Single page mode
        if page_number > 0:
            params = {
                "page[size]": page_size,  # Use requested page size (already limited to max 20)
                "page[number]": page_number,
                "include": "",
                "fields[incidents]": "id,title,summary,status,created_at,updated_at,url,started_at",
            }
            if query:
                params["filter[search]"] = query

            try:
                response = await make_authenticated_request("GET", "/v1/incidents", params=params)
                response.raise_for_status()
                return strip_heavy_nested_data(response.json())
            except Exception as e:
                error_type, error_message = MCPError.categorize_error(e)
                return MCPError.tool_error(error_message, error_type)

        # Multi-page mode (page_number = 0)
        all_incidents = []
        current_page = 1
        effective_page_size = page_size  # Use requested page size (already limited to max 20)
        max_pages = 10  # Safety limit to prevent infinite loops

        try:
            while len(all_incidents) < max_results and current_page <= max_pages:
                params = {
                    "page[size]": effective_page_size,
                    "page[number]": current_page,
                    "include": "",
                    "fields[incidents]": "id,title,summary,status,created_at,updated_at,url,started_at",
                }
                if query:
                    params["filter[search]"] = query

                try:
                    response = await make_authenticated_request(
                        "GET", "/v1/incidents", params=params
                    )
                    response.raise_for_status()
                    response_data = response.json()

                    if "data" in response_data:
                        incidents = response_data["data"]
                        if not incidents:
                            # No more incidents available
                            break

                        # Check if we got fewer incidents than requested (last page)
                        if len(incidents) < effective_page_size:
                            all_incidents.extend(incidents)
                            break

                        all_incidents.extend(incidents)

                        # Check metadata if available
                        meta = response_data.get("meta", {})
                        current_page_meta = meta.get("current_page", current_page)
                        total_pages = meta.get("total_pages")

                        # If we have reliable metadata, use it
                        if total_pages and current_page_meta >= total_pages:
                            break

                        current_page += 1
                    else:
                        break

                except Exception as e:
                    # Re-raise authentication or critical errors for immediate handling
                    if (
                        "401" in str(e)
                        or "Unauthorized" in str(e)
                        or "authentication" in str(e).lower()
                    ):
                        error_type, error_message = MCPError.categorize_error(e)
                        return MCPError.tool_error(error_message, error_type)
                    # For other errors, break loop and return partial results
                    break

            # Limit to max_results
            if len(all_incidents) > max_results:
                all_incidents = all_incidents[:max_results]

            return strip_heavy_nested_data(
                {
                    "data": all_incidents,
                    "meta": {
                        "total_fetched": len(all_incidents),
                        "max_results": max_results,
                        "query": query,
                        "pages_fetched": current_page - 1,
                        "page_size": effective_page_size,
                    },
                }
            )
        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(error_message, error_type)

    # Initialize smart analysis tools
    similarity_analyzer = TextSimilarityAnalyzer()
    solution_extractor = SolutionExtractor()

    @mcp.tool()
    async def find_related_incidents(
        incident_id: str = "",
        incident_description: str = "",
        similarity_threshold: Annotated[
            float, Field(description="Minimum similarity score (0.0-1.0)", ge=0.0, le=1.0)
        ] = 0.15,
        max_results: Annotated[
            int, Field(description="Maximum number of related incidents to return", ge=1, le=20)
        ] = 5,
        status_filter: Annotated[
            str,
            Field(
                description="Filter incidents by status (empty for all, 'resolved', 'investigating', etc.)"
            ),
        ] = "",
    ) -> dict:
        """Find similar incidents to help with context and resolution strategies. Provide either incident_id OR incident_description (e.g., 'website is down', 'database timeout errors'). Use status_filter to limit to specific incident statuses or leave empty for all incidents."""
        try:
            target_incident = {}

            if incident_id:
                # Get the target incident details by ID
                target_response = await make_authenticated_request(
                    "GET", f"/v1/incidents/{incident_id}"
                )
                target_response.raise_for_status()
                target_incident_data = strip_heavy_nested_data(
                    {"data": [target_response.json().get("data", {})]}
                )
                target_incident = target_incident_data.get("data", [{}])[0]

                if not target_incident:
                    return MCPError.tool_error("Incident not found", "not_found")

            elif incident_description:
                # Create synthetic incident for analysis from descriptive text
                target_incident = {
                    "id": "synthetic",
                    "attributes": {
                        "title": incident_description,
                        "summary": incident_description,
                        "description": incident_description,
                    },
                }
            else:
                return MCPError.tool_error(
                    "Must provide either incident_id or incident_description", "validation_error"
                )

            # Get historical incidents for comparison
            params = {
                "page[size]": 100,  # Get more incidents for better matching
                "page[number]": 1,
                "include": "",
                "fields[incidents]": "id,title,summary,status,created_at,url",
            }

            # Only add status filter if specified
            if status_filter:
                params["filter[status]"] = status_filter

            historical_response = await make_authenticated_request(
                "GET", "/v1/incidents", params=params
            )
            historical_response.raise_for_status()
            historical_data = strip_heavy_nested_data(historical_response.json())
            historical_incidents = historical_data.get("data", [])

            # Filter out the target incident itself if it exists
            if incident_id:
                historical_incidents = [
                    inc for inc in historical_incidents if str(inc.get("id")) != str(incident_id)
                ]

            if not historical_incidents:
                return {
                    "related_incidents": [],
                    "message": "No historical incidents found for comparison",
                    "target_incident": {
                        "id": incident_id or "synthetic",
                        "title": target_incident.get("attributes", {}).get(
                            "title", incident_description
                        ),
                    },
                }

            # Calculate similarities
            similar_incidents = similarity_analyzer.calculate_similarity(
                historical_incidents, target_incident
            )

            # Filter by threshold and limit results
            filtered_incidents = [
                inc for inc in similar_incidents if inc.similarity_score >= similarity_threshold
            ][:max_results]

            # Format response
            related_incidents = []
            for incident in filtered_incidents:
                related_incidents.append(
                    {
                        "incident_id": incident.incident_id,
                        "title": incident.title,
                        "similarity_score": round(incident.similarity_score, 3),
                        "matched_services": incident.matched_services,
                        "matched_keywords": incident.matched_keywords,
                        "resolution_summary": incident.resolution_summary,
                        "resolution_time_hours": incident.resolution_time_hours,
                    }
                )

            return {
                "target_incident": {
                    "id": incident_id or "synthetic",
                    "title": target_incident.get("attributes", {}).get(
                        "title", incident_description
                    ),
                },
                "related_incidents": related_incidents,
                "total_found": len(filtered_incidents),
                "similarity_threshold": similarity_threshold,
                "analysis_summary": f"Found {len(filtered_incidents)} similar incidents out of {len(historical_incidents)} historical incidents",
            }

        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(
                f"Failed to find related incidents: {error_message}", error_type
            )

    @mcp.tool()
    async def suggest_solutions(
        incident_id: str = "",
        incident_title: str = "",
        incident_description: str = "",
        max_solutions: Annotated[
            int, Field(description="Maximum number of solution suggestions", ge=1, le=10)
        ] = 3,
        status_filter: Annotated[
            str,
            Field(
                description="Filter incidents by status (default 'resolved', empty for all, 'investigating', etc.)"
            ),
        ] = "resolved",
    ) -> dict:
        """Suggest solutions based on similar incidents. Provide either incident_id OR title/description. Defaults to resolved incidents for solution mining, but can search all statuses."""
        try:
            target_incident = {}

            if incident_id:
                # Get incident details by ID
                response = await make_authenticated_request("GET", f"/v1/incidents/{incident_id}")
                response.raise_for_status()
                incident_data = strip_heavy_nested_data({"data": [response.json().get("data", {})]})
                target_incident = incident_data.get("data", [{}])[0]

                if not target_incident:
                    return MCPError.tool_error("Incident not found", "not_found")

            elif incident_title or incident_description:
                # Create synthetic incident for analysis
                target_incident = {
                    "id": "synthetic",
                    "attributes": {
                        "title": incident_title,
                        "summary": incident_description,
                        "description": incident_description,
                    },
                }
            else:
                return MCPError.tool_error(
                    "Must provide either incident_id or incident_title/description",
                    "validation_error",
                )

            # Get incidents for solution mining
            params = {
                "page[size]": 150,  # Get more incidents for better solution matching
                "page[number]": 1,
                "include": "",
            }

            # Only add status filter if specified
            if status_filter:
                params["filter[status]"] = status_filter

            historical_response = await make_authenticated_request(
                "GET", "/v1/incidents", params=params
            )
            historical_response.raise_for_status()
            historical_data = strip_heavy_nested_data(historical_response.json())
            historical_incidents = historical_data.get("data", [])

            # Filter out target incident if it exists
            if incident_id:
                historical_incidents = [
                    inc for inc in historical_incidents if str(inc.get("id")) != str(incident_id)
                ]

            if not historical_incidents:
                status_msg = f" with status '{status_filter}'" if status_filter else ""
                return {
                    "solutions": [],
                    "message": f"No historical incidents found{status_msg} for solution mining",
                }

            # Find similar incidents
            similar_incidents = similarity_analyzer.calculate_similarity(
                historical_incidents, target_incident
            )

            # Filter to reasonably similar incidents (lower threshold for solution suggestions)
            relevant_incidents = [inc for inc in similar_incidents if inc.similarity_score >= 0.2][
                : max_solutions * 2
            ]

            if not relevant_incidents:
                return {
                    "solutions": [],
                    "message": "No sufficiently similar incidents found for solution suggestions",
                    "suggestion": "This appears to be a unique incident. Consider escalating or consulting documentation.",
                }

            # Extract solutions
            solution_data = solution_extractor.extract_solutions(relevant_incidents)

            # Format response
            return {
                "target_incident": {
                    "id": incident_id or "synthetic",
                    "title": target_incident.get("attributes", {}).get("title", incident_title),
                    "description": target_incident.get("attributes", {}).get(
                        "summary", incident_description
                    ),
                },
                "solutions": solution_data["solutions"][:max_solutions],
                "insights": {
                    "common_patterns": solution_data["common_patterns"],
                    "average_resolution_time_hours": solution_data["average_resolution_time"],
                    "total_similar_incidents": solution_data["total_similar_incidents"],
                },
                "recommendation": _generate_recommendation(solution_data),
            }

        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(f"Failed to suggest solutions: {error_message}", error_type)

    @mcp.tool()
    async def get_oncall_shift_metrics(
        start_date: Annotated[
            str,
            Field(
                description="Start date for metrics (ISO 8601 format, e.g., '2025-10-01' or '2025-10-01T00:00:00Z')"
            ),
        ],
        end_date: Annotated[
            str,
            Field(
                description="End date for metrics (ISO 8601 format, e.g., '2025-10-31' or '2025-10-31T23:59:59Z')"
            ),
        ],
        user_ids: Annotated[
            str, Field(description="Comma-separated list of user IDs to filter by (optional)")
        ] = "",
        schedule_ids: Annotated[
            str, Field(description="Comma-separated list of schedule IDs to filter by (optional)")
        ] = "",
        team_ids: Annotated[
            str,
            Field(
                description="Comma-separated list of team IDs to filter by (requires querying schedules first)"
            ),
        ] = "",
        group_by: Annotated[
            str, Field(description="Group results by: 'user', 'schedule', 'team', or 'none'")
        ] = "user",
    ) -> dict:
        """
        Get on-call shift metrics for a specified time period. Returns shift counts, total hours,
        and other statistics grouped by user, schedule, or team.

        Examples:
        - Monthly report: start_date='2025-10-01', end_date='2025-10-31'
        - Specific user: start_date='2025-10-01', end_date='2025-10-31', user_ids='123,456'
        - Specific team: team_ids='team-1' (will query schedules for that team first)
        """
        try:
            from collections import defaultdict
            from datetime import datetime, timedelta
            from typing import Any

            # Build query parameters
            params: dict[str, Any] = {
                "from": start_date,
                "to": end_date,
            }

            # Fetch schedules (schedules don't have team relationship, they have owner_group_ids)
            schedules_response = await make_authenticated_request(
                "GET", "/v1/schedules", params={"page[size]": 100}
            )

            if schedules_response is None:
                return MCPError.tool_error(
                    "Failed to get schedules: API request returned None", "execution_error"
                )

            schedules_response.raise_for_status()
            schedules_data = schedules_response.json()

            all_schedules = schedules_data.get("data", [])

            # Collect all unique team IDs from schedules' owner_group_ids
            team_ids_set = set()
            for schedule in all_schedules:
                owner_group_ids = schedule.get("attributes", {}).get("owner_group_ids", [])
                team_ids_set.update(owner_group_ids)

            # Fetch all teams
            teams_map = {}
            if team_ids_set:
                teams_response = await make_authenticated_request(
                    "GET", "/v1/teams", params={"page[size]": 100}
                )
                if teams_response and teams_response.status_code == 200:
                    teams_data = teams_response.json()
                    for team in teams_data.get("data", []):
                        teams_map[team.get("id")] = team

            # Build schedule -> team mapping
            schedule_to_team_map = {}
            for schedule in all_schedules:
                schedule_id = schedule.get("id")
                schedule_name = schedule.get("attributes", {}).get("name", "Unknown")
                owner_group_ids = schedule.get("attributes", {}).get("owner_group_ids", [])

                # Use the first owner group as the primary team
                if owner_group_ids:
                    team_id = owner_group_ids[0]
                    team_attrs = teams_map.get(team_id, {}).get("attributes", {})
                    team_name = team_attrs.get("name", "Unknown Team")
                    schedule_to_team_map[schedule_id] = {
                        "team_id": team_id,
                        "team_name": team_name,
                        "schedule_name": schedule_name,
                    }

            # Handle team filtering (requires multi-step query)
            target_schedule_ids = []
            if team_ids:
                team_id_list = [tid.strip() for tid in team_ids.split(",") if tid.strip()]

                # Filter schedules by team
                for schedule_id, team_info in schedule_to_team_map.items():
                    if str(team_info["team_id"]) in team_id_list:
                        target_schedule_ids.append(schedule_id)

            # Apply schedule filtering
            if schedule_ids:
                schedule_id_list = [sid.strip() for sid in schedule_ids.split(",") if sid.strip()]
                target_schedule_ids.extend(schedule_id_list)

            if target_schedule_ids:
                params["schedule_ids[]"] = target_schedule_ids

            # Apply user filtering
            if user_ids:
                user_id_list = [uid.strip() for uid in user_ids.split(",") if uid.strip()]
                params["user_ids[]"] = user_id_list

            # Include relationships for richer data
            params["include"] = "user,shift_override,on_call_role,schedule_rotation"

            # Query shifts
            try:
                shifts_response = await make_authenticated_request(
                    "GET", "/v1/shifts", params=params
                )

                if shifts_response is None:
                    return MCPError.tool_error(
                        "Failed to get shifts: API request returned None", "execution_error"
                    )

                shifts_response.raise_for_status()
                shifts_data = shifts_response.json()

                if shifts_data is None:
                    return MCPError.tool_error(
                        "Failed to get shifts: API returned null/empty response",
                        "execution_error",
                        details={"status": shifts_response.status_code},
                    )

                shifts = shifts_data.get("data", [])
                included = shifts_data.get("included", [])
            except AttributeError as e:
                return MCPError.tool_error(
                    f"Failed to get shifts: Response object error - {str(e)}",
                    "execution_error",
                    details={"params": params},
                )
            except Exception as e:
                return MCPError.tool_error(
                    f"Failed to get shifts: {str(e)}",
                    "execution_error",
                    details={"params": params, "error_type": type(e).__name__},
                )

            # Build lookup maps for included resources
            users_map = {}
            on_call_roles_map = {}
            for resource in included:
                if resource.get("type") == "users":
                    users_map[resource.get("id")] = resource
                elif resource.get("type") == "on_call_roles":
                    on_call_roles_map[resource.get("id")] = resource

            # Calculate metrics
            metrics: dict[str, dict[str, Any]] = defaultdict(
                lambda: {
                    "shift_count": 0,
                    "total_hours": 0.0,
                    "override_count": 0,
                    "regular_count": 0,
                    "primary_count": 0,
                    "secondary_count": 0,
                    "primary_hours": 0.0,
                    "secondary_hours": 0.0,
                    "unknown_role_count": 0,
                    "unique_days": set(),
                    "shifts": [],
                }
            )

            for shift in shifts:
                attrs = shift.get("attributes", {})
                relationships = shift.get("relationships", {})

                # Parse timestamps
                starts_at = attrs.get("starts_at")
                ends_at = attrs.get("ends_at")
                is_override = attrs.get("is_override", False)
                schedule_id = attrs.get("schedule_id")

                # Calculate shift duration in hours and track unique days
                duration_hours = 0.0
                shift_days = set()
                if starts_at and ends_at:
                    try:
                        start_dt = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                        end_dt = datetime.fromisoformat(ends_at.replace("Z", "+00:00"))
                        duration_hours = (end_dt - start_dt).total_seconds() / 3600

                        # Track all unique calendar days this shift spans
                        shift_start_date = start_dt.date()
                        shift_end_date = end_dt.date()
                        while shift_start_date <= shift_end_date:
                            shift_days.add(shift_start_date)
                            shift_start_date += timedelta(days=1)
                    except (ValueError, AttributeError):
                        pass

                # Get user info
                user_rel = relationships.get("user", {}).get("data") or {}
                user_id = user_rel.get("id")
                user_name = "Unknown"
                user_email = ""

                if user_id and user_id in users_map:
                    user_attrs = users_map[user_id].get("attributes", {})
                    user_name = user_attrs.get("full_name") or user_attrs.get("email", "Unknown")
                    user_email = user_attrs.get("email", "")

                # Get on-call role info (primary vs secondary)
                role_rel = relationships.get("on_call_role", {}).get("data") or {}
                role_id = role_rel.get("id")
                role_name = "unknown"
                is_primary = False

                if role_id and role_id in on_call_roles_map:
                    role_attrs = on_call_roles_map[role_id].get("attributes", {})
                    role_name = role_attrs.get("name", "").lower()
                    # Typically primary roles contain "primary" and secondary contain "secondary"
                    # Common patterns: "Primary", "Secondary", "L1", "L2", etc.
                    is_primary = "primary" in role_name or role_name == "l1" or role_name == "p1"

                # Determine grouping key
                if group_by == "user":
                    key = f"{user_id}|{user_name}"
                elif group_by == "schedule":
                    schedule_info = schedule_to_team_map.get(schedule_id, {})
                    schedule_name = schedule_info.get("schedule_name", f"schedule_{schedule_id}")
                    key = f"{schedule_id}|{schedule_name}"
                elif group_by == "team":
                    team_info = schedule_to_team_map.get(schedule_id, {})
                    if team_info:
                        team_id = team_info["team_id"]
                        team_name = team_info["team_name"]
                        key = f"{team_id}|{team_name}"
                    else:
                        key = "unknown_team|Unknown Team"
                else:
                    key = "all"

                # Update metrics
                metrics[key]["shift_count"] += 1
                metrics[key]["total_hours"] += duration_hours

                if is_override:
                    metrics[key]["override_count"] += 1
                else:
                    metrics[key]["regular_count"] += 1

                # Track primary vs secondary
                if role_id:
                    if is_primary:
                        metrics[key]["primary_count"] += 1
                        metrics[key]["primary_hours"] += duration_hours
                    else:
                        metrics[key]["secondary_count"] += 1
                        metrics[key]["secondary_hours"] += duration_hours
                else:
                    metrics[key]["unknown_role_count"] += 1

                # Track unique days
                metrics[key]["unique_days"].update(shift_days)

                metrics[key]["shifts"].append(
                    {
                        "shift_id": shift.get("id"),
                        "starts_at": starts_at,
                        "ends_at": ends_at,
                        "duration_hours": round(duration_hours, 2),
                        "is_override": is_override,
                        "schedule_id": schedule_id,
                        "user_id": user_id,
                        "user_name": user_name,
                        "user_email": user_email,
                        "role_name": role_name,
                        "is_primary": is_primary,
                    }
                )

            # Format results
            results = []
            for key, data in metrics.items():
                if group_by == "user":
                    user_id, user_name = key.split("|", 1)
                    result = {
                        "user_id": user_id,
                        "user_name": user_name,
                        "shift_count": data["shift_count"],
                        "days_on_call": len(data["unique_days"]),
                        "total_hours": round(data["total_hours"], 2),
                        "regular_shifts": data["regular_count"],
                        "override_shifts": data["override_count"],
                        "primary_shifts": data["primary_count"],
                        "secondary_shifts": data["secondary_count"],
                        "primary_hours": round(data["primary_hours"], 2),
                        "secondary_hours": round(data["secondary_hours"], 2),
                        "unknown_role_shifts": data["unknown_role_count"],
                    }
                elif group_by == "schedule":
                    schedule_id, schedule_name = key.split("|", 1)
                    result = {
                        "schedule_id": schedule_id,
                        "schedule_name": schedule_name,
                        "shift_count": data["shift_count"],
                        "days_on_call": len(data["unique_days"]),
                        "total_hours": round(data["total_hours"], 2),
                        "regular_shifts": data["regular_count"],
                        "override_shifts": data["override_count"],
                        "primary_shifts": data["primary_count"],
                        "secondary_shifts": data["secondary_count"],
                        "primary_hours": round(data["primary_hours"], 2),
                        "secondary_hours": round(data["secondary_hours"], 2),
                        "unknown_role_shifts": data["unknown_role_count"],
                    }
                elif group_by == "team":
                    team_id, team_name = key.split("|", 1)
                    result = {
                        "team_id": team_id,
                        "team_name": team_name,
                        "shift_count": data["shift_count"],
                        "days_on_call": len(data["unique_days"]),
                        "total_hours": round(data["total_hours"], 2),
                        "regular_shifts": data["regular_count"],
                        "override_shifts": data["override_count"],
                        "primary_shifts": data["primary_count"],
                        "secondary_shifts": data["secondary_count"],
                        "primary_hours": round(data["primary_hours"], 2),
                        "secondary_hours": round(data["secondary_hours"], 2),
                        "unknown_role_shifts": data["unknown_role_count"],
                    }
                else:
                    result = {
                        "group_key": key,
                        "shift_count": data["shift_count"],
                        "days_on_call": len(data["unique_days"]),
                        "total_hours": round(data["total_hours"], 2),
                        "regular_shifts": data["regular_count"],
                        "override_shifts": data["override_count"],
                        "primary_shifts": data["primary_count"],
                        "secondary_shifts": data["secondary_count"],
                        "primary_hours": round(data["primary_hours"], 2),
                        "secondary_hours": round(data["secondary_hours"], 2),
                        "unknown_role_shifts": data["unknown_role_count"],
                    }

                results.append(result)

            # Sort by shift count descending
            results.sort(key=lambda x: x["shift_count"], reverse=True)

            return {
                "period": {"start_date": start_date, "end_date": end_date},
                "total_shifts": len(shifts),
                "grouped_by": group_by,
                "metrics": results,
                "summary": {
                    "total_hours": round(sum(m["total_hours"] for m in results), 2),
                    "total_regular_shifts": sum(m["regular_shifts"] for m in results),
                    "total_override_shifts": sum(m["override_shifts"] for m in results),
                    "unique_people": len(results) if group_by == "user" else None,
                },
            }

        except Exception as e:
            import traceback

            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(
                f"Failed to get on-call shift metrics: {error_message}",
                error_type,
                details={
                    "params": {"start_date": start_date, "end_date": end_date},
                    "exception_type": type(e).__name__,
                    "exception_str": str(e),
                    "traceback": traceback.format_exc(),
                },
            )

    @mcp.tool()
    async def get_oncall_handoff_summary(
        team_ids: Annotated[
            str,
            Field(description="Comma-separated list of team IDs to filter schedules (optional)"),
        ] = "",
        schedule_ids: Annotated[
            str, Field(description="Comma-separated list of schedule IDs (optional)")
        ] = "",
        timezone: Annotated[
            str,
            Field(
                description="Timezone to use for display and filtering (e.g., 'America/Los_Angeles', 'Europe/London', 'Asia/Tokyo'). IMPORTANT: If user mentions a city, location, or region (e.g., 'Toronto', 'APAC', 'my time'), infer the appropriate IANA timezone. Defaults to UTC if not specified."
            ),
        ] = "UTC",
        filter_by_region: Annotated[
            bool,
            Field(
                description="If True, only show on-call for people whose shifts are during business hours (9am-5pm) in the specified timezone. Defaults to False."
            ),
        ] = False,
        include_incidents: Annotated[
            bool,
            Field(
                description="If True, fetch incidents for each shift (slower). If False, only show on-call info (faster). Defaults to False for better performance."
            ),
        ] = False,
    ) -> dict:
        """
        Get current on-call handoff summary. Shows who's currently on-call and who's next.
        Optionally fetch incidents (set include_incidents=True, but slower).

        Timezone handling: If user mentions their location/timezone, infer it (e.g., "Toronto" → "America/Toronto",
        "my time" → ask clarifying question or use a common timezone).

        Regional filtering: Use timezone + filter_by_region=True to see only people on-call
        during business hours in that region (e.g., timezone='Asia/Tokyo', filter_by_region=True
        shows only APAC on-call during APAC business hours).

        Performance: By default, incidents are NOT fetched for faster response. Set include_incidents=True
        to fetch incidents for each shift (slower, may timeout with many schedules).

        Useful for:
        - Quick on-call status checks
        - Daily handoff meetings
        - Regional on-call status (APAC, EU, Americas)
        - Team coordination across timezones
        """
        try:
            from datetime import datetime, timedelta
            from zoneinfo import ZoneInfo

            # Validate and set timezone
            try:
                tz = ZoneInfo(timezone)
            except Exception:
                tz = ZoneInfo("UTC")  # Fallback to UTC if invalid timezone

            now = datetime.now(tz)

            def convert_to_timezone(iso_string: str) -> str:
                """Convert ISO timestamp to target timezone."""
                if not iso_string:
                    return iso_string
                try:
                    dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
                    dt_converted = dt.astimezone(tz)
                    return dt_converted.isoformat()
                except (ValueError, AttributeError):
                    return iso_string  # Return original if conversion fails

            # Fetch schedules with team info (with pagination)
            all_schedules = []
            page = 1
            max_pages = 5  # Schedules shouldn't have many pages

            while page <= max_pages:
                schedules_response = await make_authenticated_request(
                    "GET", "/v1/schedules", params={"page[size]": 100, "page[number]": page}
                )
                if not schedules_response:
                    return MCPError.tool_error(
                        "Failed to fetch schedules - no response from API", "execution_error"
                    )

                if schedules_response.status_code != 200:
                    return MCPError.tool_error(
                        f"Failed to fetch schedules - API returned status {schedules_response.status_code}",
                        "execution_error",
                        details={"status_code": schedules_response.status_code},
                    )

                schedules_data = schedules_response.json()
                page_schedules = schedules_data.get("data", [])

                if not page_schedules:
                    break

                all_schedules.extend(page_schedules)

                # Check if there are more pages
                meta = schedules_data.get("meta", {})
                total_pages = meta.get("total_pages", 1)

                if page >= total_pages:
                    break

                page += 1

            # Build team mapping
            team_ids_set = set()
            for schedule in all_schedules:
                owner_group_ids = schedule.get("attributes", {}).get("owner_group_ids", [])
                team_ids_set.update(owner_group_ids)

            teams_map = {}
            if team_ids_set:
                teams_response = await make_authenticated_request(
                    "GET", "/v1/teams", params={"page[size]": 100}
                )
                if teams_response and teams_response.status_code == 200:
                    teams_data = teams_response.json()
                    for team in teams_data.get("data", []):
                        teams_map[team.get("id")] = team

            # Filter schedules
            target_schedules = []
            team_filter = (
                [tid.strip() for tid in team_ids.split(",") if tid.strip()] if team_ids else []
            )
            schedule_filter = (
                [sid.strip() for sid in schedule_ids.split(",") if sid.strip()]
                if schedule_ids
                else []
            )

            for schedule in all_schedules:
                schedule_id = schedule.get("id")
                owner_group_ids = schedule.get("attributes", {}).get("owner_group_ids", [])

                # Apply filters
                if schedule_filter and schedule_id not in schedule_filter:
                    continue
                if team_filter and not any(str(tgid) in team_filter for tgid in owner_group_ids):
                    continue

                target_schedules.append(schedule)

            # Get current and upcoming shifts for each schedule
            handoff_data = []
            for schedule in target_schedules:
                schedule_id = schedule.get("id")
                schedule_attrs = schedule.get("attributes", {})
                schedule_name = schedule_attrs.get("name", "Unknown Schedule")
                owner_group_ids = schedule_attrs.get("owner_group_ids", [])

                # Get team info
                team_name = "No Team"
                if owner_group_ids:
                    team_id = owner_group_ids[0]
                    team_attrs = teams_map.get(team_id, {}).get("attributes", {})
                    team_name = team_attrs.get("name", "Unknown Team")

                # Query shifts for this schedule
                shifts_response = await make_authenticated_request(
                    "GET",
                    "/v1/shifts",
                    params={
                        "schedule_ids[]": [schedule_id],
                        "filter[starts_at][gte]": (now - timedelta(days=1)).isoformat(),
                        "filter[starts_at][lte]": (now + timedelta(days=7)).isoformat(),
                        "include": "user,on_call_role",
                        "page[size]": 50,
                    },
                )

                if not shifts_response:
                    continue

                shifts_data = shifts_response.json()
                shifts = shifts_data.get("data", [])
                included = shifts_data.get("included", [])

                # Build user and role maps
                users_map = {}
                roles_map = {}
                for resource in included:
                    if resource.get("type") == "users":
                        users_map[resource.get("id")] = resource
                    elif resource.get("type") == "on_call_roles":
                        roles_map[resource.get("id")] = resource

                # Find current and next shifts
                current_shift = None
                next_shift = None

                for shift in sorted(
                    shifts, key=lambda s: s.get("attributes", {}).get("starts_at", "")
                ):
                    attrs = shift.get("attributes", {})
                    starts_at_str = attrs.get("starts_at")
                    ends_at_str = attrs.get("ends_at")

                    if not starts_at_str or not ends_at_str:
                        continue

                    try:
                        starts_at = datetime.fromisoformat(starts_at_str.replace("Z", "+00:00"))
                        ends_at = datetime.fromisoformat(ends_at_str.replace("Z", "+00:00"))

                        # Current shift: ongoing now
                        if starts_at <= now <= ends_at:
                            current_shift = shift
                        # Next shift: starts after now and no current shift found yet
                        elif starts_at > now and not next_shift:
                            next_shift = shift

                    except (ValueError, AttributeError):
                        continue

                # Build response for this schedule
                schedule_info = {
                    "schedule_id": schedule_id,
                    "schedule_name": schedule_name,
                    "team_name": team_name,
                    "current_oncall": None,
                    "next_oncall": None,
                }

                if current_shift:
                    current_attrs = current_shift.get("attributes", {})
                    current_rels = current_shift.get("relationships", {})
                    user_data = current_rels.get("user", {}).get("data") or {}
                    user_id = user_data.get("id")
                    role_data = current_rels.get("on_call_role", {}).get("data") or {}
                    role_id = role_data.get("id")

                    user_name = "Unknown"
                    if user_id and user_id in users_map:
                        user_attrs = users_map[user_id].get("attributes", {})
                        user_name = user_attrs.get("full_name") or user_attrs.get(
                            "email", "Unknown"
                        )

                    role_name = "Unknown Role"
                    if role_id and role_id in roles_map:
                        role_attrs = roles_map[role_id].get("attributes", {})
                        role_name = role_attrs.get("name", "Unknown Role")

                    schedule_info["current_oncall"] = {
                        "user_name": user_name,
                        "user_id": user_id,
                        "role": role_name,
                        "starts_at": convert_to_timezone(current_attrs.get("starts_at")),
                        "ends_at": convert_to_timezone(current_attrs.get("ends_at")),
                        "is_override": current_attrs.get("is_override", False),
                    }

                if next_shift:
                    next_attrs = next_shift.get("attributes", {})
                    next_rels = next_shift.get("relationships", {})
                    user_data = next_rels.get("user", {}).get("data") or {}
                    user_id = user_data.get("id")
                    role_data = next_rels.get("on_call_role", {}).get("data") or {}
                    role_id = role_data.get("id")

                    user_name = "Unknown"
                    if user_id and user_id in users_map:
                        user_attrs = users_map[user_id].get("attributes", {})
                        user_name = user_attrs.get("full_name") or user_attrs.get(
                            "email", "Unknown"
                        )

                    role_name = "Unknown Role"
                    if role_id and role_id in roles_map:
                        role_attrs = roles_map[role_id].get("attributes", {})
                        role_name = role_attrs.get("name", "Unknown Role")

                    schedule_info["next_oncall"] = {
                        "user_name": user_name,
                        "user_id": user_id,
                        "role": role_name,
                        "starts_at": convert_to_timezone(next_attrs.get("starts_at")),
                        "ends_at": convert_to_timezone(next_attrs.get("ends_at")),
                        "is_override": next_attrs.get("is_override", False),
                    }

                handoff_data.append(schedule_info)

            # Filter by region if requested
            if filter_by_region:
                # Define business hours (9am-5pm) in the target timezone
                business_start_hour = 9
                business_end_hour = 17

                # Create datetime objects for today's business hours in target timezone
                today_business_start = now.replace(
                    hour=business_start_hour, minute=0, second=0, microsecond=0
                )
                today_business_end = now.replace(
                    hour=business_end_hour, minute=0, second=0, microsecond=0
                )

                # Filter schedules where current shift overlaps with business hours
                filtered_data = []
                for schedule_info in handoff_data:
                    current_oncall = schedule_info.get("current_oncall")
                    if current_oncall:
                        # Parse shift times (already in target timezone)
                        shift_start_str = current_oncall.get("starts_at")
                        shift_end_str = current_oncall.get("ends_at")

                        if shift_start_str and shift_end_str:
                            try:
                                shift_start = datetime.fromisoformat(
                                    shift_start_str.replace("Z", "+00:00")
                                )
                                shift_end = datetime.fromisoformat(
                                    shift_end_str.replace("Z", "+00:00")
                                )

                                # Check if shift overlaps with today's business hours
                                # Shift overlaps if: shift_start < business_end AND shift_end > business_start
                                if (
                                    shift_start < today_business_end
                                    and shift_end > today_business_start
                                ):
                                    filtered_data.append(schedule_info)
                            except (ValueError, AttributeError):
                                # Skip if we can't parse times
                                continue

                handoff_data = filtered_data

            # Fetch incidents for each current shift (only if requested)
            if include_incidents:
                for schedule_info in handoff_data:
                    current_oncall = schedule_info.get("current_oncall")
                    if current_oncall:
                        shift_start = current_oncall["starts_at"]
                        shift_end = current_oncall["ends_at"]

                        incidents_result = await _fetch_shift_incidents_internal(
                            start_time=shift_start,
                            end_time=shift_end,
                            schedule_ids="",
                            severity="",
                            status="",
                            tags="",
                        )

                        schedule_info["shift_incidents"] = (
                            incidents_result if incidents_result.get("success") else None
                        )
                    else:
                        schedule_info["shift_incidents"] = None
            else:
                # Skip incident fetching for better performance
                for schedule_info in handoff_data:
                    schedule_info["shift_incidents"] = None

            return {
                "success": True,
                "timestamp": now.isoformat(),
                "timezone": timezone,
                "schedules": handoff_data,
                "summary": {
                    "total_schedules": len(handoff_data),
                    "schedules_with_current_oncall": sum(
                        1 for s in handoff_data if s["current_oncall"]
                    ),
                    "schedules_with_next_oncall": sum(1 for s in handoff_data if s["next_oncall"]),
                    "total_incidents": sum(
                        s.get("shift_incidents", {}).get("summary", {}).get("total_incidents", 0)
                        for s in handoff_data
                        if s.get("shift_incidents")
                    ),
                },
            }

        except Exception as e:
            import traceback

            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(
                f"Failed to get on-call handoff summary: {error_message}",
                error_type,
                details={
                    "exception_type": type(e).__name__,
                    "exception_str": str(e),
                    "traceback": traceback.format_exc(),
                },
            )

    async def _fetch_shift_incidents_internal(
        start_time: str,
        end_time: str,
        schedule_ids: str = "",
        severity: str = "",
        status: str = "",
        tags: str = "",
    ) -> dict:
        """Internal helper to fetch incidents - used by both get_shift_incidents and get_oncall_handoff_summary."""
        try:
            from datetime import datetime

            # Build query parameters
            # Fetch incidents that:
            # 1. Were created during the shift (created_at in range)
            # 2. OR are currently active/unresolved (started but not resolved yet)
            params = {"page[size]": 100, "sort": "-created_at"}

            # Get incidents created during shift OR still active
            # We'll fetch all incidents and filter in-memory for active ones
            params["filter[started_at][lte]"] = end_time  # Started before shift ended

            # Add severity filter if provided
            if severity:
                params["filter[severity]"] = severity.lower()

            # Add status filter if provided
            if status:
                params["filter[status]"] = status.lower()

            # Add tags filter if provided
            if tags:
                tag_list = [t.strip() for t in tags.split(",") if t.strip()]
                if tag_list:
                    params["filter[tags][]"] = tag_list

            # Query incidents with pagination
            all_incidents = []
            page = 1
            max_pages = 10  # Safety limit to prevent infinite loops

            while page <= max_pages:
                params["page[number]"] = page
                incidents_response = await make_authenticated_request(
                    "GET", "/v1/incidents", params=params
                )

                if not incidents_response:
                    return MCPError.tool_error(
                        "Failed to fetch incidents - no response from API", "execution_error"
                    )

                if incidents_response.status_code != 200:
                    return MCPError.tool_error(
                        f"Failed to fetch incidents - API returned status {incidents_response.status_code}",
                        "execution_error",
                        details={
                            "status_code": incidents_response.status_code,
                            "time_range": f"{start_time} to {end_time}",
                        },
                    )

                incidents_data = incidents_response.json()
                page_incidents = incidents_data.get("data", [])

                if not page_incidents:
                    break  # No more data

                all_incidents.extend(page_incidents)

                # Check if there are more pages
                meta = incidents_data.get("meta", {})
                total_pages = meta.get("total_pages", 1)

                if page >= total_pages:
                    break  # Reached the last page

                page += 1

            # Filter incidents to include:
            # 1. Created during shift (created_at between start_time and end_time)
            # 2. Currently active (started but not resolved, regardless of when created)
            from datetime import timezone as dt_timezone

            shift_start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            shift_end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            now_dt = datetime.now(dt_timezone.utc)

            # Format incidents for handoff summary
            incidents_summary = []
            for incident in all_incidents:
                incident_id = incident.get("id")
                attrs = incident.get("attributes", {})

                # Check if incident is relevant to this shift
                created_at = attrs.get("created_at")
                started_at = attrs.get("started_at")
                resolved_at = attrs.get("resolved_at")

                # Parse timestamps
                try:
                    created_dt = (
                        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        if created_at
                        else None
                    )
                    started_dt = (
                        datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                        if started_at
                        else None
                    )
                    resolved_dt = (
                        datetime.fromisoformat(resolved_at.replace("Z", "+00:00"))
                        if resolved_at
                        else None
                    )
                except (ValueError, AttributeError):
                    continue  # Skip if we can't parse dates

                # Include incident if:
                # 1. Created during shift
                # 2. Started during shift
                # 3. Resolved during shift
                # 4. Currently active (not resolved and started before now)
                include_incident = False

                if created_dt and shift_start_dt <= created_dt <= shift_end_dt:
                    include_incident = True  # Created during shift

                if started_dt and shift_start_dt <= started_dt <= shift_end_dt:
                    include_incident = True  # Started during shift

                if resolved_dt and shift_start_dt <= resolved_dt <= shift_end_dt:
                    include_incident = True  # Resolved during shift

                if not resolved_dt and started_dt and started_dt <= now_dt:
                    include_incident = True  # Currently active

                if not include_incident:
                    continue

                # Calculate duration if resolved
                duration_minutes = None
                if started_dt and resolved_dt:
                    duration_minutes = int((resolved_dt - started_dt).total_seconds() / 60)

                # Build narrative summary
                narrative_parts = []

                # What happened
                title = attrs.get("title", "Untitled Incident")
                severity = attrs.get("severity", "unknown")
                narrative_parts.append(f"[{severity.upper()}] {title}")

                # When and duration
                if started_at:
                    narrative_parts.append(f"Started at {started_at}")
                if resolved_at:
                    narrative_parts.append(f"Resolved at {resolved_at}")
                    if duration_minutes:
                        narrative_parts.append(f"Duration: {duration_minutes} minutes")
                elif attrs.get("status"):
                    narrative_parts.append(f"Status: {attrs.get('status')}")

                # What was the issue
                if attrs.get("summary"):
                    narrative_parts.append(f"Details: {attrs.get('summary')}")

                # Impact
                if attrs.get("customer_impact_summary"):
                    narrative_parts.append(f"Impact: {attrs.get('customer_impact_summary')}")

                # Resolution (if available)
                if attrs.get("mitigation"):
                    narrative_parts.append(f"Resolution: {attrs.get('mitigation')}")
                elif attrs.get("action_items_count") and attrs.get("action_items_count") > 0:
                    narrative_parts.append(
                        f"Action items created: {attrs.get('action_items_count')}"
                    )

                narrative = " | ".join(narrative_parts)

                incidents_summary.append(
                    {
                        "incident_id": incident_id,
                        "title": attrs.get("title", "Untitled Incident"),
                        "severity": attrs.get("severity"),
                        "status": attrs.get("status"),
                        "started_at": started_at,
                        "resolved_at": resolved_at,
                        "duration_minutes": duration_minutes,
                        "summary": attrs.get("summary"),
                        "impact": attrs.get("customer_impact_summary"),
                        "mitigation": attrs.get("mitigation"),
                        "narrative": narrative,
                        "incident_url": attrs.get("incident_url"),
                    }
                )

            # Group by severity
            by_severity = {}
            for inc in incidents_summary:
                sev = inc["severity"] or "unknown"
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(inc)

            # Calculate statistics
            total_incidents = len(incidents_summary)
            resolved_count = sum(1 for inc in incidents_summary if inc["resolved_at"])
            ongoing_count = total_incidents - resolved_count

            avg_resolution_time = None
            durations = [
                inc["duration_minutes"] for inc in incidents_summary if inc["duration_minutes"]
            ]
            if durations:
                avg_resolution_time = int(sum(durations) / len(durations))

            return {
                "success": True,
                "period": {"start_time": start_time, "end_time": end_time},
                "summary": {
                    "total_incidents": total_incidents,
                    "resolved": resolved_count,
                    "ongoing": ongoing_count,
                    "average_resolution_minutes": avg_resolution_time,
                    "by_severity": {k: len(v) for k, v in by_severity.items()},
                },
                "incidents": incidents_summary,
            }

        except Exception as e:
            import traceback

            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(
                f"Failed to get shift incidents: {error_message}",
                error_type,
                details={
                    "params": {"start_time": start_time, "end_time": end_time},
                    "exception_type": type(e).__name__,
                    "exception_str": str(e),
                    "traceback": traceback.format_exc(),
                },
            )

    @mcp.tool()
    async def get_shift_incidents(
        start_time: Annotated[
            str,
            Field(
                description="Start time for incident search (ISO 8601 format, e.g., '2025-10-01T00:00:00Z')"
            ),
        ],
        end_time: Annotated[
            str,
            Field(
                description="End time for incident search (ISO 8601 format, e.g., '2025-10-01T23:59:59Z')"
            ),
        ],
        schedule_ids: Annotated[
            str,
            Field(
                description="Comma-separated list of schedule IDs to filter incidents (optional)"
            ),
        ] = "",
        severity: Annotated[
            str,
            Field(description="Filter by severity: 'critical', 'high', 'medium', 'low' (optional)"),
        ] = "",
        status: Annotated[
            str,
            Field(
                description="Filter by status: 'started', 'detected', 'acknowledged', 'investigating', 'identified', 'monitoring', 'resolved', 'cancelled' (optional)"
            ),
        ] = "",
        tags: Annotated[
            str,
            Field(description="Comma-separated list of tag slugs to filter incidents (optional)"),
        ] = "",
    ) -> dict:
        """
        Get incidents and alerts that occurred during a specific shift or time period.

        Useful for:
        - Shift handoff summaries showing what happened during the shift
        - Post-shift debriefs and reporting
        - Incident analysis by time period
        - Understanding team workload during specific shifts

        Returns incident details including severity, status, duration, and basic summary.
        """
        return await _fetch_shift_incidents_internal(
            start_time, end_time, schedule_ids, severity, status, tags
        )

    # Cache for lookup maps (TTL: 5 minutes)
    _lookup_maps_cache: dict[str, Any] = {
        "data": None,
        "timestamp": 0.0,
        "ttl_seconds": 300,  # 5 minutes
    }
    _lookup_maps_lock = asyncio.Lock()

    # Helper function to fetch users and schedules for enrichment
    async def _fetch_users_and_schedules_maps() -> tuple[dict, dict, dict]:
        """Fetch all users, schedules, and teams to build lookup maps.

        Results are cached for 5 minutes to avoid repeated API calls.
        """
        import time

        # Check cache (fast path without lock)
        now = time.time()
        if (
            _lookup_maps_cache["data"] is not None
            and (now - _lookup_maps_cache["timestamp"]) < _lookup_maps_cache["ttl_seconds"]
        ):
            return _lookup_maps_cache["data"]

        # Acquire lock to prevent concurrent fetches
        async with _lookup_maps_lock:
            # Re-check cache after acquiring lock
            now = time.time()
            if (
                _lookup_maps_cache["data"] is not None
                and (now - _lookup_maps_cache["timestamp"]) < _lookup_maps_cache["ttl_seconds"]
            ):
                return _lookup_maps_cache["data"]

            users_map = {}
            schedules_map = {}
            teams_map = {}

            # Fetch all users with pagination
            page = 1
            while page <= 10:
                users_response = await make_authenticated_request(
                    "GET", "/v1/users", params={"page[size]": 100, "page[number]": page}
                )
                if users_response and users_response.status_code == 200:
                    users_data = users_response.json()
                    for user in users_data.get("data", []):
                        users_map[user.get("id")] = user
                    if len(users_data.get("data", [])) < 100:
                        break
                    page += 1
                else:
                    break

            # Fetch all schedules with pagination
            page = 1
            while page <= 10:
                schedules_response = await make_authenticated_request(
                    "GET", "/v1/schedules", params={"page[size]": 100, "page[number]": page}
                )
                if schedules_response and schedules_response.status_code == 200:
                    schedules_data = schedules_response.json()
                    for schedule in schedules_data.get("data", []):
                        schedules_map[schedule.get("id")] = schedule
                    if len(schedules_data.get("data", [])) < 100:
                        break
                    page += 1
                else:
                    break

            # Fetch all teams with pagination
            page = 1
            while page <= 10:
                teams_response = await make_authenticated_request(
                    "GET", "/v1/teams", params={"page[size]": 100, "page[number]": page}
                )
                if teams_response and teams_response.status_code == 200:
                    teams_data = teams_response.json()
                    for team in teams_data.get("data", []):
                        teams_map[team.get("id")] = team
                    if len(teams_data.get("data", [])) < 100:
                        break
                    page += 1
                else:
                    break

            # Cache the result
            result = (users_map, schedules_map, teams_map)
            _lookup_maps_cache["data"] = result
            _lookup_maps_cache["timestamp"] = now

            return result

    @mcp.tool()
    async def list_shifts(
        from_date: Annotated[
            str,
            Field(
                description="Start date/time for shift query (ISO 8601 format, e.g., '2026-02-09T00:00:00Z')"
            ),
        ],
        to_date: Annotated[
            str,
            Field(
                description="End date/time for shift query (ISO 8601 format, e.g., '2026-02-15T23:59:59Z')"
            ),
        ],
        user_ids: Annotated[
            str,
            Field(
                description="Comma-separated list of user IDs to filter by (e.g., '2381,94178'). Only returns shifts for these users."
            ),
        ] = "",
        schedule_ids: Annotated[
            str,
            Field(description="Comma-separated list of schedule IDs to filter by (optional)"),
        ] = "",
        include_user_details: Annotated[
            bool,
            Field(description="Include user name and email in response (default: True)"),
        ] = True,
    ) -> dict:
        """
        List on-call shifts with proper user filtering and enriched data.

        Unlike the raw API, this tool:
        - Actually filters by user_ids (client-side filtering)
        - Includes user_name, user_email, schedule_name, team_name
        - Calculates total_hours for each shift

        Use this instead of the auto-generated listShifts when you need user filtering.
        """
        try:
            from datetime import datetime

            # Build query parameters
            params: dict[str, Any] = {
                "from": from_date,
                "to": to_date,
                "include": "user,on_call_role,schedule_rotation",
                "page[size]": 100,
            }

            if schedule_ids:
                schedule_id_list = [sid.strip() for sid in schedule_ids.split(",") if sid.strip()]
                params["schedule_ids[]"] = schedule_id_list

            # Parse user_ids for filtering
            user_id_filter = set()
            if user_ids:
                user_id_filter = {uid.strip() for uid in user_ids.split(",") if uid.strip()}

            # Fetch lookup maps for enrichment
            users_map, schedules_map, teams_map = await _fetch_users_and_schedules_maps()

            # Build schedule -> team mapping
            schedule_to_team = {}
            for schedule_id, schedule in schedules_map.items():
                owner_group_ids = schedule.get("attributes", {}).get("owner_group_ids", [])
                if owner_group_ids:
                    team_id = owner_group_ids[0]
                    team = teams_map.get(team_id, {})
                    schedule_to_team[schedule_id] = {
                        "team_id": team_id,
                        "team_name": team.get("attributes", {}).get("name", "Unknown Team"),
                    }

            # Fetch all shifts with pagination
            all_shifts = []
            page = 1
            while page <= 10:
                params["page[number]"] = page
                shifts_response = await make_authenticated_request(
                    "GET", "/v1/shifts", params=params
                )

                if shifts_response is None:
                    break

                shifts_response.raise_for_status()
                shifts_data = shifts_response.json()

                shifts = shifts_data.get("data", [])
                included = shifts_data.get("included", [])

                # Update users_map from included data
                for resource in included:
                    if resource.get("type") == "users":
                        users_map[resource.get("id")] = resource

                if not shifts:
                    break

                all_shifts.extend(shifts)

                meta = shifts_data.get("meta", {})
                total_pages = meta.get("total_pages", 1)
                if page >= total_pages:
                    break
                page += 1

            # Process and filter shifts
            enriched_shifts = []
            for shift in all_shifts:
                attrs = shift.get("attributes", {})
                relationships = shift.get("relationships", {})

                # Get user info
                user_rel = relationships.get("user", {}).get("data") or {}
                user_id = user_rel.get("id")

                # Skip shifts without a user
                if not user_id:
                    continue

                # Apply user_ids filter
                if user_id_filter and str(user_id) not in user_id_filter:
                    continue

                user_info = users_map.get(user_id, {})
                user_attrs = user_info.get("attributes", {})
                user_name = user_attrs.get("full_name") or user_attrs.get("name") or "Unknown"
                user_email = user_attrs.get("email", "")

                # Get schedule info
                schedule_id = attrs.get("schedule_id")
                schedule_info = schedules_map.get(schedule_id, {})
                schedule_name = schedule_info.get("attributes", {}).get("name", "Unknown Schedule")

                # Get team info
                team_info = schedule_to_team.get(schedule_id, {})
                team_name = team_info.get("team_name", "Unknown Team")

                # Calculate total hours
                starts_at = attrs.get("starts_at")
                ends_at = attrs.get("ends_at")
                total_hours = 0.0
                if starts_at and ends_at:
                    try:
                        start_dt = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                        end_dt = datetime.fromisoformat(ends_at.replace("Z", "+00:00"))
                        total_hours = round((end_dt - start_dt).total_seconds() / 3600, 2)
                    except (ValueError, AttributeError):
                        pass

                enriched_shift = {
                    "shift_id": shift.get("id"),
                    "user_id": user_id,
                    "schedule_id": schedule_id,
                    "starts_at": starts_at,
                    "ends_at": ends_at,
                    "is_override": attrs.get("is_override", False),
                    "total_hours": total_hours,
                }

                if include_user_details:
                    enriched_shift["user_name"] = user_name
                    enriched_shift["user_email"] = user_email
                    enriched_shift["schedule_name"] = schedule_name
                    enriched_shift["team_name"] = team_name

                enriched_shifts.append(enriched_shift)

            return {
                "period": {"from": from_date, "to": to_date},
                "total_shifts": len(enriched_shifts),
                "filters_applied": {
                    "user_ids": list(user_id_filter) if user_id_filter else None,
                    "schedule_ids": schedule_ids if schedule_ids else None,
                },
                "shifts": enriched_shifts,
            }

        except Exception as e:
            import traceback

            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(
                f"Failed to list shifts: {error_message}",
                error_type,
                details={
                    "params": {"from": from_date, "to": to_date},
                    "exception_type": type(e).__name__,
                    "traceback": traceback.format_exc(),
                },
            )

    @mcp.tool()
    async def get_oncall_schedule_summary(
        start_date: Annotated[
            str,
            Field(description="Start date (ISO 8601, e.g., '2026-02-09')"),
        ],
        end_date: Annotated[
            str,
            Field(description="End date (ISO 8601, e.g., '2026-02-15')"),
        ],
        schedule_ids: Annotated[
            str,
            Field(description="Comma-separated schedule IDs to filter (optional)"),
        ] = "",
        team_ids: Annotated[
            str,
            Field(description="Comma-separated team IDs to filter (optional)"),
        ] = "",
        include_user_ids: Annotated[
            bool,
            Field(description="Include numeric user IDs for cross-platform correlation"),
        ] = True,
    ) -> dict:
        """
        Get compact on-call schedule summary for a date range.

        Returns one entry per user per schedule (not raw shifts), with
        aggregated hours. Optimized for AI agent context windows.

        Use this instead of listShifts when you need:
        - Aggregated hours per responder
        - Schedule coverage overview
        - Responder load analysis with warnings
        """
        try:
            from collections import defaultdict
            from datetime import datetime

            # Parse filter IDs
            schedule_id_filter = set()
            if schedule_ids:
                schedule_id_filter = {sid.strip() for sid in schedule_ids.split(",") if sid.strip()}

            team_id_filter = set()
            if team_ids:
                team_id_filter = {tid.strip() for tid in team_ids.split(",") if tid.strip()}

            # Fetch lookup maps
            users_map, schedules_map, teams_map = await _fetch_users_and_schedules_maps()

            # Build schedule -> team mapping and apply team filter
            schedule_to_team = {}
            filtered_schedule_ids = set()
            for schedule_id, schedule in schedules_map.items():
                owner_group_ids = schedule.get("attributes", {}).get("owner_group_ids", [])
                team_id = owner_group_ids[0] if owner_group_ids else None
                team = teams_map.get(team_id, {}) if team_id else {}
                team_name = team.get("attributes", {}).get("name", "Unknown Team")

                schedule_to_team[schedule_id] = {
                    "team_id": team_id,
                    "team_name": team_name,
                    "schedule_name": schedule.get("attributes", {}).get("name", "Unknown Schedule"),
                }

                # Apply filters
                if schedule_id_filter and schedule_id not in schedule_id_filter:
                    continue
                if team_id_filter and (not team_id or team_id not in team_id_filter):
                    continue
                filtered_schedule_ids.add(schedule_id)

            # If no filters, include all schedules
            if not schedule_id_filter and not team_id_filter:
                filtered_schedule_ids = set(schedules_map.keys())

            # Fetch shifts
            params: dict[str, Any] = {
                "from": f"{start_date}T00:00:00Z" if "T" not in start_date else start_date,
                "to": f"{end_date}T23:59:59Z" if "T" not in end_date else end_date,
                "include": "user,on_call_role",
                "page[size]": 100,
            }

            all_shifts = []
            page = 1
            while page <= 10:
                params["page[number]"] = page
                shifts_response = await make_authenticated_request(
                    "GET", "/v1/shifts", params=params
                )

                if shifts_response is None:
                    break

                shifts_response.raise_for_status()
                shifts_data = shifts_response.json()

                shifts = shifts_data.get("data", [])
                included = shifts_data.get("included", [])

                # Update users_map from included data
                for resource in included:
                    if resource.get("type") == "users":
                        users_map[resource.get("id")] = resource

                if not shifts:
                    break

                all_shifts.extend(shifts)

                meta = shifts_data.get("meta", {})
                total_pages = meta.get("total_pages", 1)
                if page >= total_pages:
                    break
                page += 1

            # Aggregate by schedule and user
            schedule_coverage: dict[str, dict] = defaultdict(
                lambda: {
                    "schedule_name": "",
                    "team_name": "",
                    "responders": defaultdict(
                        lambda: {
                            "user_name": "",
                            "user_id": None,
                            "total_hours": 0.0,
                            "shift_count": 0,
                            "is_override": False,
                        }
                    ),
                }
            )

            responder_load: dict[str, dict] = defaultdict(
                lambda: {
                    "user_name": "",
                    "user_id": None,
                    "total_hours": 0.0,
                    "schedules": set(),
                }
            )

            for shift in all_shifts:
                attrs = shift.get("attributes", {})
                schedule_id = attrs.get("schedule_id")

                # Apply schedule filter
                if filtered_schedule_ids and schedule_id not in filtered_schedule_ids:
                    continue

                # Get user info
                relationships = shift.get("relationships", {})
                user_rel = relationships.get("user", {}).get("data") or {}
                user_id = user_rel.get("id")

                # Skip shifts without a user
                if not user_id:
                    continue

                user_info = users_map.get(user_id, {})
                user_attrs = user_info.get("attributes", {})
                user_name = user_attrs.get("full_name") or user_attrs.get("name") or "Unknown"

                # Get schedule/team info
                sched_info = schedule_to_team.get(schedule_id, {})
                schedule_name = sched_info.get("schedule_name", "Unknown Schedule")
                team_name = sched_info.get("team_name", "Unknown Team")

                # Calculate hours
                starts_at = attrs.get("starts_at")
                ends_at = attrs.get("ends_at")
                hours = 0.0
                if starts_at and ends_at:
                    try:
                        start_dt = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                        end_dt = datetime.fromisoformat(ends_at.replace("Z", "+00:00"))
                        hours = (end_dt - start_dt).total_seconds() / 3600
                    except (ValueError, AttributeError):
                        pass

                is_override = attrs.get("is_override", False)

                # Update schedule coverage
                sched_data = schedule_coverage[schedule_id]
                sched_data["schedule_name"] = schedule_name
                sched_data["team_name"] = team_name

                user_key = str(user_id)
                sched_data["responders"][user_key]["user_name"] = user_name
                sched_data["responders"][user_key]["user_id"] = user_id
                sched_data["responders"][user_key]["total_hours"] += hours
                sched_data["responders"][user_key]["shift_count"] += 1
                if is_override:
                    sched_data["responders"][user_key]["is_override"] = True

                # Update responder load
                responder_load[user_key]["user_name"] = user_name
                responder_load[user_key]["user_id"] = user_id
                responder_load[user_key]["total_hours"] += hours
                responder_load[user_key]["schedules"].add(schedule_name)

            # Format schedule coverage
            formatted_coverage = []
            for _schedule_id, sched_data in schedule_coverage.items():
                responders_list = []
                for _user_key, resp_data in sched_data["responders"].items():
                    responder = {
                        "user_name": resp_data["user_name"],
                        "total_hours": round(resp_data["total_hours"], 1),
                        "shift_count": resp_data["shift_count"],
                        "is_override": resp_data["is_override"],
                    }
                    if include_user_ids:
                        responder["user_id"] = resp_data["user_id"]
                    responders_list.append(responder)

                # Sort by hours descending
                responders_list.sort(key=lambda x: x["total_hours"], reverse=True)

                formatted_coverage.append(
                    {
                        "schedule_name": sched_data["schedule_name"],
                        "team_name": sched_data["team_name"],
                        "responders": responders_list,
                    }
                )

            # Format responder load with warnings
            formatted_load = []
            for _user_key, load_data in responder_load.items():
                schedules_list = list(load_data["schedules"])
                hours = round(load_data["total_hours"], 1)

                responder_entry = {
                    "user_name": load_data["user_name"],
                    "total_hours": hours,
                    "schedules": schedules_list,
                }
                if include_user_ids:
                    responder_entry["user_id"] = load_data["user_id"]

                # Add warnings for high load
                if len(schedules_list) >= 4:
                    responder_entry["warning"] = (
                        f"High load: {len(schedules_list)} concurrent schedules"
                    )
                elif hours >= 168:  # 7 days * 24 hours
                    responder_entry["warning"] = f"High load: {hours} hours in period"

                formatted_load.append(responder_entry)

            # Sort by hours descending
            formatted_load.sort(key=lambda x: x["total_hours"], reverse=True)
            formatted_coverage.sort(key=lambda x: x["schedule_name"])

            return {
                "period": {"start": start_date, "end": end_date},
                "total_schedules": len(formatted_coverage),
                "total_responders": len(formatted_load),
                "schedule_coverage": formatted_coverage,
                "responder_load": formatted_load,
            }

        except Exception as e:
            import traceback

            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(
                f"Failed to get on-call schedule summary: {error_message}",
                error_type,
                details={
                    "params": {"start_date": start_date, "end_date": end_date},
                    "exception_type": type(e).__name__,
                    "traceback": traceback.format_exc(),
                },
            )

    @mcp.tool()
    async def check_responder_availability(
        start_date: Annotated[
            str,
            Field(description="Start date (ISO 8601, e.g., '2026-02-09')"),
        ],
        end_date: Annotated[
            str,
            Field(description="End date (ISO 8601, e.g., '2026-02-15')"),
        ],
        user_ids: Annotated[
            str,
            Field(
                description="Comma-separated Rootly user IDs to check (e.g., '2381,94178,27965')"
            ),
        ],
    ) -> dict:
        """
        Check if specific users are scheduled for on-call in a date range.

        Use this to verify if at-risk users (from On-Call Health) are scheduled,
        or to check availability before assigning new shifts.

        Returns scheduled users with their shifts and total hours,
        plus users who are not scheduled.
        """
        try:
            from datetime import datetime

            if not user_ids:
                return MCPError.tool_error(
                    "user_ids parameter is required",
                    "validation_error",
                )

            # Parse user IDs
            user_id_list = [uid.strip() for uid in user_ids.split(",") if uid.strip()]
            user_id_set = set(user_id_list)

            # Fetch lookup maps
            users_map, schedules_map, teams_map = await _fetch_users_and_schedules_maps()

            # Build schedule -> team mapping
            schedule_to_team = {}
            for schedule_id, schedule in schedules_map.items():
                owner_group_ids = schedule.get("attributes", {}).get("owner_group_ids", [])
                if owner_group_ids:
                    team_id = owner_group_ids[0]
                    team = teams_map.get(team_id, {})
                    schedule_to_team[schedule_id] = {
                        "schedule_name": schedule.get("attributes", {}).get("name", "Unknown"),
                        "team_name": team.get("attributes", {}).get("name", "Unknown Team"),
                    }

            # Fetch shifts
            params: dict[str, Any] = {
                "from": f"{start_date}T00:00:00Z" if "T" not in start_date else start_date,
                "to": f"{end_date}T23:59:59Z" if "T" not in end_date else end_date,
                "include": "user,on_call_role",
                "page[size]": 100,
            }

            all_shifts = []
            page = 1
            while page <= 10:
                params["page[number]"] = page
                shifts_response = await make_authenticated_request(
                    "GET", "/v1/shifts", params=params
                )

                if shifts_response is None:
                    break

                shifts_response.raise_for_status()
                shifts_data = shifts_response.json()

                shifts = shifts_data.get("data", [])
                included = shifts_data.get("included", [])

                # Update users_map from included data
                for resource in included:
                    if resource.get("type") == "users":
                        users_map[resource.get("id")] = resource

                if not shifts:
                    break

                all_shifts.extend(shifts)

                meta = shifts_data.get("meta", {})
                total_pages = meta.get("total_pages", 1)
                if page >= total_pages:
                    break
                page += 1

            # Group shifts by user
            user_shifts: dict[str, list] = {uid: [] for uid in user_id_list}
            user_hours: dict[str, float] = dict.fromkeys(user_id_list, 0.0)

            for shift in all_shifts:
                attrs = shift.get("attributes", {})
                relationships = shift.get("relationships", {})

                user_rel = relationships.get("user", {}).get("data") or {}
                raw_user_id = user_rel.get("id")

                # Skip shifts without a user
                if not raw_user_id:
                    continue

                user_id = str(raw_user_id)

                if user_id not in user_id_set:
                    continue

                schedule_id = attrs.get("schedule_id")
                sched_info = schedule_to_team.get(schedule_id, {})

                starts_at = attrs.get("starts_at")
                ends_at = attrs.get("ends_at")
                hours = 0.0
                if starts_at and ends_at:
                    try:
                        start_dt = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                        end_dt = datetime.fromisoformat(ends_at.replace("Z", "+00:00"))
                        hours = round((end_dt - start_dt).total_seconds() / 3600, 1)
                    except (ValueError, AttributeError):
                        pass

                user_shifts[user_id].append(
                    {
                        "schedule_name": sched_info.get("schedule_name", "Unknown"),
                        "starts_at": starts_at,
                        "ends_at": ends_at,
                        "hours": hours,
                    }
                )
                user_hours[user_id] += hours

            # Format results
            scheduled = []
            not_scheduled = []

            for user_id in user_id_list:
                user_info = users_map.get(user_id, {})
                user_attrs = user_info.get("attributes", {})
                user_name = user_attrs.get("full_name") or user_attrs.get("name") or "Unknown"

                shifts = user_shifts.get(user_id, [])
                if shifts:
                    scheduled.append(
                        {
                            "user_id": int(user_id) if user_id.isdigit() else user_id,
                            "user_name": user_name,
                            "total_hours": round(user_hours[user_id], 1),
                            "shifts": shifts,
                        }
                    )
                else:
                    not_scheduled.append(
                        {
                            "user_id": int(user_id) if user_id.isdigit() else user_id,
                            "user_name": user_name,
                        }
                    )

            # Sort scheduled by hours descending
            scheduled.sort(key=lambda x: x["total_hours"], reverse=True)

            return {
                "period": {"start": start_date, "end": end_date},
                "checked_users": len(user_id_list),
                "scheduled": scheduled,
                "not_scheduled": not_scheduled,
            }

        except Exception as e:
            import traceback

            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(
                f"Failed to check responder availability: {error_message}",
                error_type,
                details={
                    "params": {
                        "start_date": start_date,
                        "end_date": end_date,
                        "user_ids": user_ids,
                    },
                    "exception_type": type(e).__name__,
                    "traceback": traceback.format_exc(),
                },
            )

    @mcp.tool()
    async def create_override_recommendation(
        schedule_id: Annotated[
            str,
            Field(description="Schedule ID to create override for"),
        ],
        original_user_id: Annotated[
            int,
            Field(description="User ID being replaced"),
        ],
        start_date: Annotated[
            str,
            Field(description="Override start (ISO 8601, e.g., '2026-02-09')"),
        ],
        end_date: Annotated[
            str,
            Field(description="Override end (ISO 8601, e.g., '2026-02-15')"),
        ],
        exclude_user_ids: Annotated[
            str,
            Field(description="Comma-separated user IDs to exclude (e.g., other at-risk users)"),
        ] = "",
    ) -> dict:
        """
        Recommend replacement responders for an override shift.

        Finds users in the same schedule rotation who are not already
        heavily loaded during the period.

        Returns recommended replacements sorted by current load (lowest first),
        plus a ready-to-use override payload for the top recommendation.
        """
        try:
            from datetime import datetime

            # Parse exclusions
            exclude_set = set()
            if exclude_user_ids:
                exclude_set = {uid.strip() for uid in exclude_user_ids.split(",") if uid.strip()}
            exclude_set.add(str(original_user_id))

            # Fetch lookup maps
            users_map, schedules_map, teams_map = await _fetch_users_and_schedules_maps()

            # Get schedule info
            schedule = schedules_map.get(schedule_id, {})
            schedule_name = schedule.get("attributes", {}).get("name", "Unknown Schedule")

            # Get original user info
            original_user = users_map.get(str(original_user_id), {})
            original_user_attrs = original_user.get("attributes", {})
            original_user_name = (
                original_user_attrs.get("full_name") or original_user_attrs.get("name") or "Unknown"
            )

            # Fetch schedule rotations to find rotation users
            rotation_users = set()

            # First, get the schedule to find its rotations
            schedule_response = await make_authenticated_request(
                "GET", f"/v1/schedules/{schedule_id}"
            )

            if schedule_response and schedule_response.status_code == 200:
                import asyncio

                schedule_data = schedule_response.json()
                schedule_obj = schedule_data.get("data", {})
                relationships = schedule_obj.get("relationships", {})

                # Get schedule rotations
                rotations = relationships.get("schedule_rotations", {}).get("data", [])
                rotation_ids = [r.get("id") for r in rotations if r.get("id")]

                # Fetch all rotation users in parallel
                if rotation_ids:

                    async def fetch_rotation_users(rotation_id: str):
                        response = await make_authenticated_request(
                            "GET",
                            f"/v1/schedule_rotations/{rotation_id}/schedule_rotation_users",
                            params={"page[size]": 100},
                        )
                        if response and response.status_code == 200:
                            return response.json().get("data", [])
                        return []

                    # Execute all rotation user fetches in parallel
                    rotation_results = await asyncio.gather(
                        *[fetch_rotation_users(rid) for rid in rotation_ids], return_exceptions=True
                    )

                    # Process results
                    for result in rotation_results:
                        if isinstance(result, list):
                            for ru in result:
                                user_rel = (
                                    ru.get("relationships", {}).get("user", {}).get("data", {})
                                )
                                user_id = user_rel.get("id")
                                if user_id:
                                    rotation_users.add(str(user_id))

            # Fetch shifts to calculate current load for rotation users
            params: dict[str, Any] = {
                "from": f"{start_date}T00:00:00Z" if "T" not in start_date else start_date,
                "to": f"{end_date}T23:59:59Z" if "T" not in end_date else end_date,
                "include": "user",
                "page[size]": 100,
            }

            all_shifts = []
            page = 1
            while page <= 10:
                params["page[number]"] = page
                shifts_response = await make_authenticated_request(
                    "GET", "/v1/shifts", params=params
                )

                if shifts_response is None:
                    break

                shifts_response.raise_for_status()
                shifts_data = shifts_response.json()

                shifts = shifts_data.get("data", [])
                included = shifts_data.get("included", [])

                for resource in included:
                    if resource.get("type") == "users":
                        users_map[resource.get("id")] = resource

                if not shifts:
                    break

                all_shifts.extend(shifts)

                meta = shifts_data.get("meta", {})
                total_pages = meta.get("total_pages", 1)
                if page >= total_pages:
                    break
                page += 1

            # Calculate load per user
            user_load: dict[str, float] = {}
            for shift in all_shifts:
                attrs = shift.get("attributes", {})
                relationships = shift.get("relationships", {})

                user_rel = relationships.get("user", {}).get("data") or {}
                raw_user_id = user_rel.get("id")

                # Skip shifts without a user
                if not raw_user_id:
                    continue

                user_id = str(raw_user_id)

                starts_at = attrs.get("starts_at")
                ends_at = attrs.get("ends_at")
                hours = 0.0
                if starts_at and ends_at:
                    try:
                        start_dt = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                        end_dt = datetime.fromisoformat(ends_at.replace("Z", "+00:00"))
                        hours = (end_dt - start_dt).total_seconds() / 3600
                    except (ValueError, AttributeError):
                        pass

                user_load[user_id] = user_load.get(user_id, 0.0) + hours

            # Find recommendations from rotation users
            recommendations = []
            for user_id in rotation_users:
                if user_id in exclude_set:
                    continue

                user_info = users_map.get(user_id, {})
                user_attrs = user_info.get("attributes", {})
                user_name = user_attrs.get("full_name") or user_attrs.get("name") or "Unknown"

                current_hours = round(user_load.get(user_id, 0.0), 1)

                # Generate reason based on load
                if current_hours == 0:
                    reason = "Already in rotation, no current load"
                elif current_hours < 24:
                    reason = "Already in rotation, low load"
                elif current_hours < 48:
                    reason = "Same team, moderate availability"
                else:
                    reason = "In rotation, but higher load"

                recommendations.append(
                    {
                        "user_id": int(user_id) if user_id.isdigit() else user_id,
                        "user_name": user_name,
                        "current_hours_in_period": current_hours,
                        "reason": reason,
                    }
                )

            # Sort by load (lowest first)
            recommendations.sort(key=lambda x: x["current_hours_in_period"])

            # Build override payload for top recommendation
            override_payload = None
            if recommendations:
                top_rec = recommendations[0]
                # Format dates for API
                override_starts = f"{start_date}T00:00:00Z" if "T" not in start_date else start_date
                override_ends = f"{end_date}T23:59:59Z" if "T" not in end_date else end_date

                override_payload = {
                    "schedule_id": schedule_id,
                    "user_id": top_rec["user_id"],
                    "starts_at": override_starts,
                    "ends_at": override_ends,
                }

            # Build response with optional warning
            response = {
                "schedule_name": schedule_name,
                "original_user": {
                    "id": original_user_id,
                    "name": original_user_name,
                },
                "period": {
                    "start": start_date,
                    "end": end_date,
                },
                "recommended_replacements": recommendations[:5],  # Top 5
                "override_payload": override_payload,
            }

            # Add warning if no recommendations available
            if not rotation_users:
                response["warning"] = (
                    "No rotation users found for this schedule. The schedule may not have any rotations configured."
                )
            elif not recommendations:
                response["warning"] = (
                    "All rotation users are either excluded or the original user. No recommendations available."
                )

            return response

        except Exception as e:
            import traceback

            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(
                f"Failed to create override recommendation: {error_message}",
                error_type,
                details={
                    "params": {
                        "schedule_id": schedule_id,
                        "original_user_id": original_user_id,
                    },
                    "exception_type": type(e).__name__,
                    "traceback": traceback.format_exc(),
                },
            )

    # Add MCP resources for incidents and teams
    @mcp.resource("incident://{incident_id}")
    async def get_incident_resource(incident_id: str):
        """Expose incident details as an MCP resource for easy reference and context."""
        try:
            response = await make_authenticated_request("GET", f"/v1/incidents/{incident_id}")
            response.raise_for_status()
            incident_data = strip_heavy_nested_data({"data": [response.json().get("data", {})]})

            # Format incident data as readable text
            incident = incident_data.get("data", [{}])[0]
            attributes = incident.get("attributes", {})

            text_content = f"""Incident #{incident_id}
Title: {attributes.get("title", "N/A")}
Status: {attributes.get("status", "N/A")}
Severity: {attributes.get("severity", "N/A")}
Created: {attributes.get("created_at", "N/A")}
Updated: {attributes.get("updated_at", "N/A")}
Summary: {attributes.get("summary", "N/A")}
URL: {attributes.get("url", "N/A")}"""

            return {
                "uri": f"incident://{incident_id}",
                "name": f"Incident #{incident_id}",
                "text": text_content,
                "mimeType": "text/plain",
            }
        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return {
                "uri": f"incident://{incident_id}",
                "name": f"Incident #{incident_id} (Error)",
                "text": f"Error ({error_type}): {error_message}",
                "mimeType": "text/plain",
            }

    @mcp.resource("team://{team_id}")
    async def get_team_resource(team_id: str):
        """Expose team details as an MCP resource for easy reference and context."""
        try:
            response = await make_authenticated_request("GET", f"/v1/teams/{team_id}")
            response.raise_for_status()
            team_data = response.json()

            # Format team data as readable text
            team = team_data.get("data", {})
            attributes = team.get("attributes", {})

            text_content = f"""Team #{team_id}
Name: {attributes.get("name", "N/A")}
Color: {attributes.get("color", "N/A")}
Slug: {attributes.get("slug", "N/A")}
Created: {attributes.get("created_at", "N/A")}
Updated: {attributes.get("updated_at", "N/A")}"""

            return {
                "uri": f"team://{team_id}",
                "name": f"Team: {attributes.get('name', team_id)}",
                "text": text_content,
                "mimeType": "text/plain",
            }
        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return {
                "uri": f"team://{team_id}",
                "name": f"Team #{team_id} (Error)",
                "text": f"Error ({error_type}): {error_message}",
                "mimeType": "text/plain",
            }

    @mcp.resource("rootly://incidents")
    async def list_incidents_resource():
        """List recent incidents as an MCP resource for quick reference."""
        try:
            response = await make_authenticated_request(
                "GET",
                "/v1/incidents",
                params={
                    "page[size]": 10,
                    "page[number]": 1,
                    "include": "",
                    "fields[incidents]": "id,title,status",
                },
            )
            response.raise_for_status()
            data = strip_heavy_nested_data(response.json())

            incidents = data.get("data", [])
            text_lines = ["Recent Incidents:\n"]

            for incident in incidents:
                attrs = incident.get("attributes", {})
                text_lines.append(
                    f"• #{incident.get('id', 'N/A')} - {attrs.get('title', 'N/A')} [{attrs.get('status', 'N/A')}]"
                )

            return {
                "uri": "rootly://incidents",
                "name": "Recent Incidents",
                "text": "\n".join(text_lines),
                "mimeType": "text/plain",
            }
        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return {
                "uri": "rootly://incidents",
                "name": "Recent Incidents (Error)",
                "text": f"Error ({error_type}): {error_message}",
                "mimeType": "text/plain",
            }

    @mcp.tool()
    async def check_oncall_health_risk(
        start_date: Annotated[
            str,
            Field(description="Start date for the on-call period (ISO 8601, e.g., '2026-02-09')"),
        ],
        end_date: Annotated[
            str,
            Field(description="End date for the on-call period (ISO 8601, e.g., '2026-02-15')"),
        ],
        och_analysis_id: Annotated[
            int | None,
            Field(
                description="On-Call Health analysis ID. If not provided, uses the latest analysis"
            ),
        ] = None,
        och_threshold: Annotated[
            float,
            Field(description="OCH score threshold for at-risk classification (default: 50.0)"),
        ] = 50.0,
        include_replacements: Annotated[
            bool,
            Field(description="Include recommended replacement responders (default: true)"),
        ] = True,
    ) -> dict:
        """Check if any at-risk responders (based on On-Call Health analysis) are scheduled for on-call.

        Integrates with On-Call Health (oncallhealth.ai) to identify responders with elevated
        workload health risk and checks if they are scheduled during the specified period.
        Optionally recommends safe replacement responders.

        Requires ONCALLHEALTH_API_KEY environment variable.
        """
        try:
            # Validate OCH API key is configured
            if not os.environ.get("ONCALLHEALTH_API_KEY"):
                raise PermissionError(
                    "ONCALLHEALTH_API_KEY environment variable required. "
                    "Get your key from oncallhealth.ai/settings/api-keys"
                )

            och_client = OnCallHealthClient()

            # 1. Get OCH analysis (by ID or latest)
            try:
                if och_analysis_id:
                    analysis = await och_client.get_analysis(och_analysis_id)
                else:
                    analysis = await och_client.get_latest_analysis()
                    och_analysis_id = analysis.get("id")
            except httpx.HTTPStatusError as e:
                raise ConnectionError(f"Failed to fetch On-Call Health data: {e}")
            except ValueError as e:
                raise ValueError(str(e))

            # 2. Extract at-risk and safe users
            at_risk_users, safe_users = och_client.extract_at_risk_users(
                analysis, threshold=och_threshold
            )

            if not at_risk_users:
                return {
                    "period": {"start": start_date, "end": end_date},
                    "och_analysis_id": och_analysis_id,
                    "och_threshold": och_threshold,
                    "at_risk_scheduled": [],
                    "at_risk_not_scheduled": [],
                    "recommended_replacements": [],
                    "summary": {
                        "total_at_risk": 0,
                        "at_risk_scheduled": 0,
                        "action_required": False,
                        "message": "No users above health risk threshold.",
                    },
                }

            # 3. Get shifts for the period
            all_shifts = []
            users_map = {}
            schedules_map = {}

            # Fetch lookup maps
            lookup_users, lookup_schedules, lookup_teams = await _fetch_users_and_schedules_maps()
            users_map.update({str(k): v for k, v in lookup_users.items()})
            schedules_map.update({str(k): v for k, v in lookup_schedules.items()})

            # Fetch shifts
            page = 1
            while page <= 10:
                shifts_response = await make_authenticated_request(
                    "GET",
                    "/v1/shifts",
                    params={
                        "filter[starts_at_lte]": (
                            end_date if "T" in end_date else f"{end_date}T23:59:59Z"
                        ),
                        "filter[ends_at_gte]": (
                            start_date if "T" in start_date else f"{start_date}T00:00:00Z"
                        ),
                        "page[size]": 100,
                        "page[number]": page,
                        "include": "user,schedule",
                    },
                )
                if shifts_response is None:
                    break
                shifts_response.raise_for_status()
                shifts_data = shifts_response.json()

                shifts = shifts_data.get("data", [])
                included = shifts_data.get("included", [])

                for resource in included:
                    if resource.get("type") == "users":
                        users_map[str(resource.get("id"))] = resource
                    elif resource.get("type") == "schedules":
                        schedules_map[str(resource.get("id"))] = resource

                if not shifts:
                    break

                all_shifts.extend(shifts)

                meta = shifts_data.get("meta", {})
                total_pages = meta.get("total_pages", 1)
                if page >= total_pages:
                    break
                page += 1

            # 5. Correlate: which at-risk users are scheduled?
            at_risk_scheduled = []
            at_risk_not_scheduled = []

            for user in at_risk_users:
                rootly_id = user.get("rootly_user_id")
                if not rootly_id:
                    continue

                rootly_id_str = str(rootly_id)

                # Find shifts for this user
                user_shifts = []
                for shift in all_shifts:
                    relationships = shift.get("relationships", {})
                    user_rel = relationships.get("user", {}).get("data") or {}
                    shift_user_id = str(user_rel.get("id", ""))

                    if shift_user_id == rootly_id_str:
                        attrs = shift.get("attributes", {})
                        schedule_rel = relationships.get("schedule", {}).get("data") or {}
                        schedule_id = str(schedule_rel.get("id", ""))
                        schedule_info = schedules_map.get(schedule_id, {})
                        schedule_name = schedule_info.get("attributes", {}).get("name", "Unknown")

                        starts_at = attrs.get("starts_at")
                        ends_at = attrs.get("ends_at")
                        hours = 0.0
                        if starts_at and ends_at:
                            try:
                                start_dt = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                                end_dt = datetime.fromisoformat(ends_at.replace("Z", "+00:00"))
                                hours = (end_dt - start_dt).total_seconds() / 3600
                            except (ValueError, AttributeError):
                                pass

                        user_shifts.append(
                            {
                                "schedule_id": schedule_id,
                                "schedule_name": schedule_name,
                                "starts_at": starts_at,
                                "ends_at": ends_at,
                                "hours": round(hours, 1),
                            }
                        )

                if user_shifts:
                    total_hours = sum(s["hours"] for s in user_shifts)
                    at_risk_scheduled.append(
                        {
                            "user_name": user["user_name"],
                            "user_id": int(rootly_id),
                            "och_score": user["och_score"],
                            "risk_level": user["risk_level"],
                            "health_risk_score": user["health_risk_score"],
                            "total_hours": round(total_hours, 1),
                            "shifts": user_shifts,
                        }
                    )
                else:
                    at_risk_not_scheduled.append(
                        {
                            "user_name": user["user_name"],
                            "user_id": int(rootly_id) if rootly_id else None,
                            "och_score": user["och_score"],
                            "risk_level": user["risk_level"],
                        }
                    )

            # 6. Get recommended replacements (if requested)
            recommended_replacements = []
            if include_replacements and safe_users:
                safe_rootly_ids = [
                    str(u["rootly_user_id"]) for u in safe_users[:10] if u.get("rootly_user_id")
                ]

                if safe_rootly_ids:
                    # Calculate current hours for safe users
                    for user in safe_users[:5]:
                        rootly_id = user.get("rootly_user_id")
                        if not rootly_id:
                            continue

                        rootly_id_str = str(rootly_id)
                        user_hours = 0.0

                        for shift in all_shifts:
                            relationships = shift.get("relationships", {})
                            user_rel = relationships.get("user", {}).get("data") or {}
                            shift_user_id = str(user_rel.get("id", ""))

                            if shift_user_id == rootly_id_str:
                                attrs = shift.get("attributes", {})
                                starts_at = attrs.get("starts_at")
                                ends_at = attrs.get("ends_at")
                                if starts_at and ends_at:
                                    try:
                                        start_dt = datetime.fromisoformat(
                                            starts_at.replace("Z", "+00:00")
                                        )
                                        end_dt = datetime.fromisoformat(
                                            ends_at.replace("Z", "+00:00")
                                        )
                                        user_hours += (end_dt - start_dt).total_seconds() / 3600
                                    except (ValueError, AttributeError):
                                        pass

                        recommended_replacements.append(
                            {
                                "user_name": user["user_name"],
                                "user_id": int(rootly_id),
                                "och_score": user["och_score"],
                                "risk_level": user["risk_level"],
                                "current_hours_in_period": round(user_hours, 1),
                            }
                        )

            # 7. Build summary
            total_scheduled_hours = sum(u["total_hours"] for u in at_risk_scheduled)
            action_required = len(at_risk_scheduled) > 0

            if action_required:
                message = (
                    f"{len(at_risk_scheduled)} at-risk user(s) scheduled for "
                    f"{total_scheduled_hours} hours. Consider reassignment."
                )
            else:
                message = "No at-risk users are scheduled for the period."

            return {
                "period": {"start": start_date, "end": end_date},
                "och_analysis_id": och_analysis_id,
                "och_threshold": och_threshold,
                "at_risk_scheduled": at_risk_scheduled,
                "at_risk_not_scheduled": at_risk_not_scheduled,
                "recommended_replacements": recommended_replacements,
                "summary": {
                    "total_at_risk": len(at_risk_users),
                    "at_risk_scheduled": len(at_risk_scheduled),
                    "action_required": action_required,
                    "message": message,
                },
            }

        except PermissionError as e:
            return MCPError.tool_error(str(e), "permission_error")
        except ConnectionError as e:
            return MCPError.tool_error(str(e), "connection_error")
        except ValueError as e:
            return MCPError.tool_error(str(e), "validation_error")
        except Exception as e:
            import traceback

            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(
                f"Failed to check health risk: {error_message}",
                error_type,
                details={
                    "params": {
                        "start_date": start_date,
                        "end_date": end_date,
                        "och_analysis_id": och_analysis_id,
                    },
                    "exception_type": type(e).__name__,
                    "traceback": traceback.format_exc(),
                },
            )

    @mcp.tool()
    async def get_alert_by_short_id(
        short_id: Annotated[
            str,
            Field(
                description="The alert short_id (e.g., 'PhIQtP') or full alert URL (e.g., 'https://rootly.com/account/alerts/PhIQtP')"
            ),
        ],
    ) -> dict:
        """Get alert details by short_id or alert URL. Use this when a user pastes an alert URL or short_id from a pager notification and wants to investigate the alert."""
        try:
            # Parse short_id from URL if a full URL is provided
            alert_short_id = short_id.strip()
            if "/" in alert_short_id:
                alert_short_id = alert_short_id.rstrip("/").split("/")[-1]

            if not alert_short_id:
                return MCPError.tool_error("short_id is required", "validation_error")

            # Paginate through alerts looking for a matching short_id
            page = 1
            while page <= 20:
                response = await make_authenticated_request(
                    "GET",
                    "/v1/alerts",
                    params={
                        "page[number]": page,
                        "page[size]": 100,
                        "fields[alerts]": "id,summary,status,started_at,ended_at,short_id,source,description,noise,alert_urgency_id,url,created_at",
                    },
                )
                response.raise_for_status()
                data = response.json()
                alerts = data.get("data", [])

                if not alerts:
                    break

                for alert in alerts:
                    attrs = alert.get("attributes", {})
                    if attrs.get("short_id") == alert_short_id:
                        return {
                            "id": alert.get("id"),
                            "short_id": attrs.get("short_id"),
                            "summary": attrs.get("summary"),
                            "status": attrs.get("status"),
                            "source": attrs.get("source"),
                            "description": attrs.get("description"),
                            "started_at": attrs.get("started_at"),
                            "ended_at": attrs.get("ended_at"),
                            "noise": attrs.get("noise"),
                            "url": attrs.get("url"),
                            "created_at": attrs.get("created_at"),
                        }

                meta = data.get("meta", {})
                total_pages = meta.get("total_pages", 1)
                if page >= total_pages:
                    break
                page += 1

            return MCPError.tool_error(
                f"Alert with short_id '{alert_short_id}' not found",
                "not_found",
            )

        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(
                f"Failed to get alert by short_id: {error_message}", error_type
            )

    # Log server creation (tool count will be shown when tools are accessed)
    logger.info("Created Rootly MCP Server successfully")
    return mcp


def _load_swagger_spec(swagger_path: str | None = None) -> dict[str, Any]:
    """
    Load the Swagger specification from a file or URL.

    Args:
        swagger_path: Path to the Swagger JSON file. If None, will fetch from URL.

    Returns:
        The Swagger specification as a dictionary.
    """
    if swagger_path:
        # Use the provided path
        logger.info(f"Using provided Swagger path: {swagger_path}")
        if not os.path.isfile(swagger_path):
            raise FileNotFoundError(f"Swagger file not found at {swagger_path}")
        with open(swagger_path, encoding="utf-8") as f:
            return json.load(f)
    else:
        # First, check in the package data directory
        try:
            package_data_path = Path(__file__).parent / "data" / "swagger.json"
            if package_data_path.is_file():
                logger.info(f"Found Swagger file in package data: {package_data_path}")
                with open(package_data_path, encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.debug(f"Could not load Swagger file from package data: {e}")

        # Then, look for swagger.json in the current directory and parent directories
        logger.info("Looking for swagger.json in current directory and parent directories")
        current_dir = Path.cwd()

        # Check current directory first
        local_swagger_path = current_dir / "swagger.json"
        if local_swagger_path.is_file():
            logger.info(f"Found Swagger file at {local_swagger_path}")
            with open(local_swagger_path, encoding="utf-8") as f:
                return json.load(f)

        # Check parent directories
        for parent in current_dir.parents:
            parent_swagger_path = parent / "swagger.json"
            if parent_swagger_path.is_file():
                logger.info(f"Found Swagger file at {parent_swagger_path}")
                with open(parent_swagger_path, encoding="utf-8") as f:
                    return json.load(f)

        # If the file wasn't found, fetch it from the URL and save it
        logger.info("Swagger file not found locally, fetching from URL")
        swagger_spec = _fetch_swagger_from_url()

        # Save the fetched spec to the current directory
        save_swagger_path = current_dir / "swagger.json"
        logger.info(f"Saving Swagger file to {save_swagger_path}")
        try:
            with open(save_swagger_path, "w", encoding="utf-8") as f:
                json.dump(swagger_spec, f)
            logger.info(f"Saved Swagger file to {save_swagger_path}")
        except Exception as e:
            logger.warning(f"Failed to save Swagger file: {e}")

        return swagger_spec


def _fetch_swagger_from_url(url: str = SWAGGER_URL) -> dict[str, Any]:
    """
    Fetch the Swagger specification from the specified URL.

    Args:
        url: URL of the Swagger JSON file.

    Returns:
        The Swagger specification as a dictionary.
    """
    logger.info(f"Fetching Swagger specification from {url}")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch Swagger spec: {e}")
        raise Exception(f"Failed to fetch Swagger specification: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Swagger spec: {e}")
        raise Exception(f"Failed to parse Swagger specification: {e}")


def _filter_openapi_spec(spec: dict[str, Any], allowed_paths: list[str]) -> dict[str, Any]:
    """
    Filter an OpenAPI specification to only include specified paths and clean up schema references.

    Args:
        spec: The original OpenAPI specification.
        allowed_paths: List of paths to include.

    Returns:
        A filtered OpenAPI specification with cleaned schema references.
    """
    # Use deepcopy to ensure all nested structures are properly copied
    filtered_spec = deepcopy(spec)

    # Filter paths
    original_paths = filtered_spec.get("paths", {})
    filtered_paths = {
        path: path_item for path, path_item in original_paths.items() if path in allowed_paths
    }

    filtered_spec["paths"] = filtered_paths

    # Clean up schema references that might be broken
    # Remove problematic schema references from request bodies and parameters
    for path, path_item in filtered_paths.items():
        for method, operation in path_item.items():
            if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                continue

            # Clean request body schemas
            if "requestBody" in operation:
                request_body = operation["requestBody"]
                if "content" in request_body:
                    for _content_type, content_info in request_body["content"].items():
                        if "schema" in content_info:
                            schema = content_info["schema"]
                            # Remove problematic $ref references
                            if "$ref" in schema and "incident_trigger_params" in schema["$ref"]:
                                # Replace with a generic object schema
                                content_info["schema"] = {
                                    "type": "object",
                                    "description": "Request parameters for this endpoint",
                                    "additionalProperties": True,
                                }

            # Remove response schemas to avoid validation issues
            # FastMCP will still return the data, just without strict validation
            if "responses" in operation:
                for _status_code, response in operation["responses"].items():
                    if "content" in response:
                        for _content_type, content_info in response["content"].items():
                            if "schema" in content_info:
                                # Replace with a simple schema that accepts any response
                                content_info["schema"] = {
                                    "type": "object",
                                    "additionalProperties": True,
                                }

            # Clean parameter schemas (parameter names are already sanitized)
            if "parameters" in operation:
                for param in operation["parameters"]:
                    if "schema" in param and "$ref" in param["schema"]:
                        ref_path = param["schema"]["$ref"]
                        if "incident_trigger_params" in ref_path:
                            # Replace with a simple string schema
                            param["schema"] = {
                                "type": "string",
                                "description": param.get("description", "Parameter value"),
                            }

            # Add/modify pagination limits to alerts and incident-related endpoints to prevent infinite loops
            if method.lower() == "get" and ("alerts" in path.lower() or "incident" in path.lower()):
                if "parameters" not in operation:
                    operation["parameters"] = []

                # Find existing pagination parameters and update them with limits
                page_size_param = None
                page_number_param = None

                for param in operation["parameters"]:
                    if param.get("name") == "page[size]":
                        page_size_param = param
                    elif param.get("name") == "page[number]":
                        page_number_param = param

                # Update or add page[size] parameter with limits
                if page_size_param:
                    # Update existing parameter with limits
                    if "schema" not in page_size_param:
                        page_size_param["schema"] = {}
                    page_size_param["schema"].update(
                        {
                            "type": "integer",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 20,
                            "description": "Number of results per page (max: 20)",
                        }
                    )
                else:
                    # Add new parameter
                    operation["parameters"].append(
                        {
                            "name": "page[size]",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "integer",
                                "default": 10,
                                "minimum": 1,
                                "maximum": 20,
                                "description": "Number of results per page (max: 20)",
                            },
                        }
                    )

                # Update or add page[number] parameter with defaults
                if page_number_param:
                    # Update existing parameter
                    if "schema" not in page_number_param:
                        page_number_param["schema"] = {}
                    page_number_param["schema"].update(
                        {
                            "type": "integer",
                            "default": 1,
                            "minimum": 1,
                            "description": "Page number to retrieve",
                        }
                    )
                else:
                    # Add new parameter
                    operation["parameters"].append(
                        {
                            "name": "page[number]",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "integer",
                                "default": 1,
                                "minimum": 1,
                                "description": "Page number to retrieve",
                            },
                        }
                    )

                # Add sparse fieldsets for alerts endpoints to reduce payload size
                if "alert" in path.lower():
                    # Add fields[alerts] parameter with essential fields only - make it required with default
                    operation["parameters"].append(
                        {
                            "name": "fields[alerts]",
                            "in": "query",
                            "required": True,
                            "schema": {
                                "type": "string",
                                "default": "id,summary,status,started_at,ended_at,short_id,alert_urgency_id,source,noise",
                                "description": "Comma-separated list of alert fields to include (reduces payload size)",
                            },
                        }
                    )

                # Add include parameter for alerts endpoints to minimize relationships
                if "alert" in path.lower():
                    # Check if include parameter already exists
                    include_param_exists = any(
                        param.get("name") == "include" for param in operation["parameters"]
                    )
                    if not include_param_exists:
                        operation["parameters"].append(
                            {
                                "name": "include",
                                "in": "query",
                                "required": True,
                                "schema": {
                                    "type": "string",
                                    "default": "",
                                    "description": "Related resources to include (empty for minimal payload)",
                                },
                            }
                        )

                # Add filter parameters for alerts endpoints to enable team/date/source filtering
                if "alert" in path.lower():
                    filter_params = [
                        {
                            "name": "filter[status]",
                            "description": "Filter by alert status (e.g., triggered, acknowledged, resolved)",
                        },
                        {
                            "name": "filter[groups]",
                            "description": "Filter by team/group IDs (comma-separated)",
                        },
                        {
                            "name": "filter[services]",
                            "description": "Filter by service IDs (comma-separated)",
                        },
                        {
                            "name": "filter[environments]",
                            "description": "Filter by environment IDs (comma-separated)",
                        },
                        {
                            "name": "filter[labels]",
                            "description": "Filter by labels (comma-separated)",
                        },
                        {"name": "filter[source]", "description": "Filter by alert source"},
                        {
                            "name": "filter[started_at][gte]",
                            "description": "Started at >= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[started_at][lte]",
                            "description": "Started at <= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[started_at][gt]",
                            "description": "Started at > (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[started_at][lt]",
                            "description": "Started at < (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[ended_at][gte]",
                            "description": "Ended at >= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[ended_at][lte]",
                            "description": "Ended at <= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[ended_at][gt]",
                            "description": "Ended at > (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[ended_at][lt]",
                            "description": "Ended at < (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[created_at][gte]",
                            "description": "Created at >= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[created_at][lte]",
                            "description": "Created at <= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[created_at][gt]",
                            "description": "Created at > (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[created_at][lt]",
                            "description": "Created at < (ISO8601 datetime)",
                        },
                    ]

                    for param_def in filter_params:
                        # Check if param already exists
                        param_exists = any(
                            p.get("name") == param_def["name"] for p in operation["parameters"]
                        )
                        if not param_exists:
                            operation["parameters"].append(
                                {
                                    "name": param_def["name"],
                                    "in": "query",
                                    "required": False,
                                    "schema": {
                                        "type": "string",
                                        "description": param_def["description"],
                                    },
                                }
                            )

                # Add sparse fieldsets for incidents endpoints to reduce payload size
                if "incident" in path.lower():
                    # Add fields[incidents] parameter with essential fields only - make it required with default
                    operation["parameters"].append(
                        {
                            "name": "fields[incidents]",
                            "in": "query",
                            "required": True,
                            "schema": {
                                "type": "string",
                                "default": "id,title,summary,status,severity,created_at,updated_at,url,started_at",
                                "description": "Comma-separated list of incident fields to include (reduces payload size)",
                            },
                        }
                    )

                # Add include parameter for incidents endpoints to minimize relationships
                if "incident" in path.lower():
                    # Check if include parameter already exists
                    include_param_exists = any(
                        param.get("name") == "include" for param in operation["parameters"]
                    )
                    if not include_param_exists:
                        operation["parameters"].append(
                            {
                                "name": "include",
                                "in": "query",
                                "required": True,
                                "schema": {
                                    "type": "string",
                                    "default": "",
                                    "description": "Related resources to include (empty for minimal payload)",
                                },
                            }
                        )

    # Also clean up any remaining broken references in components
    if "components" in filtered_spec and "schemas" in filtered_spec["components"]:
        schemas = filtered_spec["components"]["schemas"]
        # Remove or fix any schemas that reference missing components
        schemas_to_remove = []
        for schema_name, schema_def in schemas.items():
            if isinstance(schema_def, dict) and _has_broken_references(schema_def):
                schemas_to_remove.append(schema_name)

        for schema_name in schemas_to_remove:
            logger.warning(f"Removing schema with broken references: {schema_name}")
            del schemas[schema_name]

    # Clean up any operation-level references to removed schemas
    removed_schemas = set()
    if "components" in filtered_spec and "schemas" in filtered_spec["components"]:
        removed_schemas = {
            "new_workflow",
            "update_workflow",
            "workflow",
            "workflow_task",
            "workflow_response",
            "workflow_list",
            "new_workflow_task",
            "update_workflow_task",
            "workflow_task_response",
            "workflow_task_list",
        }

    for path, path_item in filtered_spec.get("paths", {}).items():
        for method, operation in path_item.items():
            if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                continue

            # Clean request body references
            if "requestBody" in operation:
                request_body = operation["requestBody"]
                if "content" in request_body:
                    for _content_type, content_info in request_body["content"].items():
                        if "schema" in content_info and "$ref" in content_info["schema"]:
                            ref_path = content_info["schema"]["$ref"]
                            schema_name = ref_path.split("/")[-1]
                            if schema_name in removed_schemas:
                                # Replace with generic object schema
                                content_info["schema"] = {
                                    "type": "object",
                                    "description": "Request data for this endpoint",
                                    "additionalProperties": True,
                                }
                                logger.debug(
                                    f"Cleaned broken reference in {method.upper()} {path} request body: {ref_path}"
                                )

            # Clean response references
            if "responses" in operation:
                for _status_code, response in operation["responses"].items():
                    if "content" in response:
                        for _content_type, content_info in response["content"].items():
                            if "schema" in content_info and "$ref" in content_info["schema"]:
                                ref_path = content_info["schema"]["$ref"]
                                schema_name = ref_path.split("/")[-1]
                                if schema_name in removed_schemas:
                                    # Replace with generic object schema
                                    content_info["schema"] = {
                                        "type": "object",
                                        "description": "Response data from this endpoint",
                                        "additionalProperties": True,
                                    }
                                    logger.debug(
                                        f"Cleaned broken reference in {method.upper()} {path} response: {ref_path}"
                                    )

    return filtered_spec


def _has_broken_references(schema_def: dict[str, Any]) -> bool:
    """Check if a schema definition has broken references."""
    if "$ref" in schema_def:
        ref_path = schema_def["$ref"]
        # List of known broken references in the Rootly API spec
        broken_refs = [
            "incident_trigger_params",
            "new_workflow",
            "update_workflow",
            "workflow",
            "new_workflow_task",
            "update_workflow_task",
            "workflow_task",
            "workflow_task_response",
            "workflow_task_list",
            "workflow_response",
            "workflow_list",
            "workflow_custom_field_selection_response",
            "workflow_custom_field_selection_list",
            "workflow_form_field_condition_response",
            "workflow_form_field_condition_list",
            "workflow_group_response",
            "workflow_group_list",
            "workflow_run_response",
            "workflow_runs_list",
        ]
        if any(broken_ref in ref_path for broken_ref in broken_refs):
            return True

    # Recursively check nested schemas
    for _key, value in schema_def.items():
        if isinstance(value, dict):
            if _has_broken_references(value):
                return True
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and _has_broken_references(item):
                    return True

    return False


# Legacy class for backward compatibility
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
        logger.warning(
            "RootlyMCPServer class is deprecated. Use create_rootly_mcp_server() function instead."
        )

        # Create the server using the new function
        server = create_rootly_mcp_server(
            swagger_path=swagger_path, name=name, allowed_paths=allowed_paths, hosted=hosted
        )

        # Copy the server's state to this instance
        super().__init__(name, *args, **kwargs)
        # For compatibility, store reference to the new server
        # Tools will be accessed via async methods when needed
        self._server = server
        self._tools = {}  # Placeholder - tools should be accessed via async methods
        self._resources = getattr(server, "_resources", {})
        self._prompts = getattr(server, "_prompts", {})
