"""MCP resource registration for Rootly MCP server."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol

JsonDict = dict[str, Any]
MakeAuthenticatedRequest = Callable[..., Awaitable[Any]]
StripHeavyNestedData = Callable[[JsonDict], JsonDict]


class MCPErrorLike(Protocol):
    """Protocol for MCP error categorization used by resource handlers."""

    @staticmethod
    def categorize_error(exception: Exception) -> tuple[str, str]: ...


def register_resource_handlers(
    mcp: Any,
    make_authenticated_request: MakeAuthenticatedRequest,
    strip_heavy_nested_data: StripHeavyNestedData,
    mcp_error: MCPErrorLike,
) -> None:
    """Register MCP resources for incidents and teams."""

    @mcp.resource("incident://{incident_id}")
    async def get_incident_resource(incident_id: str) -> JsonDict:
        """Expose incident details as an MCP resource for easy reference and context."""
        try:
            response = await make_authenticated_request("GET", f"/v1/incidents/{incident_id}")
            response.raise_for_status()
            incident_data = strip_heavy_nested_data({"data": [response.json().get("data", {})]})

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
            error_type, error_message = mcp_error.categorize_error(e)
            return {
                "uri": f"incident://{incident_id}",
                "name": f"Incident #{incident_id} (Error)",
                "text": f"Error ({error_type}): {error_message}",
                "mimeType": "text/plain",
            }

    @mcp.resource("team://{team_id}")
    async def get_team_resource(team_id: str) -> JsonDict:
        """Expose team details as an MCP resource for easy reference and context."""
        try:
            response = await make_authenticated_request("GET", f"/v1/teams/{team_id}")
            response.raise_for_status()
            team_data = response.json()

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
            error_type, error_message = mcp_error.categorize_error(e)
            return {
                "uri": f"team://{team_id}",
                "name": f"Team #{team_id} (Error)",
                "text": f"Error ({error_type}): {error_message}",
                "mimeType": "text/plain",
            }

    @mcp.resource("rootly://incidents")
    async def list_incidents_resource() -> JsonDict:
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
            error_type, error_message = mcp_error.categorize_error(e)
            return {
                "uri": "rootly://incidents",
                "name": "Recent Incidents (Error)",
                "text": f"Error ({error_type}): {error_message}",
                "mimeType": "text/plain",
            }
