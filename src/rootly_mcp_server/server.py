"""
Rootly MCP Server - A Model Context Protocol server for Rootly API integration.

This module implements a server that dynamically generates MCP tools based on
the Rootly API's OpenAPI (Swagger) specification using FastMCP's OpenAPI integration.
"""

import json
import os
import logging
from copy import deepcopy
from pathlib import Path
import requests
import httpx
from typing import Any, Dict, List, Optional, Annotated

from fastmcp import FastMCP

from pydantic import Field

from .utils import sanitize_parameters_in_spec
from .smart_utils import TextSimilarityAnalyzer, SolutionExtractor

# Set up logger
logger = logging.getLogger(__name__)


class MCPError:
    """Enhanced error handling for MCP protocol compliance."""
    
    @staticmethod
    def protocol_error(code: int, message: str, data: Optional[Dict] = None):
        """Create a JSON-RPC protocol-level error response."""
        error_response = {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message
            }
        }
        if data:
            error_response["error"]["data"] = data
        return error_response
    
    @staticmethod
    def tool_error(error_message: str, error_type: str = "execution_error", details: Optional[Dict] = None):
        """Create a tool-level error response (returned as successful tool result)."""
        error_response = {
            "error": True,
            "error_type": error_type,
            "message": error_message
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
        if any(keyword in error_str.lower() for keyword in ["401", "unauthorized", "authentication", "token", "forbidden"]):
            return "authentication_error", f"Authentication failed: {error_str}"
        
        # Network/Connection errors  
        if any(keyword in exception_type.lower() for keyword in ["connection", "timeout", "network"]):
            return "network_error", f"Network error: {error_str}"
        
        # HTTP errors
        if "40" in error_str[:10]:  # 4xx client errors
            return "client_error", f"Client error: {error_str}"
        elif "50" in error_str[:10]:  # 5xx server errors
            return "server_error", f"Server error: {error_str}"
        
        # Validation errors
        if any(keyword in exception_type.lower() for keyword in ["validation", "pydantic", "field"]):
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
            recommendation_parts.append("Similar incidents typically require more time (> 4 hours).")
    
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
    
    return " ".join(recommendation_parts) if recommendation_parts else "Review similar incidents above for resolution guidance."


# Default allowed API paths
DEFAULT_ALLOWED_PATHS = [
    "/incidents/{incident_id}/alerts",
    "/alerts",
    "/alerts/{alert_id}",
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

    def __init__(self, base_url: str = "https://api.rootly.com", hosted: bool = False, parameter_mapping: Optional[Dict[str, str]] = None):
        self._base_url = base_url
        self.hosted = hosted
        self._api_token = None
        self.parameter_mapping = parameter_mapping or {}

        if not self.hosted:
            self._api_token = self._get_api_token()

        # Create the HTTPX client  
        headers = {
            "Content-Type": "application/vnd.api+json", 
            "Accept": "application/vnd.api+json"
            # Let httpx handle Accept-Encoding automatically with all supported formats
        }
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"

        self.client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=30.0,
            follow_redirects=True,
            # Ensure proper handling of compressed responses
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )

    def _get_api_token(self) -> Optional[str]:
        """Get the API token from environment variables."""
        api_token = os.getenv("ROOTLY_API_TOKEN")
        if not api_token:
            logger.warning("ROOTLY_API_TOKEN environment variable is not set")
            return None
        return api_token

    def _transform_params(self, params: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
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
        """Override request to transform parameters."""
        # Transform query parameters
        if 'params' in kwargs:
            kwargs['params'] = self._transform_params(kwargs['params'])

        # Call the underlying client's request method and let it handle everything
        return await self.client.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs):
        """Proxy to request with GET method."""
        return await self.request('GET', url, **kwargs)

    async def post(self, url: str, **kwargs):
        """Proxy to request with POST method."""
        return await self.request('POST', url, **kwargs)

    async def put(self, url: str, **kwargs):
        """Proxy to request with PUT method."""
        return await self.request('PUT', url, **kwargs)

    async def patch(self, url: str, **kwargs):
        """Proxy to request with PATCH method."""
        return await self.request('PATCH', url, **kwargs)

    async def delete(self, url: str, **kwargs):
        """Proxy to request with DELETE method."""
        return await self.request('DELETE', url, **kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    def __getattr__(self, name):
        # Delegate all other attributes to the underlying client, except for request methods
        if name in ['request', 'get', 'post', 'put', 'patch', 'delete']:
            # Use our overridden methods instead
            return getattr(self, name)
        return getattr(self.client, name)
    
    @property 
    def base_url(self):
        return self._base_url
        
    @property
    def headers(self):
        return self.client.headers


def create_rootly_mcp_server(
    swagger_path: Optional[str] = None,
    name: str = "Rootly",
    allowed_paths: Optional[List[str]] = None,
    hosted: bool = False,
    base_url: Optional[str] = None,
) -> FastMCP:
    """
    Create a Rootly MCP Server using FastMCP's OpenAPI integration.

    Args:
        swagger_path: Path to the Swagger JSON file. If None, will fetch from URL.
        name: Name of the MCP server.
        allowed_paths: List of API paths to include. If None, includes default paths.
        hosted: Whether the server is hosted (affects authentication).
        base_url: Base URL for Rootly API. If None, uses ROOTLY_BASE_URL env var or default.

    Returns:
        A FastMCP server instance.
    """
    # Set default allowed paths if none provided
    if allowed_paths is None:
        allowed_paths = DEFAULT_ALLOWED_PATHS

    # Add /v1 prefix to paths if not present
    allowed_paths_v1 = [
        f"/v1{path}" if not path.startswith("/v1") else path
        for path in allowed_paths
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
    logger.info(f"Sanitized parameter names for MCP compatibility (mapped {len(parameter_mapping)} parameters)")

    # Determine the base URL
    if base_url is None:
        base_url = os.getenv("ROOTLY_BASE_URL", "https://api.rootly.com")

    logger.info(f"Using Rootly API base URL: {base_url}")

    # Create the authenticated HTTP client with parameter mapping

    http_client = AuthenticatedHTTPXClient(
        base_url=base_url,
        hosted=hosted,
        parameter_mapping=parameter_mapping
    )

    # Create the MCP server using OpenAPI integration
    # By default, all routes become tools which is what we want
    mcp = FastMCP.from_openapi(
        openapi_spec=filtered_spec,
        client=http_client.client,
        name=name,
        timeout=30.0,
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

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": summary,
                    "description": description,
                })

        return endpoints

    async def make_authenticated_request(method: str, url: str, **kwargs):
        """Make an authenticated request, extracting token from MCP headers in hosted mode."""
        # In hosted mode, get token from MCP request headers
        if hosted:
            try:
                from fastmcp.server.dependencies import get_http_headers
                request_headers = get_http_headers()
                auth_header = request_headers.get("authorization", "")
                if auth_header:
                    # Add authorization header to the request
                    if "headers" not in kwargs:
                        kwargs["headers"] = {}
                    kwargs["headers"]["Authorization"] = auth_header
            except Exception:
                pass  # Fallback to default client behavior
        
        # Use our custom client with proper error handling instead of bypassing it
        return await http_client.request(method, url, **kwargs)

    @mcp.tool()
    async def search_incidents(
        query: Annotated[str, Field(description="Search query to filter incidents by title/summary")] = "",
        page_size: Annotated[int, Field(description="Number of results per page (max: 20)", ge=1, le=20)] = 10,
        page_number: Annotated[int, Field(description="Page number to retrieve (use 0 for all pages)", ge=0)] = 1,
        max_results: Annotated[int, Field(description="Maximum total results when fetching all pages (ignored if page_number > 0)", ge=1, le=10)] = 5,
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
                "fields[incidents]": "id,title,summary,status,severity,created_at,updated_at,url,started_at",
            }
            if query:
                params["filter[search]"] = query

            try:
                response = await make_authenticated_request("GET", "/v1/incidents", params=params)
                response.raise_for_status()
                return response.json()
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
                    "fields[incidents]": "id,title,summary,status,severity,created_at,updated_at,url,started_at",
                }
                if query:
                    params["filter[search]"] = query

                try:
                    response = await make_authenticated_request("GET", "/v1/incidents", params=params)
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
                    if "401" in str(e) or "Unauthorized" in str(e) or "authentication" in str(e).lower():
                        error_type, error_message = MCPError.categorize_error(e)
                        return MCPError.tool_error(error_message, error_type)
                    # For other errors, break loop and return partial results
                    break

            # Limit to max_results
            if len(all_incidents) > max_results:
                all_incidents = all_incidents[:max_results]

            return {
                "data": all_incidents,
                "meta": {
                    "total_fetched": len(all_incidents),
                    "max_results": max_results,
                    "query": query,
                    "pages_fetched": current_page - 1,
                    "page_size": effective_page_size
                }
            }
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
        similarity_threshold: Annotated[float, Field(description="Minimum similarity score (0.0-1.0)", ge=0.0, le=1.0)] = 0.15,
        max_results: Annotated[int, Field(description="Maximum number of related incidents to return", ge=1, le=20)] = 5,
        status_filter: Annotated[str, Field(description="Filter incidents by status (empty for all, 'resolved', 'investigating', etc.)")] = ""
    ) -> dict:
        """Find similar incidents to help with context and resolution strategies. Provide either incident_id OR incident_description (e.g., 'website is down', 'database timeout errors'). Use status_filter to limit to specific incident statuses or leave empty for all incidents."""
        try:
            target_incident = {}
            
            if incident_id:
                # Get the target incident details by ID
                target_response = await make_authenticated_request("GET", f"/v1/incidents/{incident_id}")
                target_response.raise_for_status()
                target_incident_data = target_response.json()
                target_incident = target_incident_data.get("data", {})
                
                if not target_incident:
                    return MCPError.tool_error("Incident not found", "not_found")
                    
            elif incident_description:
                # Create synthetic incident for analysis from descriptive text
                target_incident = {
                    "id": "synthetic",
                    "attributes": {
                        "title": incident_description,
                        "summary": incident_description,
                        "description": incident_description
                    }
                }
            else:
                return MCPError.tool_error("Must provide either incident_id or incident_description", "validation_error")
            
            # Get historical incidents for comparison
            params = {
                "page[size]": 100,  # Get more incidents for better matching
                "page[number]": 1,
                "include": ""
            }
            
            # Only add status filter if specified
            if status_filter:
                params["filter[status]"] = status_filter
                
            historical_response = await make_authenticated_request("GET", "/v1/incidents", params=params)
            historical_response.raise_for_status()
            historical_data = historical_response.json()
            historical_incidents = historical_data.get("data", [])
            
            # Filter out the target incident itself if it exists
            if incident_id:
                historical_incidents = [inc for inc in historical_incidents if str(inc.get('id')) != str(incident_id)]
            
            if not historical_incidents:
                return {
                    "related_incidents": [],
                    "message": "No historical incidents found for comparison",
                    "target_incident": {
                        "id": incident_id or "synthetic",
                        "title": target_incident.get("attributes", {}).get("title", incident_description)
                    }
                }
            
            # Calculate similarities
            similar_incidents = similarity_analyzer.calculate_similarity(historical_incidents, target_incident)
            
            # Filter by threshold and limit results
            filtered_incidents = [
                inc for inc in similar_incidents 
                if inc.similarity_score >= similarity_threshold
            ][:max_results]
            
            # Format response
            related_incidents = []
            for incident in filtered_incidents:
                related_incidents.append({
                    "incident_id": incident.incident_id,
                    "title": incident.title,
                    "similarity_score": round(incident.similarity_score, 3),
                    "matched_services": incident.matched_services,
                    "matched_keywords": incident.matched_keywords,
                    "resolution_summary": incident.resolution_summary,
                    "resolution_time_hours": incident.resolution_time_hours
                })
            
            return {
                "target_incident": {
                    "id": incident_id or "synthetic",
                    "title": target_incident.get("attributes", {}).get("title", incident_description)
                },
                "related_incidents": related_incidents,
                "total_found": len(filtered_incidents),
                "similarity_threshold": similarity_threshold,
                "analysis_summary": f"Found {len(filtered_incidents)} similar incidents out of {len(historical_incidents)} historical incidents"
            }
            
        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(f"Failed to find related incidents: {error_message}", error_type)

    @mcp.tool()
    async def suggest_solutions(
        incident_id: str = "",
        incident_title: str = "",
        incident_description: str = "",
        max_solutions: Annotated[int, Field(description="Maximum number of solution suggestions", ge=1, le=10)] = 3,
        status_filter: Annotated[str, Field(description="Filter incidents by status (default 'resolved', empty for all, 'investigating', etc.)")] = "resolved"
    ) -> dict:
        """Suggest solutions based on similar incidents. Provide either incident_id OR title/description. Defaults to resolved incidents for solution mining, but can search all statuses."""
        try:
            target_incident = {}
            
            if incident_id:
                # Get incident details by ID
                response = await make_authenticated_request("GET", f"/v1/incidents/{incident_id}")
                response.raise_for_status()
                incident_data = response.json()
                target_incident = incident_data.get("data", {})
                
                if not target_incident:
                    return MCPError.tool_error("Incident not found", "not_found")
                    
            elif incident_title or incident_description:
                # Create synthetic incident for analysis
                target_incident = {
                    "id": "synthetic",
                    "attributes": {
                        "title": incident_title,
                        "summary": incident_description,
                        "description": incident_description
                    }
                }
            else:
                return MCPError.tool_error("Must provide either incident_id or incident_title/description", "validation_error")
            
            # Get incidents for solution mining
            params = {
                "page[size]": 150,  # Get more incidents for better solution matching
                "page[number]": 1,
                "include": ""
            }
            
            # Only add status filter if specified
            if status_filter:
                params["filter[status]"] = status_filter
                
            historical_response = await make_authenticated_request("GET", "/v1/incidents", params=params)
            historical_response.raise_for_status()
            historical_data = historical_response.json()
            historical_incidents = historical_data.get("data", [])
            
            # Filter out target incident if it exists
            if incident_id:
                historical_incidents = [inc for inc in historical_incidents if str(inc.get('id')) != str(incident_id)]
            
            if not historical_incidents:
                status_msg = f" with status '{status_filter}'" if status_filter else ""
                return {
                    "solutions": [],
                    "message": f"No historical incidents found{status_msg} for solution mining"
                }
            
            # Find similar incidents
            similar_incidents = similarity_analyzer.calculate_similarity(historical_incidents, target_incident)
            
            # Filter to reasonably similar incidents (lower threshold for solution suggestions)
            relevant_incidents = [inc for inc in similar_incidents if inc.similarity_score >= 0.2][:max_solutions * 2]
            
            if not relevant_incidents:
                return {
                    "solutions": [],
                    "message": "No sufficiently similar incidents found for solution suggestions",
                    "suggestion": "This appears to be a unique incident. Consider escalating or consulting documentation."
                }
            
            # Extract solutions
            solution_data = solution_extractor.extract_solutions(relevant_incidents)
            
            # Format response
            return {
                "target_incident": {
                    "id": incident_id or "synthetic",
                    "title": target_incident.get("attributes", {}).get("title", incident_title),
                    "description": target_incident.get("attributes", {}).get("summary", incident_description)
                },
                "solutions": solution_data["solutions"][:max_solutions],
                "insights": {
                    "common_patterns": solution_data["common_patterns"],
                    "average_resolution_time_hours": solution_data["average_resolution_time"],
                    "total_similar_incidents": solution_data["total_similar_incidents"]
                },
                "recommendation": _generate_recommendation(solution_data)
            }
            
        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return MCPError.tool_error(f"Failed to suggest solutions: {error_message}", error_type)

    @mcp.tool()
    async def get_oncall_shift_metrics(
        start_date: Annotated[str, Field(description="Start date for metrics (ISO 8601 format, e.g., '2025-10-01' or '2025-10-01T00:00:00Z')")],
        end_date: Annotated[str, Field(description="End date for metrics (ISO 8601 format, e.g., '2025-10-31' or '2025-10-31T23:59:59Z')")],
        user_ids: Annotated[str, Field(description="Comma-separated list of user IDs to filter by (optional)")] = "",
        schedule_ids: Annotated[str, Field(description="Comma-separated list of schedule IDs to filter by (optional)")] = "",
        team_ids: Annotated[str, Field(description="Comma-separated list of team IDs to filter by (requires querying schedules first)")] = "",
        group_by: Annotated[str, Field(description="Group results by: 'user', 'schedule', 'team', or 'none'")] = "user"
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
            from datetime import datetime, timedelta
            from collections import defaultdict
            from typing import Any, Dict

            # Build query parameters
            params: Dict[str, Any] = {
                "from": start_date,
                "to": end_date,
            }

            # Fetch schedules (schedules don't have team relationship, they have owner_group_ids)
            schedules_response = await make_authenticated_request("GET", "/v1/schedules", params={"page[size]": 100})

            if schedules_response is None:
                return MCPError.tool_error("Failed to get schedules: API request returned None", "execution_error")

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
                teams_response = await make_authenticated_request("GET", "/v1/teams", params={"page[size]": 100})
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
                        "schedule_name": schedule_name
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
                shifts_response = await make_authenticated_request("GET", "/v1/shifts", params=params)

                if shifts_response is None:
                    return MCPError.tool_error("Failed to get shifts: API request returned None", "execution_error")

                shifts_response.raise_for_status()
                shifts_data = shifts_response.json()

                if shifts_data is None:
                    return MCPError.tool_error("Failed to get shifts: API returned null/empty response", "execution_error", details={"status": shifts_response.status_code})

                shifts = shifts_data.get("data", [])
                included = shifts_data.get("included", [])
            except AttributeError as e:
                return MCPError.tool_error(f"Failed to get shifts: Response object error - {str(e)}", "execution_error", details={"params": params})
            except Exception as e:
                return MCPError.tool_error(f"Failed to get shifts: {str(e)}", "execution_error", details={"params": params, "error_type": type(e).__name__})

            # Build lookup maps for included resources
            users_map = {}
            on_call_roles_map = {}
            for resource in included:
                if resource.get("type") == "users":
                    users_map[resource.get("id")] = resource
                elif resource.get("type") == "on_call_roles":
                    on_call_roles_map[resource.get("id")] = resource

            # Calculate metrics
            metrics: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
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
                "shifts": []
            })

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

                metrics[key]["shifts"].append({
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
                    "is_primary": is_primary
                })

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
                "period": {
                    "start_date": start_date,
                    "end_date": end_date
                },
                "total_shifts": len(shifts),
                "grouped_by": group_by,
                "metrics": results,
                "summary": {
                    "total_hours": round(sum(m["total_hours"] for m in results), 2),
                    "total_regular_shifts": sum(m["regular_shifts"] for m in results),
                    "total_override_shifts": sum(m["override_shifts"] for m in results),
                    "unique_people": len(results) if group_by == "user" else None
                }
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
                    "traceback": traceback.format_exc()
                }
            )

    @mcp.tool()
    async def get_oncall_handoff_summary(
        team_ids: Annotated[str, Field(description="Comma-separated list of team IDs to filter schedules (optional)")] = "",
        schedule_ids: Annotated[str, Field(description="Comma-separated list of schedule IDs (optional)")] = "",
        timezone: Annotated[str, Field(description="Timezone to use for display and filtering (e.g., 'America/Los_Angeles', 'Europe/London', 'Asia/Tokyo'). IMPORTANT: If user mentions a city, location, or region (e.g., 'Toronto', 'APAC', 'my time'), infer the appropriate IANA timezone. Defaults to UTC if not specified.")] = "UTC",
        filter_by_region: Annotated[bool, Field(description="If True, only show on-call for people whose shifts are during business hours (9am-5pm) in the specified timezone. Defaults to False.")] = False,
        include_incidents: Annotated[bool, Field(description="If True, fetch incidents for each shift (slower). If False, only show on-call info (faster). Defaults to False for better performance.")] = False
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
                schedules_response = await make_authenticated_request("GET", "/v1/schedules", params={"page[size]": 100, "page[number]": page})
                if not schedules_response:
                    return MCPError.tool_error("Failed to fetch schedules - no response from API", "execution_error")

                if schedules_response.status_code != 200:
                    return MCPError.tool_error(
                        f"Failed to fetch schedules - API returned status {schedules_response.status_code}",
                        "execution_error",
                        details={"status_code": schedules_response.status_code}
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
                teams_response = await make_authenticated_request("GET", "/v1/teams", params={"page[size]": 100})
                if teams_response and teams_response.status_code == 200:
                    teams_data = teams_response.json()
                    for team in teams_data.get("data", []):
                        teams_map[team.get("id")] = team

            # Filter schedules
            target_schedules = []
            team_filter = [tid.strip() for tid in team_ids.split(",") if tid.strip()] if team_ids else []
            schedule_filter = [sid.strip() for sid in schedule_ids.split(",") if sid.strip()] if schedule_ids else []

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
                        "page[size]": 50
                    }
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

                for shift in sorted(shifts, key=lambda s: s.get("attributes", {}).get("starts_at", "")):
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
                    "next_oncall": None
                }

                if current_shift:
                    current_attrs = current_shift.get("attributes", {})
                    current_rels = current_shift.get("relationships", {})
                    user_data = (current_rels.get("user", {}).get("data") or {})
                    user_id = user_data.get("id")
                    role_data = (current_rels.get("on_call_role", {}).get("data") or {})
                    role_id = role_data.get("id")

                    user_name = "Unknown"
                    if user_id and user_id in users_map:
                        user_attrs = users_map[user_id].get("attributes", {})
                        user_name = user_attrs.get("full_name") or user_attrs.get("email", "Unknown")

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
                        "is_override": current_attrs.get("is_override", False)
                    }

                if next_shift:
                    next_attrs = next_shift.get("attributes", {})
                    next_rels = next_shift.get("relationships", {})
                    user_data = (next_rels.get("user", {}).get("data") or {})
                    user_id = user_data.get("id")
                    role_data = (next_rels.get("on_call_role", {}).get("data") or {})
                    role_id = role_data.get("id")

                    user_name = "Unknown"
                    if user_id and user_id in users_map:
                        user_attrs = users_map[user_id].get("attributes", {})
                        user_name = user_attrs.get("full_name") or user_attrs.get("email", "Unknown")

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
                        "is_override": next_attrs.get("is_override", False)
                    }

                handoff_data.append(schedule_info)

            # Filter by region if requested
            if filter_by_region:
                # Define business hours (9am-5pm) in the target timezone
                business_start_hour = 9
                business_end_hour = 17

                # Create datetime objects for today's business hours in target timezone
                today_business_start = now.replace(hour=business_start_hour, minute=0, second=0, microsecond=0)
                today_business_end = now.replace(hour=business_end_hour, minute=0, second=0, microsecond=0)

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
                                shift_start = datetime.fromisoformat(shift_start_str.replace("Z", "+00:00"))
                                shift_end = datetime.fromisoformat(shift_end_str.replace("Z", "+00:00"))

                                # Check if shift overlaps with today's business hours
                                # Shift overlaps if: shift_start < business_end AND shift_end > business_start
                                if shift_start < today_business_end and shift_end > today_business_start:
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
                            tags=""
                        )

                        schedule_info["shift_incidents"] = incidents_result if incidents_result.get("success") else None
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
                    "schedules_with_current_oncall": sum(1 for s in handoff_data if s["current_oncall"]),
                    "schedules_with_next_oncall": sum(1 for s in handoff_data if s["next_oncall"]),
                    "total_incidents": sum(
                        s.get("shift_incidents", {}).get("summary", {}).get("total_incidents", 0)
                        for s in handoff_data
                        if s.get("shift_incidents")
                    )
                }
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
                    "traceback": traceback.format_exc()
                }
            )

    async def _fetch_shift_incidents_internal(
        start_time: str,
        end_time: str,
        schedule_ids: str = "",
        severity: str = "",
        status: str = "",
        tags: str = ""
    ) -> dict:
        """Internal helper to fetch incidents - used by both get_shift_incidents and get_oncall_handoff_summary."""
        try:
            from datetime import datetime

            # Build query parameters
            # Fetch incidents that:
            # 1. Were created during the shift (created_at in range)
            # 2. OR are currently active/unresolved (started but not resolved yet)
            params = {
                "page[size]": 100,
                "sort": "-created_at"
            }

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
                incidents_response = await make_authenticated_request("GET", "/v1/incidents", params=params)

                if not incidents_response:
                    return MCPError.tool_error("Failed to fetch incidents - no response from API", "execution_error")

                if incidents_response.status_code != 200:
                    return MCPError.tool_error(
                        f"Failed to fetch incidents - API returned status {incidents_response.status_code}",
                        "execution_error",
                        details={"status_code": incidents_response.status_code, "time_range": f"{start_time} to {end_time}"}
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
                    created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00")) if created_at else None
                    started_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00")) if started_at else None
                    resolved_dt = datetime.fromisoformat(resolved_at.replace("Z", "+00:00")) if resolved_at else None
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
                    narrative_parts.append(f"Action items created: {attrs.get('action_items_count')}")

                narrative = " | ".join(narrative_parts)

                incidents_summary.append({
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
                    "incident_url": attrs.get("incident_url")
                })

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
            durations = [inc["duration_minutes"] for inc in incidents_summary if inc["duration_minutes"]]
            if durations:
                avg_resolution_time = int(sum(durations) / len(durations))

            return {
                "success": True,
                "period": {
                    "start_time": start_time,
                    "end_time": end_time
                },
                "summary": {
                    "total_incidents": total_incidents,
                    "resolved": resolved_count,
                    "ongoing": ongoing_count,
                    "average_resolution_minutes": avg_resolution_time,
                    "by_severity": {k: len(v) for k, v in by_severity.items()}
                },
                "incidents": incidents_summary
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
                    "traceback": traceback.format_exc()
                }
            )

    @mcp.tool()
    async def get_shift_incidents(
        start_time: Annotated[str, Field(description="Start time for incident search (ISO 8601 format, e.g., '2025-10-01T00:00:00Z')")],
        end_time: Annotated[str, Field(description="End time for incident search (ISO 8601 format, e.g., '2025-10-01T23:59:59Z')")],
        schedule_ids: Annotated[str, Field(description="Comma-separated list of schedule IDs to filter incidents (optional)")] = "",
        severity: Annotated[str, Field(description="Filter by severity: 'critical', 'high', 'medium', 'low' (optional)")] = "",
        status: Annotated[str, Field(description="Filter by status: 'started', 'detected', 'acknowledged', 'investigating', 'identified', 'monitoring', 'resolved', 'cancelled' (optional)")] = "",
        tags: Annotated[str, Field(description="Comma-separated list of tag slugs to filter incidents (optional)")] = ""
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
        return await _fetch_shift_incidents_internal(start_time, end_time, schedule_ids, severity, status, tags)

    # Add MCP resources for incidents and teams
    @mcp.resource("incident://{incident_id}")
    async def get_incident_resource(incident_id: str):
        """Expose incident details as an MCP resource for easy reference and context."""
        try:
            response = await make_authenticated_request("GET", f"/v1/incidents/{incident_id}")
            response.raise_for_status()
            incident_data = response.json()
            
            # Format incident data as readable text
            incident = incident_data.get("data", {})
            attributes = incident.get("attributes", {})
            
            text_content = f"""Incident #{incident_id}
Title: {attributes.get('title', 'N/A')}
Status: {attributes.get('status', 'N/A')}  
Severity: {attributes.get('severity', 'N/A')}
Created: {attributes.get('created_at', 'N/A')}
Updated: {attributes.get('updated_at', 'N/A')}
Summary: {attributes.get('summary', 'N/A')}
URL: {attributes.get('url', 'N/A')}"""
            
            return {
                "uri": f"incident://{incident_id}",
                "name": f"Incident #{incident_id}",
                "text": text_content,
                "mimeType": "text/plain"
            }
        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return {
                "uri": f"incident://{incident_id}",
                "name": f"Incident #{incident_id} (Error)",
                "text": f"Error ({error_type}): {error_message}",
                "mimeType": "text/plain"
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
Name: {attributes.get('name', 'N/A')}
Color: {attributes.get('color', 'N/A')}
Slug: {attributes.get('slug', 'N/A')}
Created: {attributes.get('created_at', 'N/A')}
Updated: {attributes.get('updated_at', 'N/A')}"""
            
            return {
                "uri": f"team://{team_id}",
                "name": f"Team: {attributes.get('name', team_id)}",
                "text": text_content,
                "mimeType": "text/plain"
            }
        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return {
                "uri": f"team://{team_id}",
                "name": f"Team #{team_id} (Error)",
                "text": f"Error ({error_type}): {error_message}",
                "mimeType": "text/plain"
            }

    @mcp.resource("rootly://incidents")
    async def list_incidents_resource():
        """List recent incidents as an MCP resource for quick reference."""
        try:
            response = await make_authenticated_request("GET", "/v1/incidents", params={
                "page[size]": 10,
                "page[number]": 1,
                "include": ""
            })
            response.raise_for_status()
            data = response.json()
            
            incidents = data.get("data", [])
            text_lines = ["Recent Incidents:\n"]
            
            for incident in incidents:
                attrs = incident.get("attributes", {})
                text_lines.append(f"• #{incident.get('id', 'N/A')} - {attrs.get('title', 'N/A')} [{attrs.get('status', 'N/A')}]")
            
            return {
                "uri": "rootly://incidents",
                "name": "Recent Incidents",
                "text": "\n".join(text_lines),
                "mimeType": "text/plain"
            }
        except Exception as e:
            error_type, error_message = MCPError.categorize_error(e)
            return {
                "uri": "rootly://incidents", 
                "name": "Recent Incidents (Error)",
                "text": f"Error ({error_type}): {error_message}",
                "mimeType": "text/plain"
            }


    # Log server creation (tool count will be shown when tools are accessed)
    logger.info("Created Rootly MCP Server successfully")
    return mcp


def _load_swagger_spec(swagger_path: Optional[str] = None) -> Dict[str, Any]:
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
        with open(swagger_path, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        # First, check in the package data directory
        try:
            package_data_path = Path(__file__).parent / "data" / "swagger.json"
            if package_data_path.is_file():
                logger.info(f"Found Swagger file in package data: {package_data_path}")
                with open(package_data_path, "r", encoding="utf-8") as f:
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
            with open(local_swagger_path, "r", encoding="utf-8") as f:
                return json.load(f)

        # Check parent directories
        for parent in current_dir.parents:
            parent_swagger_path = parent / "swagger.json"
            if parent_swagger_path.is_file():
                logger.info(f"Found Swagger file at {parent_swagger_path}")
                with open(parent_swagger_path, "r", encoding="utf-8") as f:
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


def _fetch_swagger_from_url(url: str = SWAGGER_URL) -> Dict[str, Any]:
    """
    Fetch the Swagger specification from the specified URL.

    Args:
        url: URL of the Swagger JSON file.

    Returns:
        The Swagger specification as a dictionary.
    """
    logger.info(f"Fetching Swagger specification from {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch Swagger spec: {e}")
        raise Exception(f"Failed to fetch Swagger specification: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Swagger spec: {e}")
        raise Exception(f"Failed to parse Swagger specification: {e}")


def _filter_openapi_spec(spec: Dict[str, Any], allowed_paths: List[str]) -> Dict[str, Any]:
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
        path: path_item
        for path, path_item in original_paths.items()
        if path in allowed_paths
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
                    for content_type, content_info in request_body["content"].items():
                        if "schema" in content_info:
                            schema = content_info["schema"]
                            # Remove problematic $ref references
                            if "$ref" in schema and "incident_trigger_params" in schema["$ref"]:
                                # Replace with a generic object schema
                                content_info["schema"] = {
                                    "type": "object",
                                    "description": "Request parameters for this endpoint",
                                    "additionalProperties": True
                                }

            # Remove response schemas to avoid validation issues
            # FastMCP will still return the data, just without strict validation
            if "responses" in operation:
                for status_code, response in operation["responses"].items():
                    if "content" in response:
                        for content_type, content_info in response["content"].items():
                            if "schema" in content_info:
                                # Replace with a simple schema that accepts any response
                                content_info["schema"] = {
                                    "type": "object",
                                    "additionalProperties": True
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
                                "description": param.get("description", "Parameter value")
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
                    page_size_param["schema"].update({
                        "type": "integer",
                        "default": 10,
                        "minimum": 1,
                        "maximum": 20,
                        "description": "Number of results per page (max: 20)"
                    })
                else:
                    # Add new parameter
                    operation["parameters"].append({
                        "name": "page[size]",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "integer",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 20,
                            "description": "Number of results per page (max: 20)"
                        }
                    })
                
                # Update or add page[number] parameter with defaults
                if page_number_param:
                    # Update existing parameter 
                    if "schema" not in page_number_param:
                        page_number_param["schema"] = {}
                    page_number_param["schema"].update({
                        "type": "integer",
                        "default": 1,
                        "minimum": 1,
                        "description": "Page number to retrieve"
                    })
                else:
                    # Add new parameter
                    operation["parameters"].append({
                        "name": "page[number]",
                        "in": "query", 
                        "required": False,
                        "schema": {
                            "type": "integer",
                            "default": 1,
                            "minimum": 1,
                            "description": "Page number to retrieve"
                        }
                    })
                
                # Add sparse fieldsets for alerts endpoints to reduce payload size
                if "alert" in path.lower():
                    # Add fields[alerts] parameter with essential fields only - make it required with default
                    operation["parameters"].append({
                        "name": "fields[alerts]",
                        "in": "query",
                        "required": True,
                        "schema": {
                            "type": "string",
                            "default": "id,summary,status,started_at,ended_at,short_id,alert_urgency_id,source,noise",
                            "description": "Comma-separated list of alert fields to include (reduces payload size)"
                        }
                    })
                
                # Add include parameter for alerts endpoints to minimize relationships
                if "alert" in path.lower():
                    # Check if include parameter already exists
                    include_param_exists = any(param.get("name") == "include" for param in operation["parameters"])
                    if not include_param_exists:
                        operation["parameters"].append({
                            "name": "include",
                            "in": "query",
                            "required": True,
                            "schema": {
                                "type": "string",
                                "default": "",
                                "description": "Related resources to include (empty for minimal payload)"
                            }
                        })
                
                # Add sparse fieldsets for incidents endpoints to reduce payload size
                if "incident" in path.lower():
                    # Add fields[incidents] parameter with essential fields only - make it required with default
                    operation["parameters"].append({
                        "name": "fields[incidents]", 
                        "in": "query",
                        "required": True,
                        "schema": {
                            "type": "string",
                            "default": "id,title,summary,status,severity,created_at,updated_at,url,started_at",
                            "description": "Comma-separated list of incident fields to include (reduces payload size)"
                        }
                    })
                
                # Add include parameter for incidents endpoints to minimize relationships
                if "incident" in path.lower():
                    # Check if include parameter already exists
                    include_param_exists = any(param.get("name") == "include" for param in operation["parameters"])
                    if not include_param_exists:
                        operation["parameters"].append({
                            "name": "include",
                            "in": "query",
                            "required": True,
                            "schema": {
                                "type": "string", 
                                "default": "",
                                "description": "Related resources to include (empty for minimal payload)"
                            }
                        })

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
        removed_schemas = {"new_workflow", "update_workflow", "workflow", "workflow_task", 
                          "workflow_response", "workflow_list", "new_workflow_task", 
                          "update_workflow_task", "workflow_task_response", "workflow_task_list"}
    
    for path, path_item in filtered_spec.get("paths", {}).items():
        for method, operation in path_item.items():
            if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                continue
                
            # Clean request body references
            if "requestBody" in operation:
                request_body = operation["requestBody"]
                if "content" in request_body:
                    for content_type, content_info in request_body["content"].items():
                        if "schema" in content_info and "$ref" in content_info["schema"]:
                            ref_path = content_info["schema"]["$ref"]
                            schema_name = ref_path.split("/")[-1]
                            if schema_name in removed_schemas:
                                # Replace with generic object schema
                                content_info["schema"] = {
                                    "type": "object",
                                    "description": "Request data for this endpoint",
                                    "additionalProperties": True
                                }
                                logger.debug(f"Cleaned broken reference in {method.upper()} {path} request body: {ref_path}")
            
            # Clean response references 
            if "responses" in operation:
                for status_code, response in operation["responses"].items():
                    if "content" in response:
                        for content_type, content_info in response["content"].items():
                            if "schema" in content_info and "$ref" in content_info["schema"]:
                                ref_path = content_info["schema"]["$ref"]
                                schema_name = ref_path.split("/")[-1]
                                if schema_name in removed_schemas:
                                    # Replace with generic object schema
                                    content_info["schema"] = {
                                        "type": "object",
                                        "description": "Response data from this endpoint",
                                        "additionalProperties": True
                                    }
                                    logger.debug(f"Cleaned broken reference in {method.upper()} {path} response: {ref_path}")

    return filtered_spec


def _has_broken_references(schema_def: Dict[str, Any]) -> bool:
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
            "workflow_runs_list"
        ]
        if any(broken_ref in ref_path for broken_ref in broken_refs):
            return True

    # Recursively check nested schemas
    for key, value in schema_def.items():
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
        swagger_path: Optional[str] = None,
        name: str = "Rootly",
        default_page_size: int = 10,
        allowed_paths: Optional[List[str]] = None,
        hosted: bool = False,
        *args,
        **kwargs,
    ):
        logger.warning(
            "RootlyMCPServer class is deprecated. Use create_rootly_mcp_server() function instead."
        )

        # Create the server using the new function
        server = create_rootly_mcp_server(
            swagger_path=swagger_path,
            name=name,
            allowed_paths=allowed_paths,
            hosted=hosted
        )

        # Copy the server's state to this instance
        super().__init__(name, *args, **kwargs)
        # For compatibility, store reference to the new server
        # Tools will be accessed via async methods when needed
        self._server = server
        self._tools = {}  # Placeholder - tools should be accessed via async methods
        self._resources = getattr(server, '_resources', {})
        self._prompts = getattr(server, '_prompts', {})
