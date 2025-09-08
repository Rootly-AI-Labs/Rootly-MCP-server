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
        incident_id: str,
        similarity_threshold: Annotated[float, Field(description="Minimum similarity score (0.0-1.0)", ge=0.0, le=1.0)] = 0.3,
        max_results: Annotated[int, Field(description="Maximum number of related incidents to return", ge=1, le=20)] = 5
    ) -> dict:
        """Find historically similar incidents to help with context and resolution strategies."""
        try:
            # Get the target incident details
            target_response = await make_authenticated_request("GET", f"/v1/incidents/{incident_id}")
            target_response.raise_for_status()
            target_incident_data = target_response.json()
            target_incident = target_incident_data.get("data", {})
            
            if not target_incident:
                return MCPError.tool_error("Incident not found", "not_found")
            
            # Get historical incidents for comparison (resolved incidents from last 6 months)
            historical_response = await make_authenticated_request("GET", "/v1/incidents", params={
                "page[size]": 100,  # Get more incidents for better matching
                "page[number]": 1,
                "filter[status]": "resolved",  # Only look at resolved incidents
                "include": ""
            })
            historical_response.raise_for_status()
            historical_data = historical_response.json()
            historical_incidents = historical_data.get("data", [])
            
            # Filter out the target incident itself
            historical_incidents = [inc for inc in historical_incidents if str(inc.get('id')) != str(incident_id)]
            
            if not historical_incidents:
                return {
                    "related_incidents": [],
                    "message": "No historical incidents found for comparison",
                    "target_incident": {
                        "id": incident_id,
                        "title": target_incident.get("attributes", {}).get("title", "")
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
                    "id": incident_id,
                    "title": target_incident.get("attributes", {}).get("title", "")
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
        max_solutions: Annotated[int, Field(description="Maximum number of solution suggestions", ge=1, le=10)] = 3
    ) -> dict:
        """Suggest solutions based on similar resolved incidents. Provide either incident_id OR title/description."""
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
            
            # Get resolved incidents for solution mining
            historical_response = await make_authenticated_request("GET", "/v1/incidents", params={
                "page[size]": 150,  # Get more incidents for better solution matching
                "page[number]": 1,
                "filter[status]": "resolved",
                "include": ""
            })
            historical_response.raise_for_status()
            historical_data = historical_response.json()
            historical_incidents = historical_data.get("data", [])
            
            # Filter out target incident if it exists
            if incident_id:
                historical_incidents = [inc for inc in historical_incidents if str(inc.get('id')) != str(incident_id)]
            
            if not historical_incidents:
                return {
                    "solutions": [],
                    "message": "No historical resolved incidents found for solution mining"
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
