"""
Rootly MCP Server - A Model Context Protocol server for Rootly API integration.

This module implements a server that dynamically generates MCP tools based on
the Rootly API's OpenAPI (Swagger) specification using FastMCP's OpenAPI integration.
"""

import json
import os
import re
import logging
from pathlib import Path
import requests
import httpx
from typing import Any, Dict, List, Optional, Tuple, Union, Callable, Annotated, Literal
from enum import Enum

from fastmcp import FastMCP

from fastmcp.server.dependencies import get_http_request
from starlette.requests import Request
from pydantic import BaseModel, Field

from .client import RootlyClient

# Set up logger
logger = logging.getLogger(__name__)

# Default Swagger URL
SWAGGER_URL = "https://rootly-heroku.s3.amazonaws.com/swagger/v1/swagger.json"


class AuthenticatedHTTPXClient:
    """An HTTPX client wrapper that handles Rootly API authentication."""
    
    def __init__(self, base_url: str = "https://api.rootly.com", hosted: bool = False):
        self.base_url = base_url
        self.hosted = hosted
        self._api_token = None
        
        if not self.hosted:
            self._api_token = self._get_api_token()
        
        # Create the HTTPX client
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"
            
        self.client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=30.0
        )
    
    def _get_api_token(self) -> Optional[str]:
        """Get the API token from environment variables."""
        api_token = os.getenv("ROOTLY_API_TOKEN")
        if not api_token:
            logger.warning("ROOTLY_API_TOKEN environment variable is not set")
            return None
        return api_token
    
    async def __aenter__(self):
        return self.client
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    def __getattr__(self, name):
        # Delegate all other attributes to the underlying client
        return getattr(self.client, name)


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
        allowed_paths = [
            "/incidents",
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

    # Determine the base URL
    if base_url is None:
        base_url = os.getenv("ROOTLY_BASE_URL", "https://api.rootly.com")
    
    logger.info(f"Using Rootly API base URL: {base_url}")

    # Create the authenticated HTTP client
    try:
        http_client = AuthenticatedHTTPXClient(
            base_url=base_url,
            hosted=hosted
        )
    except Exception as e:
        logger.warning(f"Failed to create authenticated client: {e}")
        # Create a mock client for testing
        http_client = httpx.AsyncClient(base_url=base_url)

    # Create the MCP server using OpenAPI integration
    # By default, all routes become tools which is what we want
    mcp = FastMCP.from_openapi(
        openapi_spec=filtered_spec,
        client=http_client,
        name=name,
        timeout=30.0,
        tags={"rootly", "incident-management"},
    )

    # Add some custom tools for enhanced functionality
    @mcp.tool()
    def list_endpoints() -> str:
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

        return json.dumps(endpoints, indent=2)

    @mcp.tool()
    async def search_incidents_paginated(
        query: Annotated[str, Field(description="Search query to filter incidents by title/summary")] = "",
        page_size: Annotated[int, Field(description="Number of results per page (max: 100)", ge=1, le=100)] = 100,
        page_number: Annotated[int, Field(description="Page number to retrieve", ge=1)] = 1,
    ) -> str:
        """
        Search incidents with enhanced pagination control.
        
        This tool provides better pagination handling than the standard API endpoint.
        """
        params = {
            "page[size]": min(page_size, 100),
            "page[number]": page_number,
        }
        if query:
            params["filter[search]"] = query
        
        try:
            async with http_client as client:
                response = await client.get("/v1/incidents", params=params)
                response.raise_for_status()
                result = response.json()
        except Exception as e:
            result = {"error": str(e)}
        
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def get_all_incidents_matching(
        query: Annotated[str, Field(description="Search query to filter incidents by title/summary")] = "",
        max_results: Annotated[int, Field(description="Maximum number of results to return", ge=1, le=1000)] = 500,
    ) -> str:
        """
        Get all incidents matching a query by automatically fetching multiple pages.
        
        This tool automatically handles pagination to fetch multiple pages of results.
        """
        all_incidents = []
        page_number = 1
        page_size = 100
        
        try:
            async with http_client as client:
                while len(all_incidents) < max_results:
                    params = {
                        "page[size]": page_size,
                        "page[number]": page_number,
                    }
                    if query:
                        params["filter[search]"] = query
                    
                    try:
                        response = await client.get("/v1/incidents", params=params)
                        response.raise_for_status()
                        response_data = response.json()
                        
                        if "data" in response_data:
                            incidents = response_data["data"]
                            if not incidents:  # No more results
                                break
                            all_incidents.extend(incidents)
                            
                            # Check if we have more pages
                            meta = response_data.get("meta", {})
                            current_page = meta.get("current_page", page_number)
                            total_pages = meta.get("total_pages", 1)
                            
                            if current_page >= total_pages:
                                break  # No more pages
                                
                            page_number += 1
                        else:
                            break  # Unexpected response format
                            
                    except Exception as e:
                        logger.error(f"Error fetching incidents page {page_number}: {e}")
                        break
                
                # Limit to max_results
                if len(all_incidents) > max_results:
                    all_incidents = all_incidents[:max_results]
                
                result = {
                    "data": all_incidents,
                    "meta": {
                        "total_fetched": len(all_incidents),
                        "max_results": max_results,
                        "query": query
                    }
                }
        except Exception as e:
            result = {"error": str(e)}
        
        return json.dumps(result, indent=2)

    # Log server creation (tool count will be shown when tools are accessed)
    logger.info(f"Created Rootly MCP Server successfully")
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
        with open(swagger_path, "r") as f:
            return json.load(f)
    else:
        # First, check in the package data directory
        try:
            package_data_path = Path(__file__).parent / "data" / "swagger.json"
            if package_data_path.is_file():
                logger.info(f"Found Swagger file in package data: {package_data_path}")
                with open(package_data_path, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.debug(f"Could not load Swagger file from package data: {e}")

        # Then, look for swagger.json in the current directory and parent directories
        logger.info("Looking for swagger.json in current directory and parent directories")
        current_dir = Path.cwd()

        # Check current directory first
        swagger_path = current_dir / "swagger.json"
        if swagger_path.is_file():
            logger.info(f"Found Swagger file at {swagger_path}")
            with open(swagger_path, "r") as f:
                return json.load(f)

        # Check parent directories
        for parent in current_dir.parents:
            swagger_path = parent / "swagger.json"
            if swagger_path.is_file():
                logger.info(f"Found Swagger file at {swagger_path}")
                with open(swagger_path, "r") as f:
                    return json.load(f)

        # If the file wasn't found, fetch it from the URL and save it
        logger.info("Swagger file not found locally, fetching from URL")
        swagger_spec = _fetch_swagger_from_url()

        # Save the fetched spec to the current directory
        swagger_path = current_dir / "swagger.json"
        logger.info(f"Saving Swagger file to {swagger_path}")
        try:
            with open(swagger_path, "w") as f:
                json.dump(swagger_spec, f)
            logger.info(f"Saved Swagger file to {swagger_path}")
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
    filtered_spec = spec.copy()
    
    # Filter paths
    original_paths = spec.get("paths", {})
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
            
            # Clean parameter schemas
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
            "workflow"
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
