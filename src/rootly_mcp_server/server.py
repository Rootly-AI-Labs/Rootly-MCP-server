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

# Set up logger
logger = logging.getLogger(__name__)

# Default Swagger URL
SWAGGER_URL = "https://rootly-heroku.s3.amazonaws.com/swagger/v1/swagger.json"

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
        self.base_url = base_url
        self.hosted = hosted
        self._api_token = None
        self.parameter_mapping = parameter_mapping or {}

        if not self.hosted:
            self._api_token = self._get_api_token()

        # Create the HTTPX client
        headers = {"Content-Type": "application/vnd.api+json", "Accept": "application/vnd.api+json"}
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
        """Override request to transform parameters and handle encoding issues."""
        # Transform query parameters
        if 'params' in kwargs:
            kwargs['params'] = self._transform_params(kwargs['params'])

        try:
            # Call the underlying client's request method
            response = await self.client.request(method, url, **kwargs)
            
            # Check if response is successful
            response.raise_for_status()
            
            # Try to decode response content with error handling
            try:
                # First try to get text content with UTF-8
                content = response.text
                # Validate it's proper JSON if content type suggests JSON
                if 'json' in response.headers.get('content-type', '').lower():
                    response.json()  # This will raise if not valid JSON
                return response
            except UnicodeDecodeError as e:
                logger.error(f"Unicode decode error for {method} {url}: {e}")
                logger.error(f"Response headers: {dict(response.headers)}")
                logger.error(f"Response status: {response.status_code}")
                # Try to decode with different encoding
                try:
                    content = response.content.decode('latin1')
                    logger.warning(f"Decoded response with latin1 encoding")
                    return response
                except Exception:
                    raise Exception(f"Failed to decode response: {e}")
            except Exception as json_error:
                logger.error(f"JSON decode error for {method} {url}: {json_error}")
                logger.error(f"Response content preview: {response.content[:100]}")
                raise Exception(f"Invalid JSON response: {json_error}")
                
        except Exception as e:
            logger.error(f"Request failed for {method} {url}: {e}")
            raise

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
        client=http_client,
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
    async def debug_headers() -> dict:
        """Debug tool to inspect request/response headers for troubleshooting."""
        try:
            response = await make_authenticated_request("GET", "/v1/teams", params={"page[size]": 1})
            response.raise_for_status()
            
            return {
                "request_headers": dict(response.request.headers) if response.request else {},
                "response_headers": dict(response.headers),
                "status_code": response.status_code,
                "content_type": response.headers.get('content-type', 'unknown'),
                "encoding": response.encoding,
                "content_preview": str(response.content[:200]) if response.content else "No content"
            }
        except Exception as e:
            return {"error": str(e), "error_type": type(e).__name__}

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
        
        # Make the request using the underlying httpx client
        return await http_client.client.request(method, url, **kwargs)

    @mcp.tool()
    async def search_incidents(
        query: Annotated[str, Field(description="Search query to filter incidents by title/summary")] = "",
        page_size: Annotated[int, Field(description="Number of results per page (max: 20)", ge=1, le=20)] = 10,
        page_number: Annotated[int, Field(description="Page number to retrieve (use 0 for all pages)", ge=0)] = 1,
        max_results: Annotated[int, Field(description="Maximum total results when fetching all pages (ignored if page_number > 0)", ge=1, le=100)] = 20,
    ) -> dict:
        """
        Search incidents with flexible pagination control.

        Use page_number=0 to fetch all matching results across multiple pages up to max_results.
        Use page_number>0 to fetch a specific page.
        """
        # Single page mode
        if page_number > 0:
            params = {
                "page[size]": min(page_size, 20),
                "page[number]": page_number,
                "include": "",
            }
            if query:
                params["filter[search]"] = query

            try:
                response = await make_authenticated_request("GET", "/v1/incidents", params=params)
                response.raise_for_status()
                return response.json()
            except Exception as e:
                return {"error": str(e)}

        # Multi-page mode (page_number = 0)
        all_incidents = []
        current_page = 1
        effective_page_size = min(page_size, 10)

        try:
            while len(all_incidents) < max_results:
                params = {
                    "page[size]": effective_page_size,
                    "page[number]": current_page,
                    "include": "",
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
                            break
                        
                        all_incidents.extend(incidents)

                        # Check if we have more pages
                        meta = response_data.get("meta", {})
                        current_page_meta = meta.get("current_page", current_page)
                        total_pages = meta.get("total_pages", 1)

                        if current_page_meta >= total_pages:
                            break

                        current_page += 1
                    else:
                        break

                except Exception as e:
                    # Re-raise authentication or critical errors
                    if "401" in str(e) or "Unauthorized" in str(e) or "authentication" in str(e).lower():
                        raise e
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
            return {"error": str(e)}

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
