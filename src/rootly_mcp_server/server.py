"""
Rootly MCP Server - A Model Context Protocol server for Rootly API integration.

This module implements a server that dynamically generates MCP tools based on
the Rootly API's OpenAPI (Swagger) specification.
"""

import json
import os
import re
import logging
from pathlib import Path
import requests
import importlib.resources
from typing import Any, Dict, List, Optional, Tuple, Union, Callable

import mcp
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from .client import RootlyClient

# Set up logger
logger = logging.getLogger(__name__)

# Default Swagger URL
SWAGGER_URL = "https://rootly-heroku.s3.amazonaws.com/swagger/v1/swagger.json"


class RootlyMCPServer(FastMCP):
    """
    A Model Context Protocol server for Rootly API integration.
    
    This server dynamically generates MCP tools based on the Rootly API's
    OpenAPI (Swagger) specification.
    """
    
    def __init__(self, swagger_path: Optional[str] = None, name: str = "Rootly", default_page_size: int = 10):
        """
        Initialize the Rootly MCP Server.
        
        Args:
            swagger_path: Path to the Swagger JSON file. If None, will look for
                          swagger.json in the current directory and parent directories.
            name: Name of the MCP server.
            default_page_size: Default number of items to return per page for paginated endpoints.
                              This helps prevent context window overflow.
        """
        logger.info(f"Initializing RootlyMCPServer with name: {name}")
        super().__init__(name)
        
        # Initialize the Rootly API client
        self.client = RootlyClient()
        
        # Store default page size
        self.default_page_size = default_page_size
        logger.info(f"Using default page size: {default_page_size}")
        
        # Load the Swagger specification
        logger.info("Loading Swagger specification")
        self.swagger_spec = self._load_swagger_spec(swagger_path)
        logger.info(f"Loaded Swagger spec with {len(self.swagger_spec.get('paths', {}))} paths")
        
        # Register tools based on the Swagger spec
        logger.info("Registering tools based on Swagger spec")
        self._register_tools()
    
    def _fetch_swagger_from_url(self, url: str = SWAGGER_URL) -> Dict[str, Any]:
        """
        Fetch the Swagger specification from the specified URL.
        
        Args:
            url: URL of the Swagger JSON file.
        
        Returns:
            The Swagger specification as a dictionary.
            
        Raises:
            Exception: If the request fails or the response is not valid JSON.
        """
        logger.info(f"Fetching Swagger specification from {url}")
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an exception for bad status codes
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch Swagger spec: {e}")
            raise Exception(f"Failed to fetch Swagger specification: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Swagger spec: {e}")
            raise Exception(f"Failed to parse Swagger specification: {e}")
    
    def _load_swagger_spec(self, swagger_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load the Swagger specification from a file.
        
        Args:
            swagger_path: Path to the Swagger JSON file. If None, will look for
                          swagger.json in the following locations (in order):
                          1. package data directory
                          2. current directory and parent directories
                          3. download from the URL
        
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
            swagger_spec = self._fetch_swagger_from_url()
            
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
    
    def _register_tools(self) -> None:
        """
        Register MCP tools based on the Swagger specification.
        
        This method iterates through the paths and operations in the Swagger spec
        and creates corresponding MCP tools.
        """
        paths = self.swagger_spec.get("paths", {})
        logger.info(f"Found {len(paths)} paths in Swagger spec")
        
        # Register the list_endpoints tool
        @self.tool()
        def list_endpoints() -> str:
            """List all available Rootly API endpoints."""
            endpoints = []
            for path, path_item in paths.items():
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
                        "tool_name": self._create_tool_name(path, method)
                    })
            
            return json.dumps(endpoints, indent=2)
        
        # Register a tool for each endpoint
        tool_count = 0
        
        for path, path_item in paths.items():
            # Skip path parameters
            if "parameters" in path_item:
                path_item = {k: v for k, v in path_item.items() if k != "parameters"}
            
            for method, operation in path_item.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue
                
                # Create a tool name based on the path and method
                tool_name = self._create_tool_name(path, method)
                
                # Create a tool description
                description = operation.get("summary", "") or operation.get("description", "")
                if not description:
                    description = f"{method.upper()} {path}"
                
                # Create the input schema
                input_schema = self._create_input_schema(path, operation)
                
                # Register the tool using the direct method
                try:
                    # Define the tool function
                    def create_tool_fn(p=path, m=method, op=operation):
                        def tool_fn(**kwargs):
                            return self._handle_api_request(p, m, op, **kwargs)
                        
                        # Set the function name and docstring
                        tool_fn.__name__ = tool_name
                        tool_fn.__doc__ = description
                        return tool_fn
                    
                    # Create the tool function
                    tool_fn = create_tool_fn()
                    
                    # Register the tool with FastMCP
                    self.add_tool(
                        name=tool_name,
                        description=description,
                        fn=tool_fn
                    )
                    
                    tool_count += 1
                    logger.info(f"Registered tool: {tool_name}")
                except Exception as e:
                    logger.error(f"Error registering tool {tool_name}: {e}")
        
        logger.info(f"Registered {tool_count} tools in total")
    
    def _create_tool_name(self, path: str, method: str) -> str:
        """
        Create a tool name based on the path and method.
        
        Args:
            path: The API path.
            method: The HTTP method.
        
        Returns:
            A tool name string.
        """
        # Remove the /v1 prefix if present
        if path.startswith("/v1"):
            path = path[3:]
        
        # Replace path parameters with "by_id"
        path = re.sub(r"\{([^}]+)\}", r"by_\1", path)
        
        # Replace slashes with underscores and remove leading/trailing underscores
        path = path.replace("/", "_").strip("_")
        
        return f"{path}_{method.lower()}"
    
    def _create_input_schema(self, path: str, operation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create an input schema for the tool.
        
        Args:
            path: The API path.
            operation: The Swagger operation object.
        
        Returns:
            An input schema dictionary.
        """
        # Create a basic schema
        schema = {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False
        }
        
        # Extract path parameters
        path_params = re.findall(r"\{([^}]+)\}", path)
        for param in path_params:
            schema["properties"][param] = {
                "type": "string",
                "description": f"Path parameter: {param}"
            }
            schema["required"].append(param)
        
        # Add operation parameters
        for param in operation.get("parameters", []):
            param_name = param.get("name")
            param_in = param.get("in")
            
            if param_in in ["query", "header"]:
                param_schema = param.get("schema", {})
                param_type = param_schema.get("type", "string")
                
                schema["properties"][param_name] = {
                    "type": param_type,
                    "description": param.get("description", f"{param_in} parameter: {param_name}")
                }
                
                if param.get("required", False):
                    schema["required"].append(param_name)
        
        # Add request body for POST, PUT, PATCH methods
        if "requestBody" in operation:
            content = operation["requestBody"].get("content", {})
            if "application/json" in content:
                body_schema = content["application/json"].get("schema", {})
                
                if "properties" in body_schema:
                    for prop_name, prop_schema in body_schema["properties"].items():
                        schema["properties"][prop_name] = {
                            "type": prop_schema.get("type", "string"),
                            "description": prop_schema.get("description", f"Body parameter: {prop_name}")
                        }
                
                if "required" in body_schema:
                    schema["required"].extend(body_schema["required"])
        
        return schema
    
    def _handle_api_request(self, path: str, method: str, operation: Dict[str, Any], **kwargs) -> str:
        """
        Handle an API request to the Rootly API.
        
        Args:
            path: The API path.
            method: The HTTP method.
            operation: The Swagger operation object.
            **kwargs: The parameters for the request.
        
        Returns:
            The API response as a JSON string.
        """
        logger.debug(f"Handling API request: {method} {path}")
        logger.debug(f"Request parameters: {kwargs}")
        
        # Extract path parameters
        path_params = re.findall(r"\{([^}]+)\}", path)
        actual_path = path
        
        # Replace path parameters in the URL
        for param in path_params:
            if param in kwargs:
                actual_path = actual_path.replace(f"{{{param}}}", str(kwargs.pop(param)))
        
        # Separate query parameters and body parameters
        query_params = {}
        body_params = {}
        
        if method.lower() == "get":
            # For GET requests, all remaining parameters are query parameters
            query_params = kwargs
            
            # Add default pagination for incident-related endpoints
            if "incidents" in path and method.lower() == "get":
                # Check if pagination parameters are already specified
                has_pagination = any(param.startswith("page[") for param in query_params.keys())
                
                # If no pagination parameters are specified, add default page size
                if not has_pagination:
                    query_params["page[size]"] = self.default_page_size
                    logger.info(f"Added default pagination (page[size]={self.default_page_size}) for incidents endpoint: {path}")
        else:
            # For other methods, check which parameters are query parameters
            for param in operation.get("parameters", []):
                param_name = param.get("name")
                param_in = param.get("in")
                
                if param_in == "query" and param_name in kwargs:
                    query_params[param_name] = kwargs.pop(param_name)
            
            # All remaining parameters go in the request body
            body_params = kwargs
        
        # Make the API request
        try:
            response = self.client.make_request(
                method=method.upper(),
                path=actual_path,
                query_params=query_params if query_params else None,
                json_data=body_params if body_params else None
            )
            return response
        except Exception as e:
            logger.error(f"Error calling Rootly API: {e}")
            return json.dumps({"error": str(e)}) 