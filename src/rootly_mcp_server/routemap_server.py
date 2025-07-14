#!/usr/bin/env python3
"""
Rootly FastMCP Server (RouteMap Version)

Working implementation using FastMCP's RouteMap system with proper response handling.
"""

import httpx
from fastmcp import FastMCP
from fastmcp.server.openapi import RouteMap, MCPType
import os
import logging
from typing import Optional, List

# Import the shared OpenAPI loader
from .rootly_openapi_loader import load_rootly_openapi_spec

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_rootly_mcp_server(
    swagger_path: Optional[str] = None,
    name: str = "Rootly API Server (RouteMap Filtered)",
    custom_allowed_paths: Optional[List[str]] = None,
    hosted: bool = False,
    base_url: Optional[str] = None,
):
    """Create and configure the Rootly MCP server using RouteMap filtering."""
    
    # Get Rootly API token from environment
    ROOTLY_API_TOKEN = os.getenv("ROOTLY_API_TOKEN")
    if not ROOTLY_API_TOKEN:
        raise ValueError("ROOTLY_API_TOKEN environment variable is required")
    
    logger.info("Creating authenticated HTTP client...")
    # Create a custom HTTP client wrapper that ensures string responses
    class StringifyingClient:
        def __init__(self, base_url: str, headers: dict, timeout: float):
            self._client = httpx.AsyncClient(
                base_url=base_url,
                headers=headers,
                timeout=timeout
            )
        
        async def __aenter__(self):
            await self._client.__aenter__()
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            await self._client.__aexit__(exc_type, exc_val, exc_tb)
        
        async def request(self, method: str, url: str, **kwargs):
            """Override request to return responses that FastMCP can handle."""
            response = await self._client.request(method, url, **kwargs)
            
            # Create a response that returns the raw text instead of structured JSON
            class TextResponse:
                def __init__(self, original_response):
                    self.status_code = original_response.status_code
                    self.headers = original_response.headers
                    self.url = original_response.url
                    self.request = original_response.request
                    self._original = original_response
                    
                    # Pre-compute the text response
                    if original_response.status_code == 200:
                        try:
                            import json
                            data = original_response.json()
                            self._text_response = json.dumps(data, indent=2)
                        except Exception:
                            self._text_response = original_response.text or "No content"
                    else:
                        self._text_response = f"Error: HTTP {original_response.status_code} - {original_response.text}"
                
                def json(self):
                    """Return the original JSON data for structured_content."""
                    try:
                        # Return the original JSON data so FastMCP can handle structured_content
                        return self._original.json()
                    except Exception:
                        # If JSON parsing fails, return a wrapper structure
                        return {"result": self._text_response}
                
                @property
                def text(self):
                    """Return the formatted JSON as text."""
                    return self._text_response
                
                @property
                def content(self):
                    return self._text_response.encode('utf-8')
                
                def raise_for_status(self):
                    """Delegate to original response."""
                    return self._original.raise_for_status()
                
                def __getattr__(self, name):
                    """Delegate any missing attributes to original response."""
                    return getattr(self._original, name)
            
            return TextResponse(response)
        
        def __getattr__(self, name):
            return getattr(self._client, name)
    
    # Create authenticated HTTP client with string conversion
    client = StringifyingClient(
        base_url=base_url or "https://api.rootly.com",
        headers={
            "Authorization": f"Bearer {ROOTLY_API_TOKEN}",
            "Content-Type": "application/vnd.api+json",
            "User-Agent": "Rootly-FastMCP-Server/1.0"
        },
        timeout=30.0
    )
    
    logger.info("Loading OpenAPI specification...")
    # Load OpenAPI spec with smart fallback logic
    openapi_spec = load_rootly_openapi_spec()
    logger.info("✅ Successfully loaded OpenAPI specification")
    
    logger.info("Fixing OpenAPI spec for FastMCP compatibility...")
    # Fix array types for FastMCP compatibility
    def fix_array_types(obj):
        if isinstance(obj, dict):
            keys_to_process = list(obj.keys())
            for key in keys_to_process:
                value = obj[key]
                if key == 'type' and isinstance(value, list):
                    non_null_types = [t for t in value if t != 'null']
                    if len(non_null_types) >= 1:
                        obj[key] = non_null_types[0]
                        obj['nullable'] = True
                else:
                    fix_array_types(value)
        elif isinstance(obj, list):
            for item in obj:
                fix_array_types(item)
    
    fix_array_types(openapi_spec)
    logger.info("✅ Fixed OpenAPI spec compatibility issues")
    
    logger.info("Creating FastMCP server with RouteMap filtering...")
    
    # Define custom route maps for filtering specific endpoints
    route_maps = [
        # Core incident management - list endpoints
        RouteMap(
            pattern=r"^/v1/incidents$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"incidents", "core", "list"}
        ),
        # Incident detail endpoints  
        RouteMap(
            pattern=r"^/v1/incidents/\{.*\}$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"incidents", "detail"}
        ),
        # Incident relationships
        RouteMap(
            pattern=r"^/v1/incidents/\{.*\}/.*$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"incidents", "relationships"}
        ),
        
        # Alert management
        RouteMap(
            pattern=r"^/v1/alerts$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"alerts", "core", "list"}
        ),
        RouteMap(
            pattern=r"^/v1/alerts/\{.*\}$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"alerts", "detail"}
        ),
        
        # Users - both list and detail
        RouteMap(
            pattern=r"^/v1/users$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"users", "list"}
        ),
        RouteMap(
            pattern=r"^/v1/users/me$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"users", "current"}
        ),
        RouteMap(
            pattern=r"^/v1/users/\{.*\}$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"users", "detail"}
        ),
        
        # Teams
        RouteMap(
            pattern=r"^/v1/teams$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"teams", "list"}
        ),
        RouteMap(
            pattern=r"^/v1/teams/\{.*\}$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"teams", "detail"}
        ),
        
        # Services
        RouteMap(
            pattern=r"^/v1/services$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"services", "list"}
        ),
        RouteMap(
            pattern=r"^/v1/services/\{.*\}$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"services", "detail"}
        ),
        
        # Configuration entities - list patterns
        RouteMap(
            pattern=r"^/v1/(severities|incident_types|environments)$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"configuration", "list"}
        ),
        # Configuration entities - detail patterns  
        RouteMap(
            pattern=r"^/v1/(severities|incident_types|environments)/\{.*\}$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"configuration", "detail"}
        ),
        
        # Exclude everything else
        RouteMap(
            pattern=r".*",
            mcp_type=MCPType.EXCLUDE
        )
    ]
    
    # Custom response handler to ensure proper MCP output format
    def ensure_mcp_response(route, component):
        """Ensure all responses work with FastMCP's structured content system."""
        # Set output schema to handle structured JSON data
        component.output_schema = {
            "type": "object",
            "description": "Rootly API response data",
            "additionalProperties": True
        }
        
        # Add description 
        if hasattr(component, 'description'):
            component.description = f"🔧 {component.description or 'Rootly API endpoint'}"
    
    # Create MCP server with custom route maps and response handling
    mcp = FastMCP.from_openapi(
        openapi_spec=openapi_spec,
        client=client,
        name=name,
        timeout=30.0,
        tags={"rootly", "incident-management", "evaluation"},
        route_maps=route_maps,
        mcp_component_fn=ensure_mcp_response
    )
    
    logger.info(f"✅ Created MCP server with RouteMap filtering successfully")
    logger.info("🚀 Selected Rootly API endpoints are now available as MCP tools")
    
    return mcp


def main():
    """Main entry point."""
    try:
        logger.info("🚀 Starting Rootly FastMCP Server (RouteMap Version)...")
        mcp = create_rootly_mcp_server()
        
        logger.info("🌐 Server starting on stdio transport...")
        logger.info("Ready for MCP client connections!")
        
        # Run the MCP server
        mcp.run()
        
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped by user")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        raise

if __name__ == "__main__":
    main()