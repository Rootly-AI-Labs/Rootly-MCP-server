#!/usr/bin/env python3
"""
Rootly FastMCP Server (RouteMap Version)

Alternative implementation using FastMCP's RouteMap system for filtering
instead of pre-filtering the OpenAPI spec.
"""

import httpx
from fastmcp import FastMCP
from fastmcp.server.openapi import RouteMap, MCPType
import os
import logging
import sys
from pathlib import Path
from typing import Optional, List

# Import the shared OpenAPI loader
sys.path.append(str(Path(__file__).parent.parent.parent))
from rootly_openapi_loader import load_rootly_openapi_spec

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_rootly_mcp_server(
    swagger_path: Optional[str] = None,
    name: str = "Rootly API Server (RouteMap Filtered)",
    allowed_paths: Optional[List[str]] = None,
    hosted: bool = False,
    base_url: Optional[str] = None,
):
    """Create and configure the Rootly MCP server using RouteMap filtering."""
    
    # Get Rootly API token from environment
    ROOTLY_API_TOKEN = os.getenv("ROOTLY_API_TOKEN")
    if not ROOTLY_API_TOKEN:
        raise ValueError("ROOTLY_API_TOKEN environment variable is required")
    
    logger.info("Creating authenticated HTTP client...")
    # Create authenticated HTTP client
    client = httpx.AsyncClient(
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
        # Core incident management
        RouteMap(
            pattern=r"^/v1/incidents$",
            mcp_type=MCPType.TOOL
        ),
        RouteMap(
            pattern=r"^/v1/incidents/\{incident_id\}/alerts$",
            mcp_type=MCPType.TOOL
        ),
        RouteMap(
            pattern=r"^/v1/incidents/\{incident_id\}/action_items$",
            mcp_type=MCPType.TOOL
        ),
        
        # Alert management
        RouteMap(
            pattern=r"^/v1/alerts$",
            mcp_type=MCPType.TOOL
        ),
        RouteMap(
            pattern=r"^/v1/alerts/\{id\}$",
            mcp_type=MCPType.TOOL
        ),
        
        # Configuration entities
        RouteMap(
            pattern=r"^/v1/severities(\{id\})?$",
            mcp_type=MCPType.TOOL
        ),
        RouteMap(
            pattern=r"^/v1/incident_types(\{id\})?$",
            mcp_type=MCPType.TOOL
        ),
        RouteMap(
            pattern=r"^/v1/functionalities(\{id\})?$",
            mcp_type=MCPType.TOOL
        ),
        
        # Organization
        RouteMap(
            pattern=r"^/v1/teams(\{id\})?$",
            mcp_type=MCPType.TOOL
        ),
        RouteMap(
            pattern=r"^/v1/users(\{id\}|/me)?$",
            mcp_type=MCPType.TOOL
        ),
        
        # Infrastructure
        RouteMap(
            pattern=r"^/v1/services(\{id\})?$",
            mcp_type=MCPType.TOOL
        ),
        RouteMap(
            pattern=r"^/v1/environments(\{id\})?$",
            mcp_type=MCPType.TOOL
        ),
        
        # Action items
        RouteMap(
            pattern=r"^/v1/incident_action_items(\{id\})?$",
            mcp_type=MCPType.TOOL
        ),
        
        # Workflows
        RouteMap(
            pattern=r"^/v1/workflows(\{id\})?$",
            mcp_type=MCPType.TOOL
        ),
        RouteMap(
            pattern=r"^/v1/workflow_runs(\{id\})?$",
            mcp_type=MCPType.TOOL
        ),
        
        # Status pages
        RouteMap(
            pattern=r"^/v1/status_pages(\{id\})?$",
            mcp_type=MCPType.TOOL
        ),
        
        # Exclude everything else
        RouteMap(
            pattern=r".*",
            mcp_type=MCPType.EXCLUDE
        )
    ]
    
    # Create MCP server with custom route maps
    mcp = FastMCP.from_openapi(
        openapi_spec=openapi_spec,
        client=client,
        name=name,
        timeout=30.0,
        tags={"rootly", "incident-management", "evaluation"},
        route_maps=route_maps
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