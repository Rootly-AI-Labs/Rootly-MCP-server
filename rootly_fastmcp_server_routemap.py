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
from rootly_openapi_loader import load_rootly_openapi_spec

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_rootly_mcp_server():
    """Create and configure the Rootly MCP server using RouteMap filtering."""
    
    # Get Rootly API token from environment
    ROOTLY_API_TOKEN = os.getenv("ROOTLY_API_TOKEN")
    if not ROOTLY_API_TOKEN:
        raise ValueError("ROOTLY_API_TOKEN environment variable is required")
    
    logger.info("Creating authenticated HTTP client...")
    # Create authenticated HTTP client
    client = httpx.AsyncClient(
        base_url="https://api.rootly.com",
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
            mcp_type=MCPType.TOOL,
            mcp_tags={"incidents", "core"}
        ),
        RouteMap(
            pattern=r"^/v1/incidents/\{incident_id\}/alerts$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"incidents", "alerts", "relationship"}
        ),
        RouteMap(
            pattern=r"^/v1/incidents/\{incident_id\}/action_items$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"incidents", "action-items", "relationship"}
        ),
        
        # Alert management
        RouteMap(
            pattern=r"^/v1/alerts$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"alerts", "core"}
        ),
        RouteMap(
            pattern=r"^/v1/alerts/\{alert_id\}$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"alerts", "detail"}
        ),
        
        # Configuration entities
        RouteMap(
            pattern=r"^/v1/severities(\{severity_id\})?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"configuration", "severities"}
        ),
        RouteMap(
            pattern=r"^/v1/incident_types(\{incident_type_id\})?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"configuration", "incident-types"}
        ),
        RouteMap(
            pattern=r"^/v1/functionalities(\{functionality_id\})?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"configuration", "functionalities"}
        ),
        
        # Organization
        RouteMap(
            pattern=r"^/v1/teams(\{team_id\})?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"organization", "teams"}
        ),
        RouteMap(
            pattern=r"^/v1/users(\{user_id\}|/me)?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"organization", "users"}
        ),
        
        # Infrastructure
        RouteMap(
            pattern=r"^/v1/services(\{service_id\})?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"infrastructure", "services"}
        ),
        RouteMap(
            pattern=r"^/v1/environments(\{environment_id\})?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"infrastructure", "environments"}
        ),
        
        # Action items
        RouteMap(
            pattern=r"^/v1/incident_action_items(\{incident_action_item_id\})?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"action-items", "management"}
        ),
        
        # Workflows
        RouteMap(
            pattern=r"^/v1/workflows(\{workflow_id\})?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"automation", "workflows"}
        ),
        RouteMap(
            pattern=r"^/v1/workflow_runs(\{workflow_run_id\})?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"automation", "workflow-runs"}
        ),
        
        # Status pages
        RouteMap(
            pattern=r"^/v1/status_pages(\{status_page_id\})?$",
            mcp_type=MCPType.TOOL,
            mcp_tags={"communication", "status-pages"}
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
        name="Rootly API Server (RouteMap Filtered)",
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