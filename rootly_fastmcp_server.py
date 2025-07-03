#!/usr/bin/env python3
"""
Rootly FastMCP Server

A production-ready MCP server for Rootly's API using FastMCP.
Automatically fetches the latest OpenAPI spec from Rootly's Swagger endpoint.
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
    """Create and configure the Rootly MCP server."""
    
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
    
    logger.info("Filtering OpenAPI spec to include only allowed endpoints...")
    # Define allowed endpoints for evaluation
    ALLOWED_ENDPOINTS = {
        "/v1/incidents",
        "/v1/incidents/{incident_id}/alerts", 
        "/v1/alerts",
        "/v1/alerts/{alert_id}",
        "/v1/severities",
        "/v1/severities/{severity_id}",
        "/v1/teams", 
        "/v1/teams/{team_id}",
        "/v1/services",
        "/v1/services/{service_id}",
        "/v1/functionalities",
        "/v1/functionalities/{functionality_id}",
        "/v1/incident_types",
        "/v1/incident_types/{incident_type_id}",
        "/v1/incident_action_items",
        "/v1/incident_action_items/{incident_action_item_id}",
        "/v1/incidents/{incident_id}/action_items",
        "/v1/workflows",
        "/v1/workflows/{workflow_id}",
        "/v1/workflow_runs", 
        "/v1/workflow_runs/{workflow_run_id}",
        "/v1/environments",
        "/v1/environments/{environment_id}",
        "/v1/users",
        "/v1/users/{user_id}",
        "/v1/users/me",
        "/v1/status_pages",
        "/v1/status_pages/{status_page_id}"
    }
    
    # Filter the OpenAPI spec to only include allowed paths
    if "paths" in openapi_spec:
        filtered_paths = {}
        for path, methods in openapi_spec["paths"].items():
            if path in ALLOWED_ENDPOINTS:
                filtered_paths[path] = methods
                logger.info(f"✅ Included endpoint: {path}")
            else:
                logger.debug(f"⚪ Excluded endpoint: {path}")
        
        openapi_spec["paths"] = filtered_paths
        logger.info(f"🔍 Filtered to {len(filtered_paths)} allowed endpoints out of {len(openapi_spec.get('paths', {}))} total")
    
    logger.info("Creating FastMCP server with filtered endpoints...")
    # Create MCP server with filtered OpenAPI spec
    mcp = FastMCP.from_openapi(
        openapi_spec=openapi_spec,
        client=client,
        name="Rootly API Server (Filtered)",
        timeout=30.0,
        tags={"rootly", "incident-management", "evaluation"}
    )
    
    logger.info(f"✅ Created MCP server with filtered endpoints successfully")
    logger.info("🚀 Selected Rootly API endpoints are now available as MCP tools for evaluation")
    
    return mcp



def main():
    """Main entry point."""
    try:
        logger.info("🚀 Starting Rootly FastMCP Server...")
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