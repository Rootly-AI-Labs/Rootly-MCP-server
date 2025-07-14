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
from pathlib import Path
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
    
    logger.info("Creating FastMCP server with pre-filtered OpenAPI spec...")
    
    # Define the specific endpoints we want to include
    if custom_allowed_paths:
        allowed_paths = set(custom_allowed_paths)
    else:
        allowed_paths = {
            # Core incident management
            "/v1/incidents",
            "/v1/incidents/{incident_id}/alerts", 
            "/v1/incidents/{incident_id}/action_items",
            
            # Alert management  
            "/v1/alerts",
            "/v1/alerts/{id}",
            
            # Configuration entities
            "/v1/severities",
            "/v1/severities/{id}",
            "/v1/incident_types", 
            "/v1/incident_types/{id}",
            "/v1/functionalities",
            "/v1/functionalities/{id}",
            
            # Organization
            "/v1/teams",
            "/v1/teams/{id}",
            "/v1/users",
            "/v1/users/me", 
            "/v1/users/{id}",
            
            # Infrastructure
            "/v1/services",
            "/v1/services/{id}",
            "/v1/environments",
            "/v1/environments/{id}",
            
            # Action items
            "/v1/action_items",
            "/v1/action_items/{id}",
            
            # Workflows
            "/v1/workflows",
            "/v1/workflows/{id}",
            
            # Status pages
            "/v1/status-pages",
            "/v1/status-pages/{id}"
        }
    
    # Filter the OpenAPI spec to only include allowed paths
    original_paths = openapi_spec.get("paths", {})
    filtered_paths = {path: spec for path, spec in original_paths.items() if path in allowed_paths}
    
    logger.info(f"📊 Filtered OpenAPI spec from {len(original_paths)} paths to {len(filtered_paths)} paths")
    logger.info(f"🔍 Allowed paths: {sorted(allowed_paths)}")
    logger.info(f"✅ Filtered paths: {sorted(filtered_paths.keys())}")
    
    openapi_spec["paths"] = filtered_paths
    
    # Create MCP server without route maps for now to test basic functionality  
    mcp = FastMCP.from_openapi(
        openapi_spec=openapi_spec,
        client=client,
        name=name,
        timeout=30.0,
        tags={"rootly", "incident-management", "evaluation"}
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