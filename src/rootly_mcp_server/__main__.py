#!/usr/bin/env python3
"""
Rootly MCP Server - Main entry point

This module provides the main entry point for the Rootly MCP Server.
"""

import os
import sys
from typing import Optional, List

from rootly_mcp_server.server import create_rootly_mcp_server


# Create the server instance following FastMCP conventions
def get_server():
    """Get a configured Rootly MCP server instance."""
    # Get configuration from environment variables
    swagger_path = os.getenv("ROOTLY_SWAGGER_PATH")
    server_name = os.getenv("ROOTLY_SERVER_NAME", "Rootly")
    hosted = os.getenv("ROOTLY_HOSTED", "false").lower() in ("true", "1", "yes")
    base_url = os.getenv("ROOTLY_BASE_URL")
    
    # Parse allowed paths from environment variable
    allowed_paths = None
    allowed_paths_env = os.getenv("ROOTLY_ALLOWED_PATHS")
    if allowed_paths_env:
        allowed_paths = [path.strip() for path in allowed_paths_env.split(",")]
    
    # Create and return the server
    return create_rootly_mcp_server(
        swagger_path=swagger_path,
        name=server_name,
        allowed_paths=allowed_paths,
        hosted=hosted,
        base_url=base_url,
    )


# Create the server instance for FastMCP CLI (follows quickstart pattern)
mcp = get_server()


def main():
    """Main entry point for the Rootly MCP Server."""
    try:
        # Run the server
        mcp.run()
        
    except Exception as e:
        print(f"Error starting Rootly MCP Server: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
