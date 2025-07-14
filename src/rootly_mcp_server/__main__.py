#!/usr/bin/env python3
"""
Rootly MCP Server - Main entry point

This module provides the main entry point for the Rootly MCP Server.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Optional, List

from .routemap_server import create_rootly_mcp_server


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Start the Rootly MCP server for API integration."
    )
    parser.add_argument(
        "--swagger-path",
        type=str,
        help="Path to the Swagger JSON file. If not provided, will look for swagger.json in the current directory and parent directories.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level. Default: INFO",
    )
    parser.add_argument(
        "--name",
        type=str,
        default="Rootly",
        help="Name of the MCP server. Default: Rootly",
    )
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol to use. Default: stdio",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode (equivalent to --log-level DEBUG)",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        help="Base URL for the Rootly API. Default: https://api.rootly.com",
    )
    parser.add_argument(
        "--allowed-paths",
        type=str,
        help="Comma-separated list of allowed API paths to include",
    )
    parser.add_argument(
        "--hosted",
        action="store_true",
        help="Enable hosted mode for remote MCP server",
    )
    # Backward compatibility: support deprecated --host argument
    parser.add_argument(
        "--host",
        action="store_true",
        help="(Deprecated) Use --hosted instead. Enable hosted mode for remote MCP server",
    )
    return parser.parse_args()


def setup_logging(log_level, debug=False):
    """Set up logging configuration."""
    if debug or os.getenv("DEBUG", "").lower() in ("true", "1", "yes"):
        log_level = "DEBUG"
    
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    
    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],  # Log to stderr for stdio transport
    )
    
    # Set specific logger levels
    logging.getLogger("rootly_mcp_server").setLevel(numeric_level)
    logging.getLogger("mcp").setLevel(numeric_level)
    
    # Log the configuration
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured with level: {log_level}")
    logger.debug(f"Python version: {sys.version}")
    logger.debug(f"Current directory: {Path.cwd()}")
    logger.debug(f"Environment variables: {', '.join([f'{k}={v[:3]}...' if k.endswith('TOKEN') else f'{k}={v}' for k, v in os.environ.items() if k.startswith('ROOTLY_') or k in ['DEBUG']])}")


def check_api_token():
    """Check if the Rootly API token is set."""
    logger = logging.getLogger(__name__)
    
    api_token = os.environ.get("ROOTLY_API_TOKEN")
    if not api_token:
        logger.error("ROOTLY_API_TOKEN environment variable is not set.")
        print("Error: ROOTLY_API_TOKEN environment variable is not set.", file=sys.stderr)
        print("Please set it with: export ROOTLY_API_TOKEN='your-api-token-here'", file=sys.stderr)
        sys.exit(1)
    else:
        logger.info("ROOTLY_API_TOKEN is set")
        # Log the first few characters of the token for debugging
        logger.debug(f"Token starts with: {api_token[:5]}...")


# Create the server instance for FastMCP CLI (follows quickstart pattern)
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
        custom_allowed_paths=allowed_paths,
        hosted=hosted,
        base_url=base_url,
    )


# Create the server instance for FastMCP CLI (follows quickstart pattern)
mcp = get_server()


def main():
    """Main entry point for the Rootly MCP Server."""
    args = parse_args()
    setup_logging(args.log_level, args.debug)
    
    logger = logging.getLogger(__name__)
    logger.info("Starting Rootly MCP Server")
    
    # Handle backward compatibility for --host argument
    hosted_mode = args.hosted
    if args.host:
        logger.warning("--host argument is deprecated, use --hosted instead")
        hosted_mode = True
    
    check_api_token()
    
    try:
        # Parse allowed paths from command line argument
        allowed_paths = None
        if args.allowed_paths:
            allowed_paths = [path.strip() for path in args.allowed_paths.split(",")]
        
        logger.info(f"Initializing server with name: {args.name}")
        server = create_rootly_mcp_server(
            swagger_path=args.swagger_path,
            name=args.name,
            allowed_paths=allowed_paths,
            hosted=hosted_mode,
            base_url=args.base_url,
        )
        
        logger.info(f"Running server with transport: {args.transport}...")
        server.run(transport=args.transport)
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to start server: {e}", exc_info=True)
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
