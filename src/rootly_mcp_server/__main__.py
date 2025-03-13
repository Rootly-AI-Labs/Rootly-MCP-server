"""
Command-line interface for starting the Rootly MCP server.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from .server import RootlyMCPServer


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


def main():
    """Entry point for the Rootly MCP server."""
    args = parse_args()
    setup_logging(args.log_level, args.debug)
    
    logger = logging.getLogger(__name__)
    logger.info("Starting Rootly MCP Server")
    
    check_api_token()
    
    try:
        logger.info(f"Initializing server with name: {args.name}")
        server = RootlyMCPServer(swagger_path=args.swagger_path, name=args.name)
        
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