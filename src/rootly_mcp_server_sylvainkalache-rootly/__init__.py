"""
Rootly MCP Server - A Model Context Protocol server for Rootly API integration.

This package provides a Model Context Protocol (MCP) server for Rootly API integration.
It dynamically generates MCP tools based on the Rootly API's OpenAPI (Swagger) specification.

Features:
- Automatic tool generation from Swagger spec
- Authentication via ROOTLY_API_TOKEN environment variable
- Default pagination (10 items) for incidents endpoints to prevent context window overflow
"""

from .server import RootlyMCPServer
from .client import RootlyClient

__version__ = "0.1.0"
__all__ = [
    'RootlyMCPServer',
    'RootlyClient',
] 