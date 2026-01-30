"""
Rootly MCP Server - A Model Context Protocol server for Rootly API integration.

This package provides a Model Context Protocol (MCP) server for Rootly API integration.
It dynamically generates MCP tools based on the Rootly API's OpenAPI (Swagger) specification.

Features:
- Automatic tool generation from Swagger spec
- Authentication via ROOTLY_API_TOKEN environment variable
- Default pagination (10 items) for incidents endpoints to prevent context window overflow
- Comprehensive security: HTTPS enforcement, input sanitization, rate limiting
- Structured logging with correlation IDs and metrics collection
- Custom exception hierarchy for better error handling
- Input validation and sensitive data masking
"""

from .client import RootlyClient
from .server import RootlyMCPServer

__version__ = "2.1.0"
__all__ = [
    "RootlyMCPServer",
    "RootlyClient",
]
