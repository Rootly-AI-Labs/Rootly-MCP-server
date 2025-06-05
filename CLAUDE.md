# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Environment Setup
```bash
# Install dependencies using uv
uv pip install .

# Create and activate virtual environment
uv venv .venv
source .venv/bin/activate
```

### Testing and Quality
```bash
# Run test client to verify setup
python test_mcp_client.py

# Linting and type checking (if you add dev dependencies)
ruff check src/
pyright src/
```

### Package Building
```bash
# Build the package
uv build
```

## Architecture Overview

This is an MCP (Model Context Protocol) server that provides AI agents access to the Rootly API for incident management. The project uses Python 3.12+ with `uv` for dependency management.

### Core Components

- **`server.py`**: Main MCP server implementation (`RootlyMCPServer` class)
  - Dynamically generates MCP tools from Rootly's OpenAPI/Swagger specification
  - Filters available endpoints via `allowed_paths` configuration for security and context management
  - Implements automatic pagination (default 10 items) for incident endpoints
  - Uses FastMCP framework with ERROR log level to prevent UI noise

- **`client.py`**: Rootly API client (`RootlyClient` class)
  - Handles authentication via `ROOTLY_API_TOKEN` environment variable
  - Supports both JSON and JSON-API formats depending on endpoint requirements
  - Base URL defaults to `https://api.rootly.com`
  - Auto-prefixes paths with `/v1` if not present

- **`data/swagger.json`**: Cached OpenAPI specification
  - Falls back to downloading from `https://rootly-heroku.s3.amazonaws.com/swagger/v1/swagger.json`
  - Server searches local directories before downloading

### Key Design Patterns

- **Dynamic Tool Generation**: Tools are created at runtime based on Swagger spec rather than hardcoded
- **Path Whitelisting**: Only specific endpoints in `allowed_paths` are exposed to prevent context overflow and maintain security
- **JSON-API Support**: Automatically wraps request bodies in JSON-API format for create/update operations
- **Error Resilience**: Comprehensive error handling with structured JSON error responses

### Configuration

The `allowed_paths` array in `server.py:56-92` controls which Rootly API endpoints are available. Modify this list to expose additional endpoints. Paths should be specified without the `/v1` prefix.

### Environment Variables

- `ROOTLY_API_TOKEN`: Required authentication token for Rootly API access