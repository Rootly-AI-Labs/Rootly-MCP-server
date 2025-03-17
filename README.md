# Rootly MCP Server

A Model Context Protocol (MCP) server for Rootly API. This server dynamically generates MCP resources based on Rootly's OpenAPI (Swagger) specification.

## Features

- Dynamically generated MCP tools based on Rootly's OpenAPI specification
- Authentication via Rootly API token
- Default pagination (10 items) for incidents endpoints to prevent context window overflow
- Easy integration with Claude and other MCP-compatible LLMs

## Prerequisites

- Python 3.12 or higher
- `uv` package manager
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
- Rootly API token

## Setup

1. Create and activate a virtual environment:
```bash
# Create a new virtual environment
uv venv

# Activate the virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate
```

2. Install the package in development mode:
```bash
# Install all dependencies
uv pip install -e .

# Install dev dependencies (optional)
uv pip install -e ".[dev]"
```

3. Set your Rootly API token:
```bash
export ROOTLY_API_TOKEN="your-api-token-here"
```

## Running the Server

Start the server:
```bash
rootly-mcp-server
```

## MCP Configuration

The server configuration is defined in `mcp.json`. To use this server with Claude or other MCP clients, add the following configuration to your MCP configuration file:

```json
{
    "mcpServers": {
      "rootly": {
        "command": "uv",
        "args": [
          "run",
          "--directory",
          "/path/to/rootly-mcp-server",
          "rootly-mcp-server"
        ],
        "env": {
          "ROOTLY_API_TOKEN": "YOUR_ROOTLY_API_TOKEN"
        }
      }
    }
  }
```

Replace `/path/to/rootly-mcp-server` with the absolute path to your project directory.

## About the Rootly AI Labs
This project was developed by the [Rootly AI Labs](https://labs.rootly.ai/). The AI Labs is building the future of system reliability and operational excellence. We operate as an open-source incubator, sharing ideas, experimenting, and rapidly prototyping. We're committed to ensuring our research benefits the entire community.
![Rootly AI logo](https://github.com/Rootly-AI-Labs/EventOrOutage/raw/main/rootly-ai.png)

