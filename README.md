# Rootly MCP Server

An MCP server for the [Rootly API](https://docs.rootly.com/api-reference/overview) that integrates seamlessly with MCP-compatible editors like Cursor, Windsurf, and Claude. Resolve production incidents in under a minute without leaving your IDE.

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=rootly&config=eyJjb21tYW5kIjoibnB4IC15IG1jcC1yZW1vdGUgaHR0cHM6Ly9tY3Aucm9vdGx5LmNvbS9zc2UgLS1oZWFkZXIgQXV0aG9yaXphdGlvbjoke1JPT1RMWV9BVVRIX0hFQURFUn0iLCJlbnYiOnsiUk9PVExZX0FVVEhfSEVBREVSIjoiQmVhcmVyIDxZT1VSX1JPT1RMWV9BUElfVE9LRU4%2BIn19)

![Demo GIF](rootly-mcp-server-demo.gif)

## Prerequisites

- Python 3.12 or higher
- `uv` package manager
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
- [Rootly API token](https://docs.rootly.com/api-reference/overview#how-to-generate-an-api-key%3F)

## Installation

Install via our [PyPi package](https://pypi.org/project/rootly-mcp-server/) or by cloning this repository.

Configure your MCP-compatible editor (tested with Cursor and Windsurf) with the following:

### With uv

```json
{
  "mcpServers": {
    "rootly": {
      "command": "uv",
      "args": [
        "tool",
        "run",
        "--from",
        "rootly-mcp-server",
        "rootly-mcp-server",
      ],      
      "env": {
        "ROOTLY_API_TOKEN": "<YOUR_ROOTLY_API_TOKEN>"
      }
    }
  }
}
```

### With uv-tool-uvx

```json
{
  "mcpServers": {
    "rootly": {
      "command": "uvx",
      "args": [
        "--from",
        "rootly-mcp-server",
        "rootly-mcp-server",
      ],      
      "env": {
        "ROOTLY_API_TOKEN": "<YOUR_ROOTLY_API_TOKEN>"
      }
    }
  }
}
```

To customize `allowed_paths` and access additional Rootly API paths, clone the repository and use this configuration:

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
        "ROOTLY_API_TOKEN": "<YOUR_ROOTLY_API_TOKEN>"
      }
    }
  }
}
```

## Features

- **Dynamic Tool Generation**: Automatically creates MCP resources from Rootly's OpenAPI (Swagger) specification
- **Smart Pagination**: Defaults to 10 items per request for incident endpoints to prevent context window overflow
- **API Filtering**: Limits exposed API endpoints for security and performance

### Whitelisted Endpoints

By default, the following Rootly API endpoints are exposed to the AI agent (see `allowed_paths` in `src/rootly_mcp_server/server.py`):

```
/v1/incidents
/v1/incidents/{incident_id}/alerts
/v1/alerts
/v1/alerts/{alert_id}
/v1/severities
/v1/severities/{severity_id}
/v1/teams
/v1/teams/{team_id}
/v1/services
/v1/services/{service_id}
/v1/functionalities
/v1/functionalities/{functionality_id}
/v1/incident_types
/v1/incident_types/{incident_type_id}
/v1/incident_action_items
/v1/incident_action_items/{incident_action_item_id}
/v1/incidents/{incident_id}/action_items
/v1/workflows
/v1/workflows/{workflow_id}
/v1/workflow_runs
/v1/workflow_runs/{workflow_run_id}
/v1/environments
/v1/environments/{environment_id}
/v1/users
/v1/users/{user_id}
/v1/users/me
/v1/status_pages
/v1/status_pages/{status_page_id}
```

### Why Path Limiting?

We limit exposed API paths for two key reasons:

1. **Context Management**: Rootly's comprehensive API can overwhelm AI agents, affecting their ability to perform simple tasks effectively
2. **Security**: Control which information and actions are accessible through the MCP server

To expose additional paths, modify the `allowed_paths` variable in `src/rootly_mcp_server/server.py`.

## About Rootly AI Labs

This project was developed by [Rootly AI Labs](https://labs.rootly.ai/), where we're building the future of system reliability and operational excellence. As an open-source incubator, we share ideas, experiment, and rapidly prototype solutions that benefit the entire community.
![Rootly AI logo](https://github.com/Rootly-AI-Labs/EventOrOutage/raw/main/rootly-ai.png)

## Developer Setup & Troubleshooting

### Prerequisites
- Python 3.12 or higher
- [`uv`](https://github.com/astral-sh/uv) for dependency management

### 1. Set Up Virtual Environment

Create and activate a virtual environment:

```bash
uv venv .venv
source .venv/bin/activate  # Always activate before running scripts
```

### 2. Install Dependencies

Install all project dependencies:

```bash
uv pip install .
```

To add new dependencies during development:
```bash
uv pip install <package>
```

### 3. Verify Installation

Run the test client to ensure everything is configured correctly:

```bash
python test_mcp_client.py
```

### Connect to Hosted MCP Server

Alternatively, connect directly to our hosted MCP server:

```json
{
  "mcpServers": {
    "rootly": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://mcp.rootly.com/sse",
        "--header",
        "Authorization:${ROOTLY_AUTH_HEADER}"
      ],
      "env": {
        "ROOTLY_AUTH_HEADER": "Bearer <YOUR_ROOTLY_API_TOKEN>"
      }
    }
  }
}
```
