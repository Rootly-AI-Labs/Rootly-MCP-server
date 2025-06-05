# Rootly MCP Server

An MCP server for [Rootly API](https://docs.rootly.com/api-reference/overview) that you can plug into your favorite MCP-compatible editors like Cursor, Windsurf, and Claude. Resolve production incidents in under a minute without leaving your IDE.

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=rootly&config=eyJjb21tYW5kIjoibnB4IC15IG1jcC1yZW1vdGUgaHR0cHM6Ly9tY3Aucm9vdGx5LmNvbS9zc2UgLS1oZWFkZXIgQXV0aG9yaXphdGlvbjoke1JPT1RMWV9BVVRIX0hFQURFUn0iLCJlbnYiOnsiUk9PVExZX0FVVEhfSEVBREVSIjoiQmVhcmVyIDxZT1VSX1JPT1RMWV9BUElfVE9LRU4%2BIn19)

![Demo GIF](rootly-mcp-server-demo.gif)

## Prerequisites

- Python 3.12 or higher
- `uv` package manager
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
- [Rootly API token](https://docs.rootly.com/api-reference/overview#how-to-generate-an-api-key%3F)

## Run it in your IDE

Install with our [PyPi package](https://pypi.org/project/rootly-mcp-server/) or by cloning this repo.

To set it up in your favorite MCP-compatible editor (we tested it with Cursor and Windsurf), here is the config :

```json
{
  "mcpServers": {
    "rootly": {
      "command": "uvx",
      "args": ["--from", "rootly-mcp-server", "rootly-mcp-server"],
      "env": {
        "ROOTLY_API_TOKEN": "<YOUR_ROOTLY_API_TOKEN>"
      }
    }
  }
}
```

If you want to customize `allowed_paths` to access more Rootly API paths, clone the package and use this config.

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

This server dynamically generates MCP resources based on Rootly's OpenAPI (Swagger) specification:

- Dynamically generated MCP tools based on Rootly's OpenAPI specification
- Default pagination (10 items) for incident endpoints to prevent context window overflow
- Limits the number of API paths exposed to the AI agent

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

We limited the number of API paths exposed for 2 reasons:

- Context size: because [Rootly's API](https://docs.rootly.com/api-reference/overview) is very rich in paths, AI agents can get overwhelmed and not perform simple actions properly.
- Security: if you want to limit the type of information or actions that users can access through the MCP server

If you want to make more paths available, edit the variable `allowed_paths` in `src/rootly_mcp_server/server.py`.

## About the Rootly AI Labs

This project was developed by the [Rootly AI Labs](https://labs.rootly.ai/). The AI Labs is building the future of system reliability and operational excellence. We operate as an open-source incubator, sharing ideas, experimenting, and rapidly prototyping. We're committed to ensuring our research benefits the entire community.
![Rootly AI logo](https://github.com/Rootly-AI-Labs/EventOrOutage/raw/main/rootly-ai.png)

## Developer Setup & Troubleshooting

### 1. Install dependencies with `uv`

This project uses [`uv`](https://github.com/astral-sh/uv) for fast dependency management. To install all dependencies from your `pyproject.toml`:

```bash
uv pip install .
```

### 2. Using a virtual environment

It is recommended to use a virtual environment for development:

```bash
uv venv .venv
source .venv/bin/activate
```

### 3. Running the test client

To run the test client and verify your setup:

```bash
python test_mcp_client.py
```

### 5. General tips

- Always activate your virtual environment before running scripts.
- If you add new dependencies, use `uv pip install <package>` to keep your environment up to date.
- If you encounter issues, check your Python version and ensure it matches the project's requirements.

### 6. Connecting to Our MCP Server

You can configure your client to connect directly to our hosted MCP server:

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
