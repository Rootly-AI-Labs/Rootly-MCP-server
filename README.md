# Rootly MCP Server

[![PyPI version](https://badge.fury.io/py/rootly-mcp-server.svg)](https://pypi.org/project/rootly-mcp-server/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/rootly-mcp-server)](https://pypi.org/project/rootly-mcp-server/)
[![Python Version](https://img.shields.io/pypi/pyversions/rootly-mcp-server.svg)](https://pypi.org/project/rootly-mcp-server/)

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

Configure your MCP-compatible editor (tested with Cursor) with one of the configurations below. The package will be automatically downloaded and installed when you first open your editor.

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

### With uvx

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

## Features

- **Dynamic Tool Generation**: Automatically creates MCP resources from Rootly's OpenAPI (Swagger) specification
- **Smart Pagination**: Defaults to 10 items per request for incident endpoints to prevent context window overflow
- **API Filtering**: Limits exposed API endpoints for security and performance
- **AI-Powered Incident Analysis**: Smart tools that learn from historical incident data
  - **`find_related_incidents`**: Uses TF-IDF similarity analysis to find historically similar incidents
  - **`suggest_solutions`**: Mines past incident resolutions to recommend actionable solutions
- **MCP Resources**: Exposes incident and team data as structured resources for easy AI reference
- **Intelligent Pattern Recognition**: Automatically identifies services, error types, and resolution patterns

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
2. **Security**: Controls which information and actions are accessible through the MCP server

To expose additional paths, modify the `allowed_paths` variable in `src/rootly_mcp_server/server.py`.

### AI-Powered Smart Tools

The MCP server includes intelligent tools that analyze historical incident data to provide actionable insights:

#### `find_related_incidents`
Finds historically similar incidents using machine learning text analysis:
```
find_related_incidents(incident_id="12345", similarity_threshold=0.3, max_results=5)
```
- **Input**: Incident ID, similarity threshold (0.0-1.0), max results
- **Output**: Similar incidents with confidence scores, matched services, and resolution times
- **Use Case**: Get context from past incidents to understand patterns and solutions

#### `suggest_solutions` 
Recommends solutions by analyzing how similar incidents were resolved:
```
suggest_solutions(incident_id="12345", max_solutions=3)
# OR for new incidents:
suggest_solutions(incident_title="Payment API errors", incident_description="Users getting 500 errors during checkout")
```
- **Input**: Either incident ID OR title/description text
- **Output**: Actionable solution recommendations with confidence scores and time estimates  
- **Use Case**: Get AI-powered suggestions based on successful past resolutions

#### How It Works
- **Text Similarity**: Uses TF-IDF vectorization and cosine similarity (scikit-learn)
- **Service Detection**: Automatically identifies affected services from incident text
- **Pattern Recognition**: Finds common error types, resolution patterns, and time estimates
- **Fallback Mode**: Works without ML libraries using keyword-based similarity
- **Solution Mining**: Extracts actionable steps from resolution summaries

#### Data Requirements
For optimal results, ensure your Rootly incidents have descriptive:
- **Titles**: Clear, specific incident descriptions
- **Summaries**: Detailed resolution steps when closing incidents
- **Service Tags**: Proper service identification

Example good resolution summary: `"Restarted auth-service, cleared Redis cache, and increased connection pool from 10 to 50"`

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

The server should now be ready to use with your MCP-compatible editor.

**For developers:** Additional testing tools are available in the `tests/` directory.

