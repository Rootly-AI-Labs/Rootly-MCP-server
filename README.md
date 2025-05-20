# Rootly MCP Server

An MCP server for [Rootly API](https://docs.rootly.com/api-reference/overview) that you can plug into your favorite MCP-compatible editors like Cursor, Windsurf, and Claude. Resolve production incidents in under a minute without leaving your IDE.
<br>
<br>

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
      "args": [
        "--from",
        "rootly-mcp-server",
        "rootly-mcp-server"
      ],
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

We limited the number of API paths exposed for 2 reasons
* Context size: because [Rootly's API](https://docs.rootly.com/api-reference/overview) is very rich in paths, AI agents can get overwhelmed and not perform simple actions properly. As of now we only expose the [/incidents](https://docs.rootly.com/api-reference/incidents/list-incidents) and [/incidents/{incident_id}/alerts](https://docs.rootly.com/api-reference/incidentevents/list-incident-events).
* Security: if you want to limit the type of information or actions that users can access through the MCP server

If you want to make more path available, edit the variable `allowed_paths` in `src/rootly_mcp_server/server.py`.

## Disclaimer
This project is a prototype and not intended for production use. If you have featured ideas or spotted some issues, feel free to submit a PR or open an issue.

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

