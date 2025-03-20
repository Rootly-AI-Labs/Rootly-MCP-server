
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

