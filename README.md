<!-- mcp-name: com.rootly/mcp-server -->
# Rootly MCP Server

[![PyPI version](https://badge.fury.io/py/rootly-mcp-server.svg)](https://pypi.org/project/rootly-mcp-server/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/rootly-mcp-server)](https://pypi.org/project/rootly-mcp-server/)
[![Python Version](https://img.shields.io/pypi/pyversions/rootly-mcp-server.svg)](https://pypi.org/project/rootly-mcp-server/)
[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=rootly&config=eyJ1cmwiOiJodHRwczovL21jcC5yb290bHkuY29tL3NzZSIsImhlYWRlcnMiOnsiQXV0aG9yaXphdGlvbiI6IkJlYXJlciA8WU9VUl9ST09UTFlfQVBJX1RPS0VOPiJ9fQ==)

An MCP server for the [Rootly API](https://docs.rootly.com/api-reference/overview) that integrates seamlessly with MCP-compatible editors like Cursor, Windsurf, and Claude. Resolve production incidents in under a minute without leaving your IDE.

![Demo GIF](https://raw.githubusercontent.com/Rootly-AI-Labs/Rootly-MCP-server/refs/heads/main/rootly-mcp-server-demo.gif)

## Prerequisites

- Python 3.12 or higher
- `uv` package manager
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
- [Rootly API token](https://docs.rootly.com/api-reference/overview#how-to-generate-an-api-key%3F) with appropriate permissions (see below)

### API Token Permissions

The MCP server requires a Rootly API token. Choose the appropriate token type based on your needs:

- **Global API Key** (Recommended): Full access to all entities across your Rootly instance. Required for organization-wide visibility across teams, schedules, and incidents.
- **Team API Key**: Team Admin permissions with full read/edit access to entities owned by that team. Suitable for team-specific workflows.
- **Personal API Key**: Inherits the permissions of the user who created it. Works for individual use cases but may have limited visibility.

For full functionality of tools like `get_oncall_handoff_summary`, `get_oncall_shift_metrics`, and organization-wide incident search, a **Global API Key** is recommended.

## Quick Start

The fastest way to get started is to connect to our hosted MCP server — no installation required.

### Hosted (Streamable HTTP, recommended)

```json
{
  "mcpServers": {
    "rootly": {
      "url": "https://mcp.rootly.com/mcp",
      "headers": {
        "Authorization": "Bearer <YOUR_ROOTLY_API_TOKEN>"
      }
    }
  }
}
```

### Hosted (SSE, backward compatible)

```json
{
  "mcpServers": {
    "rootly": {
      "url": "https://mcp.rootly.com/sse",
      "headers": {
        "Authorization": "Bearer <YOUR_ROOTLY_API_TOKEN>"
      }
    }
  }
}
```

For **Claude Code**, run:

```bash
claude mcp add rootly --transport streamable-http https://mcp.rootly.com/mcp \
  --header "Authorization: Bearer YOUR_ROOTLY_API_TOKEN"

# SSE fallback
claude mcp add rootly-sse --transport sse https://mcp.rootly.com/sse \
  --header "Authorization: Bearer YOUR_ROOTLY_API_TOKEN"
```

## Alternative Installation (Local)

If you prefer to run the MCP server locally, configure your editor with one of the options below. The package will be automatically downloaded and installed when you first open your editor.

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
        "rootly-mcp-server"
      ],
      "env": {
        "ROOTLY_API_TOKEN": "<YOUR_ROOTLY_API_TOKEN>"
      }
    }
  }
}
```

## Self-Hosted Transport Options

Rootly MCP supports both hosted HTTP transports:

- **Streamable HTTP** endpoint path: `/mcp`
- **SSE** endpoint path: `/sse`

Each server process runs one transport at a time. To support both `/mcp` and
`/sse` concurrently in production, run two instances behind your reverse proxy.

Example Docker run (Streamable HTTP):

```bash
docker run -p 8000:8000 \
  -e ROOTLY_TRANSPORT=streamable-http \
  -e ROOTLY_API_TOKEN=<YOUR_ROOTLY_API_TOKEN> \
  rootly-mcp-server
```

Example Docker run (SSE):

```bash
docker run -p 8000:8000 \
  -e ROOTLY_TRANSPORT=sse \
  -e ROOTLY_API_TOKEN=<YOUR_ROOTLY_API_TOKEN> \
  rootly-mcp-server
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
- **Intelligent Incident Analysis**: Smart tools that analyze historical incident data
  - **`find_related_incidents`**: Uses TF-IDF similarity analysis to find historically similar incidents
  - **`suggest_solutions`**: Mines past incident resolutions to recommend actionable solutions
- **MCP Resources**: Exposes incident and team data as structured resources for easy AI reference
- **Intelligent Pattern Recognition**: Automatically identifies services, error types, and resolution patterns
- **On-Call Health Integration**: Detects workload health risk in scheduled responders

## On-Call Health Integration

Rootly MCP integrates with [On-Call Health](https://oncallhealth.ai) to detect workload health risk in scheduled responders.

### Setup

Set the `ONCALLHEALTH_API_KEY` environment variable:

```json
{
  "mcpServers": {
    "rootly": {
      "command": "uvx",
      "args": ["rootly-mcp-server"],
      "env": {
        "ROOTLY_API_TOKEN": "your_rootly_token",
        "ONCALLHEALTH_API_KEY": "och_live_your_key"
      }
    }
  }
}
```

### Usage

```
check_oncall_health_risk(
    start_date="2026-02-09",
    end_date="2026-02-15"
)
```

Returns at-risk users who are scheduled, recommended safe replacements, and action summaries.

## Example Skills

Want to get started quickly? We provide pre-built Claude Code skills that showcase the full power of the Rootly MCP server:

### 🚨 [Rootly Incident Responder](examples/skills/rootly-incident-responder.md)

An AI-powered incident response specialist that:
- Analyzes production incidents with full context
- Finds similar historical incidents using ML-based similarity matching
- Suggests solutions based on past successful resolutions
- Coordinates with on-call teams across timezones
- Correlates incidents with recent code changes and deployments
- Creates action items and remediation plans
- Provides confidence scores and time estimates

**Quick Start:**
```bash
# Copy the skill to your project
mkdir -p .claude/skills
cp examples/skills/rootly-incident-responder.md .claude/skills/

# Then in Claude Code, invoke it:
# @rootly-incident-responder analyze incident #12345
```

This skill demonstrates a complete incident response workflow using Rootly's intelligent tools combined with GitHub integration for code correlation.

### On-Call Shift Metrics

Get on-call shift metrics for any time period, grouped by user, team, or schedule. Includes primary/secondary role tracking, shift counts, hours, and days on-call.

```
get_oncall_shift_metrics(
    start_date="2025-10-01",
    end_date="2025-10-31",
    group_by="user"
)
```

### On-Call Handoff Summary

Complete handoff: current/next on-call + incidents during shifts.

```python
# All on-call (any timezone)
get_oncall_handoff_summary(
    team_ids="team-1,team-2",
    timezone="America/Los_Angeles"
)

# Regional filter - only show APAC on-call during APAC business hours
get_oncall_handoff_summary(
    timezone="Asia/Tokyo",
    filter_by_region=True
)
```

Regional filtering shows only people on-call during business hours (9am-5pm) in the specified timezone.

Returns: `schedules` with `current_oncall`, `next_oncall`, and `shift_incidents`

### Shift Incidents

Incidents during a time period, with filtering by severity/status/tags.

```python
get_shift_incidents(
    start_time="2025-10-20T09:00:00Z",
    end_time="2025-10-20T17:00:00Z",
    severity="critical",  # optional
    status="resolved",    # optional
    tags="database,api"   # optional
)
```

Returns: `incidents` list + `summary` (counts, avg resolution time, grouping)


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for developer setup and guidelines.

## Play with it on Postman
[<img src="https://run.pstmn.io/button.svg" alt="Run In Postman" style="width: 128px; height: 32px;">](https://god.gw.postman.com/run-collection/45004446-1074ba3c-44fe-40e3-a932-af7c071b96eb?action=collection%2Ffork&source=rip_markdown&collection-url=entityId%3D45004446-1074ba3c-44fe-40e3-a932-af7c071b96eb%26entityType%3Dcollection%26workspaceId%3D4bec6e3c-50a0-4746-85f1-00a703c32f24)


## About Rootly AI Labs

This project was developed by [Rootly AI Labs](https://labs.rootly.ai/), where we're building the future of system reliability and operational excellence. As an open-source incubator, we share ideas, experiment, and rapidly prototype solutions that benefit the entire community.
![Rootly AI logo](https://github.com/Rootly-AI-Labs/EventOrOutage/raw/main/rootly-ai.png)
