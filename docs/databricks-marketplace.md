# Databricks Marketplace listing

Everything needed to list the hosted Rootly MCP server on
[Databricks Marketplace](https://marketplace.databricks.com/) as an
**MCP server** listing. Field names follow the Databricks provider docs:
[Create a listing](https://docs.databricks.com/aws/en/marketplace/create-listing#mcp-listings)
and [Become a provider](https://docs.databricks.com/aws/en/marketplace/become-provider).

## How Databricks uses the server

Installing a Marketplace MCP listing creates a Unity Catalog HTTP connection
plus an MCP service in the consumer's catalog and schema. Databricks then calls
the server from its serverless compute plane over **Streamable HTTP** and exposes
it to Supervisor Agent, AI Playground, and coding agents at
`https://<workspace-host>/ai-gateway/mcp-services/<catalog>.<schema>.<service>`.

The hosted server already meets these requirements:

| Requirement | Rootly |
| --- | --- |
| Streamable HTTP endpoint | `https://mcp.rootly.com/mcp` |
| OAuth discovery (RFC 9728) | `https://mcp.rootly.com/.well-known/oauth-protected-resource` points to `https://rootly.com` |
| Authorization server metadata (RFC 8414) | `https://rootly.com/.well-known/oauth-authorization-server`, also proxied at `https://mcp.rootly.com/.well-known/oauth-authorization-server` |
| Dynamic Client Registration (RFC 7591) | `https://rootly.com/oauth/register` accepts any HTTPS redirect URI, including Databricks' `https://<workspace-host>/login/oauth/http.html` |
| PKCE | S256 (required) |
| Bearer token fallback | `Authorization: Bearer <ROOTLY_API_TOKEN>` |
| 401 challenge | `WWW-Authenticate: Bearer resource_metadata="https://mcp.rootly.com/.well-known/oauth-protected-resource"` |

## 1. Provider onboarding (one time)

1. Apply through the Databricks Data Partner Program and pick **Databricks Data
   Provider** ([steps](https://docs.databricks.com/aws/en/marketplace/become-provider#apply)). If Rootly is already a Databricks
   partner, email `partnerops@databricks.com` instead.
2. Use a Databricks account on the Premium plan or above with a Unity
   Catalog-enabled workspace. That workspace hosts the Provider console.
3. Have an account admin grant the **Marketplace admin** role to whoever
   manages the listing.

## 2. Provider profile

| Field | Value |
| --- | --- |
| Provider name | Rootly |
| Logo | Rootly logo, light and dark variants |
| Description | Rootly is an AI-native incident management and on-call platform. Engineering teams use Rootly to detect, respond to, and learn from incidents across Slack, Microsoft Teams, and the web. |
| Organization website | https://rootly.com |
| Business email | _Internal address for Databricks notifications_ |
| Support email | support@rootly.com |
| Terms of service link | https://rootly.com/legal/terms |
| Privacy policy | https://rootly.com/legal/privacy |

## 3. Listing

### Basics

| Field | Value |
| --- | --- |
| Listing name | Rootly MCP Server |
| Product type | MCP server |
| Category | AI (add any incident, IT operations, or observability category Databricks offers) |
| Cost | Free (requires a Rootly account) |
| Short description | Manage incidents, alerts, and on-call schedules in Rootly from your Databricks agents. |

### Description

```markdown
Connect your Databricks agents to Rootly, the AI-native incident management and on-call platform. The Rootly MCP server lets Supervisor Agent, AI Playground, and your own agents read and act on live incident data with your existing Rootly permissions.

**What agents can do**

- Find, summarize, and update incidents, action items, and retrospectives
- Look up who is on call, shift history, and escalation policies
- Investigate alerts and alert groups, and link them to incidents
- Find similar past incidents and suggested solutions for a new incident
- Report on on-call load and incident metrics for a team or service

**Sample use cases**

- "Summarize the active SEV1 incidents and who is responding."
- "Who is on call for the payments service this weekend?"
- "Find incidents similar to INC-1234 and what fixed them."
- "Correlate last week's failed jobs with Rootly incidents for the same services."

**Getting started**

1. Click **Install**, choose a catalog and schema, and name the MCP service.
2. Open the MCP service page and click **Login** to sign in to Rootly. Each user signs in with their own Rootly account.
3. Use **Tool selection** to expose only the tools your agents need, for example read-only incident and on-call tools.
4. Add the MCP service to an agent in AI Playground or Supervisor Agent.

A Rootly account is required. Access follows each user's Rootly role and team permissions.
```

### Resources

| Field | Value |
| --- | --- |
| Documentation | https://docs.rootly.com/integrations/mcp-server#databricks |
| Privacy policy | https://rootly.com/legal/privacy |
| License | https://github.com/rootlyhq/rootly-mcp-server/blob/main/LICENSE (Apache 2.0) |
| Terms of service | https://rootly.com/legal/terms |
| Sample notebooks | Optional. None for the first version. |

### MCP server fields

| Field | Value |
| --- | --- |
| Authentication type | **Dynamic Client Registration** |
| Host | `https://mcp.rootly.com` |
| Port | `443` |
| Base path | `/mcp` |
| Tag | Leave blank. The hosted server is continuously deployed. |
| Token endpoint | Leave blank (discovered via DCR) |
| Authorization endpoint | Leave blank (discovered via DCR) |
| OAuth scope | Leave blank. Rootly grants its default scopes and enforces the user's own permissions. |

Alternative authentication types, if Databricks review asks for one:

- **Bearer token**: consumers paste a Rootly API key at install time. Good for
  unattended agents that should act as a single service identity. Same host,
  port, and base path.
- **OAuth User to Machine Per User**: authorization endpoint
  `https://rootly.com/oauth/authorize`, token endpoint
  `https://rootly.com/oauth/token`. Consumers would need to create their own
  Rootly OAuth app first, so DCR is the better default.

## 4. Pre-submission checks

Run before submitting and again before publishing.

```bash
# Protected resource metadata
curl -s https://mcp.rootly.com/.well-known/oauth-protected-resource

# Authorization server metadata must include registration_endpoint
curl -s https://rootly.com/.well-known/oauth-authorization-server | jq .registration_endpoint

# Unauthenticated calls return 401 with a resource_metadata challenge
curl -si -X POST https://mcp.rootly.com/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"check","version":"1"}}}' \
  | grep -i www-authenticate
```

End-to-end check in a Databricks workspace (needs Unity Catalog, `CREATE SERVICE`
and `CREATE CONNECTION` on a schema):

1. **Unity Gateway > MCPs > + MCP > Connect an existing MCP server**, URL
   `https://mcp.rootly.com/mcp`, authentication **Dynamic Client Registration**.
2. Click **Create & load tools**, then **Login** and sign in to Rootly.
3. Confirm tools load, then test a read-only tool such as `list_incidents` in
   AI Playground.
4. Repeat with **Bearer token** and a Rootly API key.
5. After the listing is in a private exchange, install it from Marketplace and
   repeat steps 2 and 3.

## 5. Known risks

- **DCR rate limit.** `POST https://rootly.com/oauth/register` allows
  10 registrations per hour per IP. Databricks registers one client per install
  from its own infrastructure, so many installs from shared egress IPs could get
  `429 too_many_requests`. Raise or scope this limit before a public launch.
- **Tool count.** The full hosted profile exposes about 257 tools. Some models
  cap tool definitions per request (for example 128), so agents may fail if every
  tool is enabled. The listing description tells consumers to use Databricks
  **Tool selection**. If review flags this, list `/mcp-codemode` instead (a few
  discovery tools plus `execute`), at the cost of per-tool governance in Unity
  Gateway.
- **Refresh tokens.** Rootly access tokens last one hour. Rootly only issues
  refresh tokens when the DCR request includes `refresh_token` in `grant_types`.
  If Databricks omits it, users must sign in again every hour. Confirm during the
  end-to-end check.
- **Network.** Databricks calls the server from serverless egress IPs.
  Make sure Cloudflare WAF and bot rules on `mcp.rootly.com` and `rootly.com/oauth/*`
  don't challenge those requests. Consumers with restricted serverless network
  policies must allow `mcp.rootly.com` and `rootly.com`.
