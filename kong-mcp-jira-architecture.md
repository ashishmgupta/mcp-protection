# Kong AI Gateway — Secure MCP Proxy for Jira Cloud

**Version:** Kong Gateway 3.12+ · decK 3.0 · Atlassian MCP Server (authv2)  
**Last updated:** 2026-05-27

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Step-by-Step Setup Guide](#3-step-by-step-setup-guide)
   - 3.1 [Subscribe to Kong Konnect on AWS Marketplace](#31-subscribe-to-kong-konnect-on-aws-marketplace)
   - 3.2 [Deploy Kong Gateway Data Plane on EC2](#32-deploy-kong-gateway-data-plane-on-ec2)
   - 3.3 [Connect EC2 Data Plane to Konnect Control Plane](#33-connect-ec2-data-plane-to-konnect-control-plane)
   - 3.4 [Create the Kong Service for Jira MCP](#34-create-the-kong-service-for-jira-mcp)
   - 3.5 [Create the Kong Route](#35-create-the-kong-route)
   - 3.6 [Configure the AI MCP Proxy Plugin (passthrough-listener)](#36-configure-the-ai-mcp-proxy-plugin-passthrough-listener)
   - 3.7 [Write and Configure the AI Firewall Pre-Function Plugin](#37-write-and-configure-the-ai-firewall-pre-function-plugin)
   - 3.8 [Configure Jira Cloud API Token Authentication in Kong](#38-configure-jira-cloud-api-token-authentication-in-kong)
4. [Complete decK YAML Configuration](#4-complete-deck-yaml-configuration)
5. [Python MCP Client Example](#5-python-mcp-client-example)
6. [Testing and Validation](#6-testing-and-validation)
7. [Security Considerations](#7-security-considerations)
8. [Troubleshooting](#8-troubleshooting)
9. [Reference Links](#9-reference-links)

---

## 1. Architecture Overview

### Request Flow

```mermaid
flowchart LR
    subgraph Client["MCP Client (Python SDK)"]
        P["Python App\nmcp.Client\nstreamablehttp_client"]
    end

    subgraph Kong["Kong AI Gateway (EC2 / Konnect Data Plane)"]
        direction TB
        KA["key-auth plugin\n(consumer authentication)"]
        PF["pre-function plugin\n(Lua — AI Firewall inspection)"]
        MCP["ai-mcp-proxy plugin\n(passthrough-listener mode)"]
        RT["request-transformer plugin\n(inject Jira Basic-Auth header)"]
        PR["prometheus plugin\n(MCP metrics)"]
    end

    subgraph Firewall["AI Firewall"]
        CAI["CalypsoAI / custom\nREST inspection endpoint\nPOST /v1/inspect"]
    end

    subgraph Jira["Jira Cloud (Atlassian)"]
        JMCP["Atlassian MCP Server\nhttps://mcp.atlassian.com\n/v1/mcp/authv2"]
        JAPI["Jira REST API\nyoursite.atlassian.net"]
    end

    P -->|"MCP JSON-RPC\n+ Kong API Key\n:8000/mcp"| KA
    KA --> PF
    PF -->|"POST body + metadata"| CAI
    CAI -->|"200 OK / 403 violation"| PF
    PF --> MCP
    MCP --> RT
    RT -->|"HTTPS + Authorization: Basic\n/v1/mcp/authv2"| JMCP
    JMCP --> JAPI
    PR -.->|"scrape /metrics"| Metrics["Prometheus / Grafana"]
```

### Component Roles

| Component | Role |
|---|---|
| **MCP Client (Python)** | Sends MCP JSON-RPC 2.0 requests to Kong's proxy endpoint using `streamablehttp` transport |
| **Kong key-auth plugin** | Authenticates Kong consumers (AI agents / humans) via API key in `apikey` header |
| **pre-function plugin (Lua)** | Intercepts every MCP request in the `access` phase and forwards it to the AI firewall; blocks on violation, logs audit trail |
| **ai-mcp-proxy (passthrough-listener)** | Transparently proxies incoming MCP protocol traffic to the upstream Jira MCP server without REST-to-MCP conversion overhead |
| **request-transformer plugin** | Injects the Jira `Authorization: Basic <base64>` header so clients never need to handle Jira credentials directly |
| **Jira MCP Server** | Atlassian-hosted remote MCP server (`https://mcp.atlassian.com/v1/mcp/authv2`) that translates MCP tool calls into Jira REST API calls |

---

## 2. Prerequisites

### Accounts and Access

| Requirement | Notes |
|---|---|
| **AWS account** | With IAM permissions to subscribe on Marketplace and launch EC2 instances |
| **Kong Konnect account** | Created during Marketplace subscription; choose at least the **Plus** tier for AI Gateway features |
| **Kong Gateway 3.12+** | Required for `ai-mcp-proxy` plugin; AI MCP features are Enterprise-tier |
| **Jira Cloud trial** | Free trial at [atlassian.net](https://www.atlassian.com/try/cloud/signup?bundle=jira-software); note your site URL (`yoursite.atlassian.net`) |
| **Jira API token** | Generated at [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens); scoped to read-only |
| **AI Firewall endpoint** | CalypsoAI, or any REST API accepting a JSON body and returning `{"allowed": true/false, "reason": "..."}` |

### Software Tools

```bash
# On your workstation
pip install mcp httpx          # Python MCP SDK + HTTP client
brew install deck               # Kong decK CLI (macOS)
# or: https://github.com/Kong/deck/releases
```

### Network Requirements

- EC2 security group: inbound TCP 8000 (proxy), 8001 (Admin API, restricted), 8100 (Status/metrics)
- EC2 outbound: HTTPS 443 to `mcp.atlassian.com`, to your Konnect control plane, and to the AI firewall

---

## 3. Step-by-Step Setup Guide

### 3.1 Subscribe to Kong Konnect on AWS Marketplace

1. Open the AWS Marketplace listing:
   - **Kong Konnect Plus** (10 Services, 100M requests/mo): [prodview-77nhc3l2cn5im](https://aws.amazon.com/marketplace/pp/prodview-77nhc3l2cn5im)
   - **Kong Konnect Enterprise** (unlimited): [prodview-7zds3oxx3ntjy](https://aws.amazon.com/marketplace/pp/prodview-7zds3oxx3ntjy)

2. Click **View purchase options** → select a 12-month contract or pay-as-you-go → click **Subscribe**.

3. Click **Set up your account** to be redirected to [cloud.konghq.com](https://cloud.konghq.com). Complete the Konnect registration — your subscription is linked to your AWS billing.

4. In Konnect, navigate to **Gateway Manager** and create a new **Control Plane** of type *Self-Managed Hybrid*. Name it (e.g., `jira-mcp-cp`).

> **Note:** The AI MCP Proxy plugin and AI metrics require the AI Gateway add-on; confirm it is enabled under **Organization → Subscriptions** in Konnect.

---

### 3.2 Deploy Kong Gateway Data Plane on EC2

1. Launch an EC2 instance:
   - **AMI:** Amazon Linux 2023 or Ubuntu 22.04 LTS
   - **Instance type:** `t3.medium` minimum (2 vCPU, 4 GB RAM) for development; `m5.xlarge` for production
   - **Security group:** TCP inbound 8000, 8100 from your client CIDR; no direct 443 inbound needed

2. Install Kong Gateway (version 3.12+):

```bash
# Amazon Linux 2023
sudo yum install -y https://download.konghq.com/gateway-3.x-amazonlinux-2023/Packages/k/kong-3.12.0.aws.amd64.rpm

# Ubuntu 22.04
curl -Lo kong.deb "https://packages.konghq.com/public/gateway-312/deb/ubuntu/pool/jammy/main/k/ko/kong_3.12.0/kong_3.12.0_amd64.deb"
sudo dpkg -i kong.deb
```

3. Verify the installation:

```bash
kong version
# Kong: 3.12.x
```

---

### 3.3 Connect EC2 Data Plane to Konnect Control Plane

1. In Konnect **Gateway Manager → your control plane**, click **+ New Runtime Instance** → choose **Linux**.

2. Click **Generate Certificate** — download the TLS certificate and private key pair.

3. Store credentials securely (AWS SSM is recommended for production):

```bash
aws ssm put-parameter \
  --name /kong/cluster_cert \
  --type SecureString \
  --value "$(cat cluster.crt)"

aws ssm put-parameter \
  --name /kong/cluster_cert_key \
  --type SecureString \
  --value "$(cat cluster.key)"
```

4. Copy the **Configuration Parameters** shown in Konnect (cluster endpoint, telemetry endpoint). Create `/etc/kong/kong.conf`:

```properties
# /etc/kong/kong.conf
role = data_plane
database = off
konnect_mode = on
cluster_mtls = pki
lua_ssl_trusted_certificate = system

# Replace with values from Konnect "Configuration Parameters" panel
cluster_control_plane = <YOUR_CP_NAME>.cp0.konghq.com:443
cluster_server_name   = <YOUR_CP_NAME>.cp0.konghq.com
cluster_telemetry_endpoint    = <YOUR_CP_NAME>.tp0.konghq.com:443
cluster_telemetry_server_name = <YOUR_CP_NAME>.tp0.konghq.com

cluster_cert     = /etc/kong/cluster.crt
cluster_cert_key = /etc/kong/cluster.key

proxy_listen  = 0.0.0.0:8000
status_listen = 0.0.0.0:8100
```

5. Copy the cert files and start Kong:

```bash
sudo cp cluster.crt /etc/kong/cluster.crt
sudo cp cluster.key /etc/kong/cluster.key
sudo kong start -c /etc/kong/kong.conf
```

6. In Konnect, the data plane node should appear as **Connected** within 30 seconds.

---

### 3.4 Create the Kong Service for Jira MCP

The Kong Service points to the Atlassian-hosted remote MCP server. The current recommended endpoint (using the `authv2` authentication scheme) is:

```
https://mcp.atlassian.com/v1/mcp/authv2
```

> **Important:** Atlassian's legacy SSE endpoint (`https://mcp.atlassian.com/v1/sse`) is **deprecated and will be unsupported after June 30, 2026**. Always use the `authv2` endpoint.

Via decK (see [Section 4](#4-complete-deck-yaml-configuration) for the full combined YAML), the service definition is:

```yaml
services:
  - name: jira-mcp-service
    protocol: https
    host: mcp.atlassian.com
    port: 443
    path: /v1/mcp/authv2
    connect_timeout: 10000
    read_timeout: 30000
    write_timeout: 30000
    retries: 3
```

---

### 3.5 Create the Kong Route

Attach a Route to the Service that the Python MCP client will connect to on Kong:

```yaml
routes:
  - name: jira-mcp-route
    service:
      name: jira-mcp-service
    paths:
      - /mcp
    strip_path: false
    protocols:
      - http
      - https
    methods:
      - POST
      - GET
```

---

### 3.6 Configure the AI MCP Proxy Plugin (passthrough-listener)

In `passthrough-listener` mode, the plugin accepts incoming MCP JSON-RPC traffic on the Route and proxies it verbatim to the upstream service. It does **not** perform REST-to-MCP conversion; Jira's MCP server handles the MCP protocol natively.

Key configuration parameters for this mode:

| Field | Value | Notes |
|---|---|---|
| `mode` | `passthrough-listener` | Required |
| `max_request_body_size` | `1048576` | 1 MB; increase for bulk operations |
| `logging.log_statistics` | `true` | Enables `kong_ai_mcp_*` Prometheus metrics |
| `logging.log_payloads` | `false` | Set `true` only for debug; payloads may contain PII |

```yaml
plugins:
  - name: ai-mcp-proxy
    route: jira-mcp-route
    config:
      mode: passthrough-listener
      max_request_body_size: 1048576
      logging:
        log_statistics: true
        log_payloads: false
```

---

### 3.7 Write and Configure the AI Firewall Pre-Function Plugin

The pre-function plugin runs arbitrary Lua code in the `access` phase — before the request reaches the ai-mcp-proxy plugin and is forwarded to Jira. It uses `resty.http` (bundled with Kong) to call the AI firewall REST endpoint synchronously.

#### Firewall API Contract

The Lua code assumes your AI firewall accepts:

```
POST /v1/inspect
Content-Type: application/json

{ "body": "<raw MCP JSON-RPC request>", "route": "<kong route name>", "consumer": "<kong consumer name>" }
```

And returns:

```json
{ "allowed": true }          // pass through
{ "allowed": false, "reason": "PII detected in tool arguments" }  // block
```

Adapt the request/response shapes to match your actual firewall (CalypsoAI, Prompt Security, etc.).

#### Lua Code

Save the following as `firewall_inspect.lua` for reference; it is inlined in the decK YAML in Section 4:

```lua
-- AI Firewall inspection pre-function
-- Runs in the access phase before ai-mcp-proxy forwards to Jira MCP.
-- Blocks the request and returns 403 if the firewall signals a violation.
-- Emits a structured audit log entry regardless of the verdict.

local http  = require("resty.http")
local cjson = require("cjson.safe")

-- Configuration (override via Kong environment variables in production)
local FIREWALL_URL     = os.getenv("KONG_FIREWALL_URL") or "https://firewall.example.com/v1/inspect"
local FIREWALL_API_KEY = os.getenv("KONG_FIREWALL_API_KEY") or ""
local TIMEOUT_MS       = 5000  -- milliseconds

-- Read the raw MCP request body
local raw_body = kong.request.get_raw_body()
if not raw_body or raw_body == "" then
  -- No body: allow (MCP initialize / ping messages have no payload to inspect)
  return
end

-- Collect metadata for the audit record
local consumer   = kong.client.get_consumer()
local consumer_id = consumer and consumer.username or "anonymous"
local route_name  = kong.router.get_route() and kong.router.get_route().name or "unknown"
local request_id  = kong.request.get_header("x-request-id") or ngx.var.request_id or ""

-- Build the inspection payload
local inspection_payload = cjson.encode({
  body     = raw_body,
  route    = route_name,
  consumer = consumer_id,
  request_id = request_id,
})

if not inspection_payload then
  kong.log.err("[firewall] failed to encode inspection payload — allowing request")
  return
end

-- Call the AI firewall
local httpc = http.new()
httpc:set_timeout(TIMEOUT_MS)

local res, err = httpc:request_uri(FIREWALL_URL, {
  method  = "POST",
  headers = {
    ["Content-Type"]  = "application/json",
    ["Authorization"] = "Bearer " .. FIREWALL_API_KEY,
    ["X-Request-Id"]  = request_id,
  },
  body = inspection_payload,
  ssl_verify = true,
})

-- Network / timeout error: fail-open (log and allow) to avoid blocking
-- legitimate traffic during firewall downtime. Change to fail-closed if required.
if err then
  kong.log.err("[firewall] inspection call failed: " .. tostring(err) .. " — failing open")
  return
end

-- Parse the firewall response
local verdict, decode_err = cjson.decode(res.body)
if decode_err or type(verdict) ~= "table" then
  kong.log.err("[firewall] could not parse verdict response — failing open")
  return
end

-- Emit structured audit log
kong.log.info(cjson.encode({
  event      = "mcp_firewall_audit",
  allowed    = verdict.allowed,
  reason     = verdict.reason or "",
  consumer   = consumer_id,
  route      = route_name,
  request_id = request_id,
  status     = res.status,
}))

-- Block if violation detected
if verdict.allowed == false then
  return kong.response.exit(403, cjson.encode({
    error   = "Request blocked by AI firewall",
    reason  = verdict.reason or "Policy violation",
    request_id = request_id,
  }), { ["Content-Type"] = "application/json" })
end
```

#### decK plugin config (inline)

```yaml
plugins:
  - name: pre-function
    route: jira-mcp-route
    config:
      access:
        - |
            local http  = require("resty.http")
            local cjson = require("cjson.safe")
            local FIREWALL_URL     = os.getenv("KONG_FIREWALL_URL") or "https://firewall.example.com/v1/inspect"
            local FIREWALL_API_KEY = os.getenv("KONG_FIREWALL_API_KEY") or ""
            -- (full Lua body as above)
```

> In production, use the decK environment variable interpolation syntax (`${{ env "DECK_FIREWALL_LUA" }}`) to load the Lua from an environment variable instead of inlining it in the YAML.

---

### 3.8 Configure Jira Cloud API Token Authentication in Kong

#### Create a Jira API Token

1. Log in to [id.atlassian.com](https://id.atlassian.com) with your Atlassian account.
2. Go to **Security → API tokens → Create API token**.
3. Name it `kong-mcp-readonly` and click **Create**. Copy the token immediately — it is not shown again.

> **Token scope:** The Atlassian MCP server honors the user's existing Jira access permissions. For a read-only integration, create a dedicated Atlassian account with only *Browse Projects* and *View Issue* permissions in Jira, and generate the API token for that account.

#### Enable API Token Auth on the Atlassian MCP Server

API token authentication must be explicitly enabled by an org admin:

1. In Jira, go to **Settings → Rovo → MCP Server**.
2. Enable **API Token Authentication**.

#### Encode Credentials and Inject via Kong

The Atlassian MCP server uses HTTP Basic Auth: `Authorization: Basic base64(email:token)`.

```bash
# Generate the base64 value on your workstation
echo -n "your-email@example.com:YOUR_API_TOKEN" | base64
# Example output: eW91ci1lbWFpbEBleGFtcGxlLmNvbTpZT1VSX0FQSV9UT0tFTg==
```

Store it as a Kong vault secret (recommended) or directly in the `request-transformer` plugin:

```yaml
plugins:
  - name: request-transformer
    route: jira-mcp-route
    config:
      add:
        headers:
          - "Authorization:Basic eW91ci1lbWFpbEBleGFtcGxlLmNvbTpZT1VSX0FQSV9UT0tFTg=="
      remove:
        headers:
          - Authorization   # strip any Authorization header the client sends
```

> **Vault alternative:** Use Kong Vaults with AWS Secrets Manager to avoid storing the secret in decK YAML. Reference: `{vault://aws/kong-jira-auth}`.

---

## 4. Complete decK YAML Configuration

Apply this configuration with `deck gateway sync kong.yaml --konnect-token $KONNECT_TOKEN`.

```yaml
_format_version: "3.0"

# ─────────────────────────────────────────────
# Service — upstream is the Atlassian MCP server
# ─────────────────────────────────────────────
services:
  - name: jira-mcp-service
    protocol: https
    host: mcp.atlassian.com
    port: 443
    path: /v1/mcp/authv2
    connect_timeout: 10000
    read_timeout: 30000
    write_timeout: 30000
    retries: 3

    routes:
      - name: jira-mcp-route
        paths:
          - /mcp
        strip_path: false
        protocols:
          - http
          - https
        methods:
          - POST
          - GET

# ─────────────────────────────────────────────
# Consumers — one API key per calling agent/user
# ─────────────────────────────────────────────
consumers:
  - username: python-agent-readonly
    tags:
      - env:prod
      - access:readonly
    keyauth_credentials:
      - key: "REPLACE_WITH_A_RANDOM_32_CHAR_KEY"

# ─────────────────────────────────────────────
# Plugins
# ─────────────────────────────────────────────
plugins:

  # 1. Consumer authentication — API key in header "apikey"
  - name: key-auth
    route: jira-mcp-route
    config:
      key_names:
        - apikey
      hide_credentials: true   # strip the key before forwarding to Jira

  # 2. AI Firewall — pre-function runs before ai-mcp-proxy
  - name: pre-function
    route: jira-mcp-route
    config:
      access:
        - |
            local http  = require("resty.http")
            local cjson = require("cjson.safe")

            local FIREWALL_URL     = os.getenv("KONG_FIREWALL_URL")     or "https://firewall.example.com/v1/inspect"
            local FIREWALL_API_KEY = os.getenv("KONG_FIREWALL_API_KEY") or ""
            local TIMEOUT_MS       = 5000

            local raw_body = kong.request.get_raw_body()
            if not raw_body or raw_body == "" then return end

            local consumer    = kong.client.get_consumer()
            local consumer_id = consumer and consumer.username or "anonymous"
            local route_name  = kong.router.get_route() and kong.router.get_route().name or "unknown"
            local request_id  = kong.request.get_header("x-request-id") or ngx.var.request_id or ""

            local payload = cjson.encode({
              body       = raw_body,
              route      = route_name,
              consumer   = consumer_id,
              request_id = request_id,
            })
            if not payload then
              kong.log.err("[firewall] encode failed — allowing")
              return
            end

            local httpc = http.new()
            httpc:set_timeout(TIMEOUT_MS)
            local res, err = httpc:request_uri(FIREWALL_URL, {
              method  = "POST",
              headers = {
                ["Content-Type"]  = "application/json",
                ["Authorization"] = "Bearer " .. FIREWALL_API_KEY,
                ["X-Request-Id"]  = request_id,
              },
              body       = payload,
              ssl_verify = true,
            })

            if err then
              kong.log.err("[firewall] call failed: " .. tostring(err) .. " — failing open")
              return
            end

            local verdict, decode_err = cjson.decode(res.body)
            if decode_err or type(verdict) ~= "table" then
              kong.log.err("[firewall] bad response — failing open")
              return
            end

            kong.log.info(cjson.encode({
              event      = "mcp_firewall_audit",
              allowed    = verdict.allowed,
              reason     = verdict.reason or "",
              consumer   = consumer_id,
              route      = route_name,
              request_id = request_id,
            }))

            if verdict.allowed == false then
              return kong.response.exit(403, cjson.encode({
                error      = "Request blocked by AI firewall",
                reason     = verdict.reason or "Policy violation",
                request_id = request_id,
              }), { ["Content-Type"] = "application/json" })
            end

  # 3. Jira auth — inject Basic Auth header for upstream Jira MCP server
  #    Generate the base64 value: echo -n "email:token" | base64
  - name: request-transformer
    route: jira-mcp-route
    config:
      remove:
        headers:
          - Authorization
      add:
        headers:
          - "Authorization:Basic REPLACE_WITH_BASE64_EMAIL_COLON_TOKEN"

  # 4. AI MCP Proxy — passthrough-listener mode
  - name: ai-mcp-proxy
    route: jira-mcp-route
    config:
      mode: passthrough-listener
      max_request_body_size: 1048576
      logging:
        log_statistics: true
        log_payloads: false

  # 5. Prometheus — enable MCP-specific metrics
  - name: prometheus
    route: jira-mcp-route
    config:
      status_code_metrics: true
      ai_metrics: true            # enables kong_ai_mcp_* histogram and counter metrics

  # 6. Rate limiting — protect against runaway agents
  - name: rate-limiting
    route: jira-mcp-route
    config:
      minute: 120
      policy: local
      limit_by: consumer
```

Apply and validate:

```bash
# Validate config locally
deck file validate kong.yaml

# Sync to Konnect
deck gateway sync kong.yaml \
  --konnect-token "$KONNECT_TOKEN" \
  --konnect-control-plane-name jira-mcp-cp

# Verify what was pushed
deck gateway diff kong.yaml \
  --konnect-token "$KONNECT_TOKEN" \
  --konnect-control-plane-name jira-mcp-cp
```

---

## 5. Python MCP Client Example

```python
"""
jira_mcp_client.py

Connects to the Kong AI Gateway MCP proxy endpoint and calls
read-only Jira MCP tools (list projects, search issues via JQL).

Requirements:
    pip install mcp httpx
"""

import asyncio
import json
import os
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# ── Configuration ──────────────────────────────────────────────────────────────
KONG_MCP_URL = os.environ.get("KONG_MCP_URL", "http://your-ec2-public-ip:8000/mcp")
KONG_API_KEY = os.environ.get("KONG_API_KEY", "REPLACE_WITH_A_RANDOM_32_CHAR_KEY")

# Optional: your Jira site, used to scope JQL searches
JIRA_SITE    = os.environ.get("JIRA_SITE", "yoursite.atlassian.net")


async def list_available_tools(session: ClientSession) -> None:
    """Print all MCP tools exposed by the Jira MCP server through Kong."""
    tools_result = await session.list_tools()
    print(f"\n── Available Jira MCP Tools ({len(tools_result.tools)}) ──")
    for tool in tools_result.tools:
        print(f"  • {tool.name}: {tool.description or '(no description)'}")


async def list_jira_projects(session: ClientSession) -> list[dict]:
    """List all Jira projects visible to the configured API token user."""
    result = await session.call_tool("jira_list_projects", arguments={})
    projects = json.loads(result.content[0].text) if result.content else []
    print(f"\n── Jira Projects ({len(projects)}) ──")
    for project in projects:
        print(f"  [{project.get('key')}] {project.get('name')}")
    return projects


async def search_jira_issues(session: ClientSession, jql: str, max_results: int = 10) -> list[dict]:
    """Search Jira issues using JQL."""
    result = await session.call_tool(
        "jira_search_issues",
        arguments={
            "jql": jql,
            "maxResults": max_results,
            "fields": ["summary", "status", "assignee", "priority"],
        },
    )
    issues = json.loads(result.content[0].text) if result.content else []
    print(f"\n── Issues matching '{jql}' ({len(issues)}) ──")
    for issue in issues:
        key     = issue.get("key", "?")
        summary = issue.get("fields", {}).get("summary", "")
        status  = issue.get("fields", {}).get("status", {}).get("name", "?")
        print(f"  {key}: [{status}] {summary}")
    return issues


async def main() -> None:
    print(f"Connecting to Kong MCP proxy at {KONG_MCP_URL} …")

    # streamablehttp_client uses the MCP Streamable HTTP transport (not deprecated SSE).
    # The Kong key-auth plugin reads the API key from the "apikey" header.
    async with streamablehttp_client(
        url=KONG_MCP_URL,
        headers={"apikey": KONG_API_KEY},
    ) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            print("MCP session initialized.")

            await list_available_tools(session)
            await list_jira_projects(session)

            # Example read-only JQL search — no write operations
            await search_jira_issues(
                session,
                jql=f"project IS NOT EMPTY AND status != Done ORDER BY updated DESC",
                max_results=10,
            )


if __name__ == "__main__":
    asyncio.run(main())
```

### Running the Client

```bash
export KONG_MCP_URL="http://<EC2_PUBLIC_IP>:8000/mcp"
export KONG_API_KEY="REPLACE_WITH_A_RANDOM_32_CHAR_KEY"
export JIRA_SITE="yoursite.atlassian.net"

python jira_mcp_client.py
```

---

## 6. Testing and Validation

### 6.1 Verify Traffic Is Flowing Through Kong

Send a raw MCP `tools/list` request to Kong and confirm Jira tools are returned:

```bash
curl -s -X POST http://<EC2_PUBLIC_IP>:8000/mcp \
  -H "Content-Type: application/json" \
  -H "apikey: REPLACE_WITH_A_RANDOM_32_CHAR_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | jq .
```

Expected: a JSON-RPC response with a `result.tools` array containing Jira tool names.

Check Kong access logs confirm the hit:

```bash
# On the EC2 instance
sudo tail -f /var/log/kong/access.log | grep "/mcp"
```

### 6.2 Confirm the Pre-Function Plugin Is Firing

Set `log_payloads: true` temporarily and examine Kong's error log for the `mcp_firewall_audit` JSON lines:

```bash
sudo tail -f /var/log/kong/error.log | grep mcp_firewall_audit
```

Expected log line (formatted for readability):

```json
{
  "event": "mcp_firewall_audit",
  "allowed": true,
  "reason": "",
  "consumer": "python-agent-readonly",
  "route": "jira-mcp-route",
  "request_id": "abc123"
}
```

To confirm blocking works, temporarily set your firewall to return `{"allowed": false, "reason": "test block"}` and verify Kong returns HTTP 403.

### 6.3 Benchmark Latency Overhead vs. Direct MCP Calls

```bash
# Install hyperfine (cross-platform benchmark tool)
brew install hyperfine

# Direct Jira MCP (baseline — requires Jira credentials on the client)
hyperfine --warmup 3 --runs 20 \
  'curl -s -X POST https://mcp.atlassian.com/v1/mcp/authv2 \
     -H "Authorization: Basic <BASE64>" \
     -H "Content-Type: application/json" \
     -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}"'

# Via Kong (includes key-auth, pre-function firewall call, ai-mcp-proxy)
hyperfine --warmup 3 --runs 20 \
  'curl -s -X POST http://<EC2_PUBLIC_IP>:8000/mcp \
     -H "apikey: REPLACE_WITH_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}"'
```

Typical overhead breakdown:

| Layer | Added Latency |
|---|---|
| Kong proxy overhead | 1–3 ms |
| key-auth plugin | <1 ms |
| pre-function + firewall HTTP call | 5–50 ms (network-dependent) |
| ai-mcp-proxy passthrough | 1–2 ms |
| **Total Kong overhead** | **~10–60 ms** (dominated by firewall RTT) |

### 6.4 Kong Prometheus Metrics for MCP

Scrape the metrics endpoint (Status API, recommended over Admin API):

```bash
curl -s http://<EC2_PUBLIC_IP>:8100/metrics | grep kong_ai_mcp
```

Key MCP metrics (enabled by `ai_metrics: true` in the Prometheus plugin):

| Metric | Type | Labels | Description |
|---|---|---|---|
| `kong_ai_mcp_latency_ms_bucket` | Histogram | `service`, `route`, `method`, `tool_name`, `le` | MCP server call latency in milliseconds |
| `kong_ai_mcp_response_body_size_bytes_bucket` | Histogram | `service`, `route`, `method`, `tool_name` | Response body size from Jira MCP |
| `kong_ai_mcp_error_total` | Counter | `service`, `route`, `method`, `tool_name`, `type` | Total MCP server errors by type |

Example PromQL queries (Grafana):

```promql
# p99 MCP latency
histogram_quantile(0.99,
  rate(kong_ai_mcp_latency_ms_bucket[5m]))

# MCP error rate per tool
rate(kong_ai_mcp_error_total[5m])

# Firewall blocks (HTTP 403 from Kong)
rate(kong_http_requests_total{status="403", route="jira-mcp-route"}[5m])
```

---

## 7. Security Considerations

### 7.1 Block Direct Access to Jira MCP Server

The architecture's security guarantee only holds if the Jira MCP endpoint cannot be reached directly, bypassing Kong.

**Option A — Atlassian IP Allowlist (recommended)**

Atlassian supports IP allowlisting at the org level:

1. In Jira, go to **Settings → Security → IP Allowlisting**.
2. Add **only** the Elastic IP of your Kong EC2 instance.
3. All other source IPs are denied.

**Option B — Kong-only API token**

Create a dedicated Atlassian account specifically for Kong with the minimum required permissions. Do not distribute its API token to any MCP client directly.

### 7.2 API Token Scoping (Read-Only vs Read-Write)

Atlassian does not currently support OAuth scopes on personal API tokens. Scope is controlled by **Jira project permissions** on the user account:

| Use Case | Jira Permission |
|---|---|
| Read-only (list projects, search issues) | *Browse Projects* only |
| Read + comment | *Browse Projects* + *Add Comments* |
| Full write | *Create Issues*, *Edit Issues*, *Delete Issues* |

Create a dedicated Jira service account and assign it the minimum required project role.

### 7.3 Consumer-Level ACLs with AI MCP Proxy

The `ai-mcp-proxy` plugin supports per-tool ACLs (Kong 3.13+ with `conversion-listener` or `listener` modes). For `passthrough-listener` mode, implement ACLs at the Kong consumer level using the built-in ACL plugin:

```yaml
# Define ACL groups
consumers:
  - username: agent-readonly
    tags: [access:readonly]
  - username: agent-readwrite
    tags: [access:readwrite]

consumer_groups:
  - name: mcp-readonly
  - name: mcp-readwrite

plugins:
  - name: acl
    route: jira-mcp-route
    config:
      allow:
        - mcp-readonly
        - mcp-readwrite
      hide_groups_header: true
```

Assign consumers to groups via the Konnect UI or Admin API:

```bash
curl -X POST http://localhost:8001/consumers/agent-readonly/acls \
  -d "group=mcp-readonly"
```

### 7.4 Additional Hardening

- **TLS everywhere:** Kong to Jira MCP is already HTTPS. Enforce HTTPS on the Kong proxy port by disabling HTTP in the Route protocols or adding an HTTPS-redirect plugin.
- **Secrets in vaults:** Never store the Jira API token or firewall API key in plain-text decK YAML. Use `{vault://aws/secret-name}` references.
- **Rotate credentials:** Rotate the Jira API token and Kong consumer API keys on a schedule (90 days maximum). Use AWS Secrets Manager rotation with Lambda.
- **Kong audit log:** Enable Kong's built-in audit logging in `kong.conf` (`audit_log = on`) to record all Admin API changes.

---

## 8. Troubleshooting

### Kong data plane not appearing as Connected in Konnect

| Symptom | Check |
|---|---|
| Node stuck in "Connecting" | Verify `cluster_control_plane` hostname resolves from EC2: `nslookup <cp>.cp0.konghq.com` |
| TLS handshake errors in Kong error log | Confirm `cluster_cert` and `cluster_cert_key` paths are correct and files are readable by the `kong` user |
| Firewall blocking outbound | EC2 security group must allow outbound TCP 443 to `*.konghq.com` |

```bash
# Inspect Kong error log
sudo tail -200 /var/log/kong/error.log | grep -E "error|failed|cluster"
```

---

### `ai-mcp-proxy` plugin not found / returns 404

- Confirm Kong version is **3.12+**: `kong version`
- Confirm the AI Gateway license is active in Konnect (**Organization → Subscriptions**)
- Check the plugin is installed: `kong plugins list | grep ai-mcp`

---

### Requests return HTTP 401 (key-auth)

- Confirm the `apikey` header is present and matches the consumer credential exactly
- Verify the consumer credential was synced: `deck gateway dump | grep keyauth`

---

### Requests return HTTP 403 (AI firewall blocking everything)

- Check `KONG_FIREWALL_URL` and `KONG_FIREWALL_API_KEY` environment variables are set on the EC2 instance
- Test the firewall endpoint directly from EC2:

```bash
curl -s -X POST "$KONG_FIREWALL_URL" \
  -H "Authorization: Bearer $KONG_FIREWALL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"body":"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}","route":"test","consumer":"test"}' \
  | jq .
```

- If the firewall is unreachable, the Lua code currently **fails open** (allows the request). Change the `return` after the `err` check to `return kong.response.exit(403, ...)` if you require fail-closed behavior.

---

### Jira MCP returns HTTP 401 (Jira auth)

- Verify the Base64-encoded `Authorization` header injected by `request-transformer` is correct:

```bash
echo "REPLACE_WITH_BASE64_VALUE" | base64 --decode
# Should output: your-email@example.com:YOUR_API_TOKEN
```

- Confirm API token authentication is enabled in Jira: **Settings → Rovo → MCP Server → API Token Authentication: ON**
- Confirm the Atlassian account has access to the target Jira projects

---

### High latency (>500 ms)

- Profile whether the latency is in the firewall call or in Jira MCP:

```bash
# Check Kong upstream latency header
curl -v http://<EC2>:8000/mcp ... 2>&1 | grep -i "x-kong-upstream-latency"
```

- `X-Kong-Upstream-Latency` reflects time spent in Jira MCP; `X-Kong-Proxy-Latency` reflects Kong + plugins overhead
- If firewall is the bottleneck, consider deploying it in the same AWS VPC and region as Kong to minimize RTT

---

### Prometheus metrics not appearing (`kong_ai_mcp_*`)

- Confirm `ai_metrics: true` is set in the Prometheus plugin config
- Confirm `logging.log_statistics: true` is set in the ai-mcp-proxy plugin config
- At least one successful MCP call must have been made (metrics appear after first data point)
- Scrape from the Status API port (8100), not the Admin API port (8001):

```bash
curl http://localhost:8100/metrics | grep mcp
```

---

## 9. Reference Links

| Resource | URL |
|---|---|
| Kong AI MCP Proxy Plugin Reference | https://developer.konghq.com/plugins/ai-mcp-proxy/reference/ |
| Kong AI MCP Proxy: passthrough-listener example | https://developer.konghq.com/plugins/ai-mcp-proxy/examples/passthrough-listener/ |
| Kong AI MCP Proxy: per-tool ACLs | https://developer.konghq.com/plugins/ai-mcp-proxy/examples/conversion-listener-tool-acls/ |
| Observe MCP Traffic (Prometheus) | https://developer.konghq.com/mcp/observe-traffic-for-mcp-tools/ |
| Kong Pre-Function Plugin | https://developer.konghq.com/plugins/pre-function/ |
| Kong Prometheus Plugin | https://developer.konghq.com/plugins/prometheus/ |
| decK 3.0 Upgrade Reference | https://developer.konghq.com/deck/reference/3.0-upgrade/ |
| Kong Konnect Plus on AWS Marketplace | https://aws.amazon.com/marketplace/pp/prodview-77nhc3l2cn5im |
| Kong Konnect Enterprise on AWS Marketplace | https://aws.amazon.com/marketplace/pp/prodview-7zds3oxx3ntjy |
| Konnect Hybrid Data Plane on ECS (blog) | https://konghq.com/blog/engineering/implementing-a-hybrid-kong-konnect-data-plane-in-amazon-ecs |
| Atlassian MCP Server — Getting Started | https://support.atlassian.com/atlassian-rovo-mcp-server/docs/getting-started-with-the-atlassian-remote-mcp-server/ |
| atlassian/atlassian-mcp-server (GitHub) | https://github.com/atlassian/atlassian-mcp-server |
| Jira API Token Management | https://id.atlassian.com/manage-profile/security/api-tokens |
| MCP Python SDK | https://github.com/modelcontextprotocol/python-sdk |
