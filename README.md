# ATI — Agent Tools Interface

**Secure CLI that gives AI agents access to external tools without exposing API keys.**

ATI does two things:

1. **Wraps any HTTP API** as a TOML manifest — define endpoints, auth, and parameters in a file, drop it in `manifests/`, and your agent can call it.
2. **Wraps any MCP server** the same way — bring your MCP server (stdio or HTTP), ATI auto-discovers its tools and makes them available as CLI commands. No hand-authored tool definitions needed.

One binary. One manifest directory. Every tool — REST or MCP — available as `ati call <tool> --arg value`.

---

## The Problem

AI agents running in sandboxes need to call external APIs. Today this works through:

**MCP stdio servers** — Every tool is an `npx` process speaking JSON-RPC over stdin/stdout. Agents spin up 5+ node processes for basic tasks. Process-per-provider doesn't scale.

**Python-wrapped HTTP tools** — Each tool is 100-300 lines of Python doing basically the same thing: parse args, check for API key, build request, format response.

**Both share the same security problem**: API keys live where the agent can read them (`printenv`, `cat /proc/self/environ`, `os.getenv()`).

## What ATI Does

ATI is a compiled Rust binary that:

1. **Makes HTTP requests** on behalf of the agent, injecting auth that the agent never sees
2. **Connects to MCP servers** (stdio or remote HTTP), discovers tools dynamically, and proxies calls — auth handled transparently
3. **Enforces scopes** — JWT-based per-tool access control with expiration and wildcard patterns
4. **Formats responses** — JSONPath extraction, table formatting, text summarization
5. **Discovers tools** — fuzzy search (`ati tools search`) and LLM-powered recommendations (`ati assist`)

From the agent's perspective:

```bash
# Call any tool — HTTP API or MCP server, doesn't matter
ati call web_search --query "Parcha AI compliance"
ati call github__search_repositories --query "rust mcp client"

# Find the right tool
ati tools search "sanctions screening"
ati assist "I need to check if a person is politically exposed"

# See everything available
ati tools list
```

No API keys. No process management. No JSON-RPC. Just CLI calls that return structured text.

---

## Quick Start: Give Any AI Agent Tools in 5 Minutes

ATI works with any agentic SDK that has a shell/bash tool. The pattern is always the same: give the agent shell access, tell it about `ati` commands in the system prompt, done. No custom tool wrappers.

### Claude Agent SDK (~30 lines)

```python
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    system_prompt="You have ATI on your PATH. Use `ati tools search` to find tools, "
                  "`ati tools info <name>` to inspect them, `ati call <tool> --key val` to execute.",
    model="claude-haiku-4-5",
    allowed_tools=["Bash"],
    env={"ATI_DIR": "/path/to/ati"},
)

async for message in query(prompt="Research quantum computing papers", options=options):
    print(message)
```

### Works with Every Major SDK

| SDK | Shell Mechanism | Lines of Code |
|-----|----------------|---------------|
| [Claude Agent SDK](examples/claude-agent-sdk/) | Built-in `Bash` tool | ~100 |
| [OpenAI Agents SDK](examples/openai-agents-sdk/) | `@function_tool` async shell | ~100 |
| [Google ADK](examples/google-adk/) | `run_shell()` function tool | ~100 |
| [LangChain](examples/langchain/) | `ShellTool` (zero-config) | ~80 |
| [Codex CLI](examples/codex/) | Built-in (Codex IS a shell agent) | ~30 |
| [Pi](examples/pi/) | Built-in `bashTool` | ~90 |

Every example uses the same free, no-auth tools (DeepWiki, arXiv, Crossref, Hacker News) so you can run them immediately with just an LLM API key.

See the [examples/](examples/) directory for complete, runnable code.

---

## MCP Server Integration

ATI is a full MCP client. Point it at any MCP server and it auto-discovers tools via the MCP protocol — no `[[tools]]` section needed in the manifest.

### How It Works

1. **Write a manifest** that says where the MCP server is and how to auth
2. ATI connects, calls `tools/list`, and registers discovered tools
3. Tools become available as `ati call <provider>__<tool_name>`
4. Auth credentials are injected transparently — the agent never sees them

### Stdio MCP Server (local subprocess)

```toml
# manifests/github-mcp.toml
[provider]
name = "github"
description = "GitHub via official MCP server"
handler = "mcp"
mcp_transport = "stdio"
mcp_command = "npx"
mcp_args = ["-y", "@modelcontextprotocol/server-github"]
auth_type = "none"
category = "developer-tools"

[provider.mcp_env]
GITHUB_PERSONAL_ACCESS_TOKEN = "${github_token}"  # Resolved from keyring
```

ATI spawns `npx -y @modelcontextprotocol/server-github` as a subprocess, pipes JSON-RPC over stdin/stdout, and injects the GitHub token into the subprocess environment from the encrypted keyring. The agent calls:

```bash
ati call github__search_repositories --query "rust mcp"
ati call github__read_file --owner anthropics --repo claude-code --path README.md
```

### Remote HTTP MCP Server (Streamable HTTP)

```toml
# manifests/linear-mcp.toml
[provider]
name = "linear"
description = "Linear project management via MCP"
handler = "mcp"
mcp_transport = "http"
mcp_url = "https://mcp.linear.app/mcp"
auth_type = "bearer"
auth_key_name = "linear_api_key"
category = "project-management"
```

ATI sends MCP JSON-RPC messages via HTTP POST. Handles both plain JSON and SSE (Server-Sent Events) responses per the MCP 2025-03-26 spec. Session management via `Mcp-Session-Id` header.

```bash
ati call linear__list_issues --teamId "TEAM-123"
```

### No-Auth MCP Server

Some MCP servers are free and require no authentication:

```toml
# manifests/deepwiki-mcp.toml
[provider]
name = "deepwiki"
description = "DeepWiki — AI-powered documentation for GitHub repositories"
handler = "mcp"
mcp_transport = "http"
mcp_url = "https://mcp.deepwiki.com/mcp"
auth_type = "none"
category = "documentation"
```

```bash
ati call deepwiki__read_wiki_structure --repoName "anthropics/claude-code"
ati call deepwiki__ask_question --repoName "anthropics/claude-code" --question "How does tool dispatch work?"
```

### MCP Manifest Reference

| Field | Required | Description |
|-------|----------|-------------|
| `handler` | Yes | Must be `"mcp"` |
| `mcp_transport` | Yes | `"stdio"` or `"http"` |
| `mcp_command` | stdio | Command to launch (e.g., `"npx"`) |
| `mcp_args` | stdio | Arguments array (e.g., `["-y", "@modelcontextprotocol/server-github"]`) |
| `mcp_url` | http | Remote MCP endpoint URL |
| `mcp_env` | No | Environment variables for stdio subprocess (supports `${keyring_key}` syntax) |
| `auth_type` | No | Auth for HTTP transport: `bearer`, `header`, `basic`, `none` |
| `auth_key_name` | No | Key name in keyring for auth |
| `category` | No | Tool category for search/filtering |

### What Gets Discovered

When ATI connects to an MCP server, `tools/list` returns tool definitions including:
- **Name** — becomes `<provider>__<tool_name>` in ATI
- **Description** — shown in `ati tools list` and `ati tools info`
- **Input Schema** — full JSON Schema with parameters, types, required fields, defaults

All of this is surfaced through `ati tools list`, `ati tools info`, `ati tools search`, and `ati assist` — MCP tools are first-class citizens alongside HTTP tools.

### MCP in Proxy Mode

In proxy mode (`ATI_PROXY_URL` set), MCP servers run on the **proxy host**, not in the sandbox. The proxy:

1. Receives MCP JSON-RPC from the sandbox via `POST /mcp`
2. Routes to the correct real MCP backend by tool name
3. For stdio: manages the subprocess on the proxy host with credentials in env vars
4. For HTTP: injects auth headers from the keyring
5. Returns the response to the sandbox

```
Sandbox (zero secrets)              ATI Proxy (holds secrets)           Real MCP Server
──────────────────────              ─────────────────────────           ───────────────
ati call github__read_file
  → POST /mcp                       receives JSON-RPC
  { "method": "tools/call",         routes to "github" backend
    "params": {                      injects: GITHUB_TOKEN env
      "name": "read_file",          spawns/reuses subprocess
      "arguments": {...}             forwards → stdio pipe
    }}                               ← gets response
  ← returns to agent                returns JSON-RPC
```

The sandbox ATI never touches credentials. It just speaks MCP protocol to the proxy URL.

---

## Adding HTTP API Tools

For REST APIs that don't speak MCP, define tools manually in TOML. Drop the file in `manifests/` and it's immediately available via `ati call`.

### Minimal Example — Free API (no auth)

```toml
# manifests/pubmed.toml
[provider]
name = "pubmed"
description = "PubMed medical literature search"
base_url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils"
auth_type = "none"

[[tools]]
name = "medical_search"
description = "Search PubMed for medical research articles"
endpoint = "/esearch.fcgi"
method = "GET"

[tools.input_schema]
type = "object"
required = ["term"]

[tools.input_schema.properties.term]
type = "string"
description = "Search term (e.g. 'CRISPR gene therapy')"

[tools.input_schema.properties.retmax]
type = "integer"
description = "Max results"
default = 20

[tools.response]
extract = "$.esearchresult"
format = "json"
```

```bash
ati call medical_search --term "CRISPR gene therapy" --retmax 5
```

### Bearer Auth

```toml
[provider]
name = "my_api"
base_url = "https://api.example.com/v1"
auth_type = "bearer"
auth_key_name = "my_api_key"         # Key name in keyring.enc

[[tools]]
name = "my_search"
description = "Search my API"
endpoint = "/search"
method = "POST"

[tools.input_schema]
type = "object"
required = ["query"]

[tools.input_schema.properties.query]
type = "string"
description = "Search query"
```

### Auth Type Summary

| Type | Behavior | Provider Fields |
|------|----------|-----------------|
| `bearer` | `Authorization: Bearer <key>` | `auth_key_name` |
| `header` | `<header>: [prefix]<key>` | `auth_key_name`, `auth_header_name`, `auth_value_prefix` (optional) |
| `query` | `?<param>=<key>` | `auth_key_name`, `auth_query_name` |
| `basic` | HTTP Basic auth | `auth_key_name` |
| `oauth2` | Client credentials → cached Bearer token | `auth_key_name`, `auth_secret_name`, `oauth2_token_url` |
| `none` | No auth | (none) |

### Additional HTTP Provider Features

- **Custom headers**: `[provider.extra_headers]` — e.g., `X-Goog-FieldMask = "..."`
- **Custom handler**: `handler = "xai"` — routes to a custom Rust handler instead of generic HTTP
- **Default arguments**: Set defaults in `[tools.input_schema.properties.*.default]`
- **Internal providers**: `internal = true` — hidden from `ati tools list`
- **Response formatting**: JSONPath extraction, table/json/text output via `[tools.response]`

See [`manifests/example.toml`](manifests/example.toml) for every field annotated.

---

## OpenAPI Handler

Instead of hand-writing `[[tools]]` blocks, point ATI at an OpenAPI 3.0 spec and it auto-discovers every operation as a tool. One manifest goes from 100+ lines to ~8.

### Before vs After

**Before — hand-written HTTP manifest (per tool):**
```toml
[provider]
name = "clinicaltrials"
base_url = "https://clinicaltrials.gov/api/v2"
auth_type = "none"

[[tools]]
name = "search_studies"
endpoint = "/studies"
method = "GET"
[tools.input_schema]
type = "object"
required = ["query"]
[tools.input_schema.properties.query]
type = "string"

[[tools]]
name = "get_study"
endpoint = "/studies/{nctId}"
method = "GET"
[tools.input_schema]
type = "object"
required = ["nctId"]
[tools.input_schema.properties.nctId]
type = "string"

# ... repeat for every endpoint ...
```

**After — OpenAPI manifest (all tools auto-discovered):**
```toml
[provider]
name = "clinicaltrials"
description = "NIH ClinicalTrials.gov — search and retrieve clinical study data"
handler = "openapi"
base_url = "https://clinicaltrials.gov/api/v2"
openapi_spec = "clinicaltrials.json"
auth_type = "none"
category = "medical"
```

Both produce the same tools. The OpenAPI version discovers ~40 operations from the spec automatically.

### Getting Started

**1. Inspect a spec** (no changes, just preview):
```bash
# From a URL
ati openapi inspect https://petstore3.swagger.io/api/v3/openapi.json

# From a local file
ati openapi inspect ./my-api-spec.json

# Filter by tag
ati openapi inspect ./finnhub.json --include-tags "Stock Price"
```

Output:
```
OpenAPI: ClinicalTrials.gov API v2.0.3
  Access to ClinicalTrials.gov public data
Base URL: https://clinicaltrials.gov/api/v2
Auth: none
Operations (12):
  TAG: Studies (8 operations)
    listStudies          GET    /studies              Returns data of studies
    getStudy             GET    /studies/{nctId}      Returns data of a single study
    ...
  TAG: Stats (4 operations)
    listStudyFieldStats  GET    /stats/field/values   Study field value statistics
    ...
```

**2. Import a spec** (downloads spec + generates manifest):
```bash
# Import from URL — creates ~/.ati/specs/myapi.json + ~/.ati/manifests/myapi.toml
ati openapi import https://api.example.com/openapi.json --name myapi

# Import with auth
ati openapi import ./spec.json --name myapi --auth-key myapi_api_key

# Import only specific tags
ati openapi import ./spec.json --name myapi --include-tags "v1,public"

# Preview without saving
ati openapi import ./spec.json --name myapi --dry-run
```

### Manifest Fields

| Field | Required | Description |
|-------|----------|-------------|
| `handler` | Yes | Must be `"openapi"` |
| `openapi_spec` | Yes | Filename in `~/.ati/specs/` (e.g., `"finnhub.json"`) |
| `base_url` | Yes | API base URL |
| `auth_type` | No | Same auth types as HTTP tools (`bearer`, `query`, etc.) |
| `openapi_include_tags` | No | Only include operations with these tags |
| `openapi_exclude_tags` | No | Exclude operations with these tags |
| `openapi_include_operations` | No | Whitelist by operationId |
| `openapi_exclude_operations` | No | Blacklist by operationId |
| `openapi_max_operations` | No | Cap total tools (for huge APIs) |
| `openapi_overrides` | No | Per-operation tweaks (description, hints, response_extract) |

### Examples

**Large API with tag filtering:**
```toml
[provider]
name = "middesk"
description = "Middesk business identity verification"
handler = "openapi"
base_url = "https://api.middesk.com/v2"
openapi_spec = "middesk.json"
auth_type = "bearer"
auth_key_name = "middesk_api_key"
openapi_include_tags = ["subpackage_businesses"]  # Only business endpoints
```

**Huge API with operation cap:**
```toml
[provider]
name = "finnhub"
description = "Real-time stock market data"
handler = "openapi"
base_url = "https://finnhub.io/api/v1"
openapi_spec = "finnhub.json"
auth_type = "query"
auth_key_name = "finnhub_api_key"
auth_query_name = "token"
openapi_max_operations = 50  # Finnhub has 110 paths — cap at 50
```

**Per-operation overrides:**
```toml
[openapi_overrides.getQuote]
hint = "Get real-time stock price"
tags = ["stocks", "pricing"]
response_extract = "$.c"
```

### How It Works

1. ATI reads the spec from `~/.ati/specs/<openapi_spec>`
2. Parses all paths and operations (GET, POST, PUT, DELETE, PATCH)
3. Extracts parameters with location metadata (`path`, `query`, `header`, `body`)
4. Applies tag/operation filters and max_operations cap
5. Registers each operation as a tool with auto-generated name, description, and JSON Schema
6. At call time, parameters are routed to the correct location (URL path, query string, headers, or JSON body)

### Specs Directory

OpenAPI specs live in `~/.ati/specs/`. Created automatically by `ati openapi import`, or place specs manually:

```
~/.ati/specs/
├── clinicaltrials.json    # Free NIH API (no auth)
├── finnhub.json           # Stock market data (query auth)
├── crossref.json          # Academic metadata (no auth)
├── sec_edgar.json         # SEC filings (no auth)
├── semantic_scholar.json  # Research papers (no auth)
├── middesk.json           # Business verification (bearer auth)
└── ... (17 included specs for public APIs)
```

### Spec Compatibility

ATI uses the `openapiv3` crate which parses **OAS 3.0.x**. For other formats:
- **Swagger 2.0** — Convert to OAS 3.0 first (use swagger-converter or manual conversion)
- **OAS 3.1** — Downgrade type arrays: `"type": ["string", "null"]` → `"type": "string", "nullable": true`

---

## Tool Discovery

### `ati tools search` — Offline Fuzzy Search

Find tools without an LLM call. Scores matches across name, description, provider, category, tags, and hints:

```bash
$ ati tools search "sanctions"
PROVIDER           TOOL                           DESCRIPTION
complyadvantage    ca_person_sanctions_search      Search sanctions lists for individuals
complyadvantage    ca_business_sanctions_search    Search sanctions lists for businesses

$ ati tools search "stock price"
PROVIDER    TOOL              DESCRIPTION
finnhub     finnhub_quote     Get real-time stock quote
```

Works in both local and proxy mode. Searches all tools — MCP-discovered and TOML-defined alike.

### `ati tools list` — Full Catalog

```bash
# All tools
ati tools list

# Filter by provider
ati tools list --provider github

# JSON output (for programmatic use)
ati --output json tools list
```

MCP-discovered tools show up with their auto-discovered descriptions and schemas.

### `ati tools info` — Deep Inspection

```bash
$ ati tools info github__search_repositories
Tool:        github__search_repositories
Provider:    github (GitHub via official MCP server)
Handler:     mcp
Transport:   MCP (stdio)
Description: Search for GitHub repositories
Category:    developer-tools

Input Schema:
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Search query"
    }
  },
  "required": ["query"]
}

Usage:
  ati call github__search_repositories --query <query>
```

Shows handler type, transport, category, tags, hints, examples, and auto-generated usage — everything an agent or operator needs.

### `ati tools providers` — Provider Overview

```bash
$ ati tools providers
PROVIDER           DESCRIPTION                                          BASE_URL
finnhub            Real-time stock market data                          https://finnhub.io/api/v1
complyadvantage    Sanctions and PEP screening                          https://api.complyadvantage.com
github             GitHub via official MCP server
linear             Linear project management via MCP
deepwiki           DeepWiki — AI-powered documentation for GitHub repos
```

### `ati assist` — LLM-Powered Discovery

Uses an LLM to recommend tools and generate exact `ati call` commands:

```bash
$ ati assist "How do I screen a person for sanctions?"
1. **ca_person_sanctions_search** — Search sanctions lists for individuals
   ```
   ati call ca_person_sanctions_search --search_term "Person Name" --fuzziness 0.6
   ```

2. **ca_person_pep_search** — Search for PEP matches
   ```
   ati call ca_person_pep_search --search_term "Person Name" --fuzziness 0.6
   ```
```

---

## Execution Modes

ATI supports two modes. The agent doesn't know or care which is active — `ati call` auto-detects based on the `ATI_PROXY_URL` environment variable.

### Local Mode (default)

Self-contained. The orchestrator provisions encrypted credentials into the sandbox. ATI decrypts, injects auth, and calls APIs directly.

```
┌─────────────────────────────────────────────────────┐
│  Sandbox                                             │
│                                                      │
│  ┌──────────┐   ati call my_tool       ┌──────────┐ │
│  │  Agent    │ ────────────────────────▶│   ATI    │ │
│  │ (Claude)  │                          │  binary  │ │
│  │           │◀────────────────────────│          │ │
│  └──────────┘   structured text result  └────┬─────┘ │
│                                              │       │
│                    ┌─────────────────────────┘       │
│                    │  reads encrypted keyring         │
│                    │  injects auth headers            │
│                    │  manages MCP subprocesses        │
│                    │  enforces scopes                 │
│                    ▼                                  │
│              ┌───────────┐      HTTPS       ┌──────┐│
│              │keyring.enc│  ──────────────▶  │ API  ││
│              └───────────┘                   └──────┘│
│                                                      │
│  /run/ati/.key  (session key, deleted after read)    │
│  ~/.ati/manifests/*.toml  (your tool definitions)    │
│  ATI_SESSION_TOKEN  (JWT with scopes + expiry)       │
└─────────────────────────────────────────────────────┘
```

### Proxy Mode (opt-in via `ATI_PROXY_URL`)

Zero credentials in the sandbox. ATI forwards all calls — HTTP and MCP — to an external proxy server that holds the real API keys and manages MCP server subprocesses.

```
┌─────────────────────────────────────────────────────┐
│  Sandbox                                             │
│                                                      │
│  ┌──────────┐   ati call my_tool       ┌──────────┐ │
│  │  Agent    │ ────────────────────────▶│   ATI    │ │
│  │ (Claude)  │                          │  binary  │ │
│  │           │◀────────────────────────│          │ │
│  └──────────┘   structured text result  └────┬─────┘ │
│                                              │       │
│              No keyring.enc needed            │       │
│              No session key needed            │       │
│              No MCP subprocesses              │       │
│              Only manifests + scopes          │       │
│                                              │       │
└──────────────────────────────────────────────│───────┘
                                               │
                                          POST /call (HTTP tools)
                                          POST /mcp  (MCP tools)
                                               │
                                               ▼
┌─────────────────────────────────────────────────────┐
│  Proxy Server (ati proxy)                            │
│                                                      │
│  Holds real API keys (keyring.enc or --env-keys)     │
│  Manages MCP server subprocesses (stdio)             │
│  Connects to remote MCP servers (HTTP)               │
│  Injects auth, routes by tool name                   │
└─────────────────────────────────────────────────────┘
```

### Mode Comparison

| Aspect | Local Mode | Proxy Mode |
|--------|-----------|------------|
| **Credentials in sandbox** | Yes (encrypted) | No |
| **MCP subprocesses** | In sandbox | On proxy host |
| **External dependency** | None | Proxy server |
| **Latency** | Direct calls | Extra hop through proxy |
| **Setup** | Keyring + session key | `ATI_PROXY_URL` env var |
| **Key exposure risk** | Keys in memory (mlock'd) | Keys never enter sandbox |

### Switching Modes

```bash
# Local mode (default)
ati call my_tool --arg value

# Proxy mode — set the env var
export ATI_PROXY_URL=http://proxy-host:8090
ati call my_tool --arg value
```

The agent never needs to change its commands. Mode selection is purely an infrastructure decision.

---

## CLI Reference

```
ati — Agent Tools Interface

USAGE:
    ati [OPTIONS] <COMMAND>

COMMANDS:
    init       Initialize ATI directory structure (~/.ati/)
    keys       Manage API keys in the encrypted keyring
    call       Execute a tool by name
    tools      List, inspect, search, and discover tools
    mcp        Add, list, and remove MCP provider manifests
    openapi    Inspect and import OpenAPI specs as manifests
    skills     Manage skill files (methodology docs for agents)
    assist     LLM-powered tool discovery
    auth       Authentication and scope information
    token      JWT token management (keygen, issue, inspect, validate)
    proxy      Run ATI as a proxy server (holds keys, serves sandbox agents)
    version    Print version information

OPTIONS:
    --output <FORMAT>   Output format: json, table, text [default: text]
    --verbose           Enable debug output
```

### Getting Started

```bash
# Initialize ATI directory
ati init

# Add API keys to the encrypted keyring
ati keys set github_token ghp_abc123
ati keys set serpapi_api_key your-key-here

# Add an MCP provider (generates TOML manifest automatically)
ati mcp add github --transport stdio \
  --command npx --args "-y" --args "@modelcontextprotocol/server-github" \
  --env 'GITHUB_PERSONAL_ACCESS_TOKEN=${github_token}'

# Add an HTTP MCP provider
ati mcp add serpapi --transport http \
  --url 'https://mcp.serpapi.com/${serpapi_api_key}/mcp'

# Import an OpenAPI spec
ati openapi import https://api.example.com/openapi.json --name myapi

# List everything available
ati tools list
```

### Common Usage

```bash
# Call an HTTP API tool
ati call web_search --query "Parcha AI" --max_results 5

# Call an MCP tool (provider prefix + tool name)
ati call github__search_repositories --query "rust mcp"

# List all tools (HTTP + MCP)
ati tools list

# Filter by provider
ati tools list --provider github

# Inspect a tool (shows schema, auth type, transport, category)
ati tools info github__search_repositories

# Fuzzy search across all tools
ati tools search "code repository"

# List providers
ati tools providers

# Check auth status and scope expiry
ati auth status

# LLM-powered discovery
ati assist "I need to look up a company's SEC filings"
```

### MCP Provider Management

```bash
# Add HTTP transport MCP server
ati mcp add parallel --transport http \
  --url "https://search-mcp.parallel.ai/mcp" \
  --auth bearer --auth-key parallel_api_key

# Add stdio transport MCP server
ati mcp add github --transport stdio \
  --command npx --args "-y" --args "@modelcontextprotocol/server-github" \
  --env 'GITHUB_PERSONAL_ACCESS_TOKEN=${github_token}'

# List configured MCP providers
ati mcp list

# Remove an MCP provider
ati mcp remove parallel
```

### JWT Token Management

```bash
# Generate a signing key
ati token keygen ES256    # Asymmetric (recommended for production)
ati token keygen HS256    # Symmetric (simpler, single-machine setups)

# Issue a scoped session token
ati token issue --sub agent-7 --scope "tool:web_search tool:github__* help" --ttl 3600

# Inspect a token (decode without verification)
ati token inspect $ATI_SESSION_TOKEN

# Validate a token (full signature + expiry check)
ati token validate $ATI_SESSION_TOKEN --secret $ATI_JWT_SECRET
```

### Output Formats

```bash
# Default: human-readable text
ati call finnhub_quote --symbol AAPL

# JSON for programmatic use
ati --output json call finnhub_quote --symbol AAPL

# Table for tabular data
ati --output table call getIncomeStatement --ticker AAPL --limit 3
```

### Proxy Server

```bash
# Start with encrypted keyring
ati proxy --port 8090 --ati-dir ~/.ati

# Start with API keys from environment variables
ati proxy --port 8090 --ati-dir ~/.ati --env-keys

# With verbose logging
ati --verbose proxy --port 8090
```

Endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check — tool/provider/skill counts, MCP server info, version |
| `/call` | POST | Execute an HTTP tool — `{tool_name, args}` → `{result, error}` |
| `/mcp` | POST | MCP JSON-RPC proxy — `{jsonrpc, method, params}` → JSON-RPC response |
| `/help` | POST | LLM-powered tool discovery — `{query}` → `{content, error}` |
| `/skills` | GET | List skills (supports `?category=X&provider=Y&tool=Z&search=Q`) |
| `/skills/{name}` | GET | Show skill content (supports `?meta=true&refs=true`) |
| `/skills/resolve` | POST | Resolve skills for given scopes |

The `/mcp` endpoint speaks standard MCP JSON-RPC. Sandbox clients can point any MCP-compatible client at `{ATI_PROXY_URL}/mcp` and get the full aggregated tool catalog from all configured backends.

## Skills

Skills are methodology documents — structured instructions that tell AI agents *how* to approach a task. They're not tools (no code, no execution) — they provide context about *when* to use which tools, *how* to interpret results, and *what* workflow to follow.

Skills complement tools: tools provide **data access**, skills provide **methodology**.

### Structure

Each skill lives in `~/.ati/skills/<name>/` with two files:

```
~/.ati/skills/compliance-screening/
├── skill.toml      # Metadata, tool bindings, keywords
├── SKILL.md        # The methodology document itself
└── references/     # Optional supporting docs
```

### skill.toml

```toml
[skill]
name = "compliance-screening"
version = "1.0.0"
description = "Screen businesses and individuals against sanctions, PEP, and adverse media"
author = "your-org"

# Tool bindings — auto-load this skill when these tools are in scope
tools = ["ca_business_sanctions_search", "ca_person_sanctions_search"]

# Provider bindings — auto-load when this provider is available
providers = ["complyadvantage"]

# Category bindings — auto-load for this category
categories = ["compliance"]

# Discovery metadata
keywords = ["sanctions", "OFAC", "AML", "PEP", "KYB", "KYC"]
hint = "Use when screening entities against global sanctions and PEP lists"

# Dependencies — auto-load these skills alongside this one
depends_on = []
suggests = ["tin-verification"]
```

### SKILL.md

Pure Markdown. Write it like you'd brief a junior analyst:

```markdown
# Compliance Screening

## Tools Available
| Tool | Entity | Use When |
|------|--------|----------|
| ca_business_sanctions_search | Business | Always for KYB |
| ca_person_sanctions_search | Person | Always for KYC |
| ca_person_pep_search | Person | Due diligence |

## Standard Screening Order
1. `ca_business_sanctions_search` — check the company
2. `ca_adverse_media_search` — check for negative news
3. For each beneficial owner:
   - `ca_person_sanctions_search`
   - `ca_person_pep_search`

## Interpreting Results
| match_status | Meaning | Action |
|-------------|---------|--------|
| no_match | Clear | Document the check |
| potential_match | Possible hit | Review required |
| true_positive | Confirmed | Escalate |
```

### CLI Commands

```bash
# List all skills
ati skills list
ati skills list --category finance
ati skills list --provider finnhub

# Read a skill's methodology
ati skills show compliance-screening
ati skills show compliance-screening --meta   # Show skill.toml instead
ati skills show compliance-screening --refs   # Include reference files

# Search skills by keywords
ati skills search "sanctions screening"

# Show structured metadata
ati skills info compliance-screening

# Create a new skill scaffold
ati skills init my-skill
ati skills init my-skill --provider finnhub --tools getQuote,getMetrics

# Validate a skill's configuration
ati skills validate my-skill
ati skills validate my-skill --check-tools  # Verify tools exist in manifests

# Install/remove skills
ati skills install ./my-skill/
ati skills install ./skills-collection/ --all
ati skills remove my-skill

# See which skills auto-load for current scopes
ati skills resolve
```

### Scope-Driven Resolution

Skills auto-activate based on the agent's tool scope. When an agent has access to `ca_person_sanctions_search`, ATI automatically loads the `compliance-screening` skill because its `tools` binding includes that tool.

Resolution order:
1. Check `tools` bindings — exact tool name match
2. Check `providers` bindings — provider name match
3. Check `categories` bindings — category match
4. Load `depends_on` transitively (skill A depends on skill B — both load)

```bash
# Debug: see what skills resolve for your current scopes
ati skills resolve
```

### Skills in `ati assist`

When you run `ati assist "How do I screen for sanctions?"`, resolved skills are injected into the LLM context alongside the tool catalog. The LLM can reference methodology guidance in its recommendations.

### Skills in Proxy Mode

Read-only skill commands work in proxy mode (`ATI_PROXY_URL` set):

| Command | Proxy Endpoint |
|---------|---------------|
| `ati skills list` | `GET /skills?category=X&provider=Y&tool=Z` |
| `ati skills show <name>` | `GET /skills/<name>` |
| `ati skills info <name>` | `GET /skills/<name>?meta=true` |
| `ati skills search <q>` | `GET /skills?search=<q>` |
| `ati skills resolve` | `POST /skills/resolve` |

## Building

```bash
cd ati

# Build (debug)
cargo build

# Build (release, for sandbox deployment)
cargo build --release

# Run tests (270+ tests — unit, integration, e2e, and live MCP)
cargo test
bash scripts/test_skills_e2e.sh

# The binary
ls target/release/ati
```

### Cross-compilation for sandbox images

```bash
# For x86_64 Linux (most sandboxes)
cargo build --release --target x86_64-unknown-linux-musl

# Static binary, no glibc dependency
file target/x86_64-unknown-linux-musl/release/ati
# ELF 64-bit LSB executable, x86-64, statically linked
```

## Project Structure

```
ati/
├── Cargo.toml
├── README.md
├── docs/
│   ├── SECURITY.md         # Threat model and security design
│   └── IDEAS.md            # Future directions
├── manifests/              # TOML tool definitions (HTTP, MCP, and OpenAPI handlers)
│   ├── example.toml        # Annotated template (start here)
│   ├── github-mcp.toml     # GitHub via MCP stdio server
│   ├── linear-mcp.toml     # Linear via MCP HTTP server
│   ├── deepwiki-mcp.toml   # DeepWiki via MCP HTTP (no auth)
│   ├── everything-mcp.toml # MCP test server (internal)
│   ├── clinicaltrials.toml # OpenAPI handler example (auto-discovers ~40 tools)
│   └── *.toml              # 40+ providers (finance, compliance, search, etc.)
├── specs/                  # OpenAPI 3.0 spec files (17 included for public APIs)
│   ├── clinicaltrials.json # NIH ClinicalTrials.gov
│   ├── finnhub.json        # Stock market data (110 paths)
│   ├── crossref.json       # Academic metadata
│   ├── sec_edgar.json      # SEC filings (EDGAR)
│   ├── middesk.json        # Business verification
│   └── *.json              # 12 more specs
├── scripts/
│   └── test_skills_e2e.sh  # 37-test e2e suite for skills system
├── src/
│   ├── main.rs             # CLI entry point (clap)
│   ├── lib.rs              # Library crate (for integration tests)
│   ├── cli/
│   │   ├── call.rs         # ati call — routes to HTTP, MCP, xAI, or proxy
│   │   ├── tools.rs        # ati tools list/info/search/providers
│   │   ├── mcp.rs          # ati mcp add/list/remove — generate MCP manifests from CLI
│   │   ├── skills.rs       # ati skills — full CRUD, proxy forwarding, search, resolve
│   │   ├── help.rs         # ati assist — LLM-powered discovery with skill context
│   │   ├── openapi.rs      # ati openapi inspect/import — spec tools
│   │   ├── auth.rs         # ati auth status — JWT-based session info
│   │   └── token.rs        # ati token keygen/issue/inspect/validate
│   ├── core/
│   │   ├── manifest.rs     # TOML manifest parsing + registry (HTTP, MCP, OpenAPI)
│   │   ├── openapi.rs      # OpenAPI 3.0 spec parsing, tool registration, param classification
│   │   ├── jwt.rs          # JWT issuance, validation, JWKS — ES256 and HS256
│   │   ├── skill.rs        # Skill metadata, registry, scope-driven resolution
│   │   ├── mcp_client.rs   # MCP client — stdio + Streamable HTTP transport
│   │   ├── http.rs         # HTTP execution + auth injection + SSRF/header protection
│   │   ├── keyring.rs      # AES-256-GCM encrypted credential storage
│   │   ├── scope.rs        # Per-tool scope enforcement with wildcards, from JWT claims
│   │   ├── response.rs     # JSONPath extraction + output formatting
│   │   └── xai.rs          # xAI/Grok agentic handler
│   ├── proxy/
│   │   ├── client.rs       # HTTP + MCP + skills forwarding to proxy (JWT Bearer auth)
│   │   └── server.rs       # axum proxy server — /call, /mcp, /help, /skills, /skills/resolve
│   ├── security/
│   │   ├── memory.rs       # mlock, madvise, zeroize
│   │   └── sealed_file.rs  # One-shot key file read + unlink
│   ├── output/
│   │   ├── json.rs, table.rs, text.rs
│   └── providers/
│       └── generic.rs      # Generic HTTP provider
└── tests/                  # 270+ tests — unit, integration, e2e, and live MCP
    ├── manifest_test.rs    # TOML parsing, MCP/OpenAPI provider fields
    ├── openapi_test.rs     # OpenAPI spec parsing, tool generation, filtering
    ├── mcp_cmd_test.rs     # ati mcp add/list/remove CLI tests
    ├── http_test.rs        # Header deny-list, SSRF protection
    ├── skill_test.rs       # Skill loading, resolution, search, transitive deps
    ├── keyring_test.rs     # Encryption, key resolution
    ├── scope_test.rs       # Scope enforcement, wildcard matching, JWT integration
    ├── call_test.rs        # CLI dispatch (HTTP + MCP routing)
    ├── help_test.rs        # LLM-powered discovery with skill context
    ├── proxy_test.rs       # Proxy client forwarding
    ├── proxy_server_test.rs # Proxy server endpoints, JWT auth middleware
    └── mcp_live_test.rs    # Live MCP integration (GitHub, Linear, DeepWiki, Everything)
```

## MCP Protocol Implementation

ATI implements the MCP 2025-03-26 specification:

- **JSON-RPC 2.0** message framing with proper `id` matching and error handling
- **Stdio transport**: newline-delimited JSON over subprocess stdin/stdout, handles interleaved notifications
- **Streamable HTTP transport**: POST with `Accept: application/json, text/event-stream`, handles both plain JSON and SSE responses
- **SSE parsing**: Extracts JSON-RPC messages from `data:` lines, supports batch arrays and interleaved notifications
- **Session management**: `Mcp-Session-Id` header for HTTP transport, DELETE for session cleanup
- **Pagination**: `tools/list` cursor-based pagination for servers with many tools
- **Tool caching**: Discovered tools cached in memory; `invalidate_cache()` for `tools/list_changed` notifications
- **Auth injection**: Bearer tokens, custom headers, env vars for stdio — all resolved from keyring

## License

Apache-2.0
