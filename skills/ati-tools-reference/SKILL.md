# ATI Tools Reference

ATI (Agent Tools Interface) gives AI agents secure access to APIs, MCP servers, OpenAPI services, and local CLIs through one unified interface.

## Core Commands

### Run a tool

```bash
ati run <tool_name> --key value --key2 value2
```

Arguments are `--key value` pairs. Values are auto-parsed as JSON when possible, otherwise treated as strings. Use `--flag` alone for boolean `true`.

### Discover tools

```bash
# List all available tools
ati tool list

# List tools from a specific provider
ati tool list --provider finnhub

# Search by keyword (fuzzy, offline)
ati tool search "stock price"

# Full schema and usage for a specific tool
ati tool info finnhub__quote
```

### Get help from the LLM

```bash
# Ask which tools to use (searches all providers)
ati assist "how do I check sanctions for a person?"

# Scoped to a provider
ati assist finnhub "research Apple stock"

# Scoped to a specific tool
ati assist github__search_repositories "find Rust MCP libraries"
```

`ati assist` returns natural-language guidance with exact `ati run` commands.

## Adding Providers

### OpenAPI — import from a spec URL

```bash
ati provider import-openapi https://api.example.com/openapi.json
# Auto-derives name, auth, endpoints

# Preview before importing
ati provider inspect-openapi https://api.example.com/openapi.json

# Filter by tags
ati provider import-openapi https://example.com/spec.json --include-tags "Users,Orders"
```

### MCP — connect to an MCP server

```bash
# Remote HTTP transport
ati provider add-mcp linear --transport http \
  --url "https://mcp.linear.app/mcp" \
  --auth bearer --auth-key linear_api_key

# Local stdio transport
ati provider add-mcp github --transport stdio \
  --command npx --args "-y" --args "@modelcontextprotocol/server-github" \
  --env 'GITHUB_PERSONAL_ACCESS_TOKEN=${github_token}'
```

MCP tools are auto-discovered and namespaced as `<provider>__<tool_name>`.

### CLI — wrap any command

```bash
ati provider add-cli gh --command gh \
  --env 'GH_TOKEN=${github_token}'

# With default args and file-based credentials
ati provider add-cli gcloud --command gcloud \
  --default-args "--format" --default-args "json" \
  --env 'GOOGLE_APPLICATION_CREDENTIALS=@{gcp_service_account}'
```

CLI args after `--` are passed through: `ati run gh -- pr list --state open`

### Hand-written TOML — full control

Create a `.toml` file in `~/.ati/manifests/`:

```toml
[provider]
name = "my_api"
base_url = "https://api.example.com/v1"
auth_type = "bearer"           # bearer | header | query | basic | oauth2 | none
auth_key_name = "my_api_key"

[[tools]]
name = "my_search"
endpoint = "/search"
method = "GET"
[tools.input_schema]
type = "object"
required = ["query"]
[tools.input_schema.properties.query]
type = "string"
description = "Search query"
```

### Manage providers

```bash
ati provider list              # List all providers
ati provider info github       # Provider details
ati provider remove my_api     # Remove a provider
```

## Credential Management

### Store keys

```bash
ati key set finnhub_api_key "your-key-here"
ati key list                   # Values are masked
ati key remove old_key
```

### Key references in manifests

- `${key_name}` — inject as environment variable value
- `@{key_name}` — materialize as a temporary file (0600, wiped on exit) for CLIs that need a file path

### Environment variable override

Any key can be set via `ATI_KEY_<NAME>` environment variable (uppercased, with prefix).

## Skills

Skills are methodology documents (SKILL.md) that teach agents *how* to use tools — workflows, best practices, parameter guidance.

```bash
ati skill list                              # List installed skills
ati skill search "sanctions"                # Search by keyword
ati skill show compliance-screening         # Read the methodology
ati skill info compliance-screening         # Metadata and bindings

# Install from git
ati skill install https://github.com/org/repo#skill-name

# Install from local directory
ati skill install ./my-skills/my-skill/

# Scaffold a new skill
ati skill init my-skill --tools tool1,tool2

# Check what skills resolve for current scopes
ati skill resolve
```

Skills auto-activate based on the agent's tool scope — no manual loading needed.

## Proxy Mode

For sandboxed agents that should never touch credentials:

```bash
# On the proxy server
ati proxy --port 8090 --ati-dir ~/.ati

# In the sandbox — same ati run commands, routed through proxy
export ATI_PROXY_URL=http://proxy-host:8090
export ATI_SESSION_TOKEN=<jwt>
ati run finnhub__quote --symbol AAPL
```

### JWT tokens

```bash
# Generate signing keys
ati token keygen ES256     # Asymmetric (production)
ati token keygen HS256     # Symmetric (simpler)

# Issue a scoped token
ati token issue --sub agent-7 \
  --scope "tool:finnhub__* tool:github__* help" \
  --ttl 3600

# Inspect / validate
ati token inspect $ATI_SESSION_TOKEN
ati token validate $ATI_SESSION_TOKEN
```

Scope patterns: `tool:name` (exact), `tool:prefix__*` (wildcard), `help`, `skill:name`, `*` (all).

## Output Formats

```bash
ati run tool --arg value                      # text (default, human-readable)
ati --output json run tool --arg value        # JSON (programmatic)
ati --output table run tool --arg value       # table (tabular data)
```

Set default with `ATI_OUTPUT=json` environment variable.

## Quick Reference

| Task | Command |
|------|---------|
| Run a tool | `ati run <tool> --key value` |
| List all tools | `ati tool list` |
| Search tools | `ati tool search "keyword"` |
| Tool details | `ati tool info <tool>` |
| Get guidance | `ati assist "question"` |
| Import OpenAPI | `ati provider import-openapi <url>` |
| Add MCP server | `ati provider add-mcp <name> --transport http --url <url>` |
| Add CLI | `ati provider add-cli <name> --command <cmd>` |
| Store a key | `ati key set <name> <value>` |
| Issue JWT | `ati token issue --sub <id> --scope "..." --ttl 3600` |
| Install skill | `ati skill install <source>` |
| Start proxy | `ati proxy --port 8090` |
