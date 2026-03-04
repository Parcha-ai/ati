# ATI — Agent Tools Interface

**Let your agents cook.**

One binary. Any agent framework. Every tool your agent needs.

ATI gives AI agents secure access to HTTP APIs, MCP servers, OpenAPI services, and local CLIs — through one unified command. No custom tool wrappers. No per-SDK plumbing. If your agent framework has a shell tool, ATI works.

```bash
# HTTP API — search medical literature
ati run medical_search --term "CRISPR gene therapy" --retmax 5

# MCP server — search GitHub repos
ati run github__search_repositories --query "rust mcp client"

# OpenAPI spec — search clinical trials (auto-discovered from spec)
ati run clinicaltrials_searchStudies --query.term "cancer immunotherapy"

# Local CLI — use gh with injected credentials
ati run gh pr list --state open --limit 5
```

Every tool looks the same from the agent's perspective: `ati run <tool> --arg value`. The agent doesn't know (or care) whether it's calling a REST API, an MCP server, an OpenAPI service, or a local CLI.

### The Integration Pattern

ATI works with any agent framework that has a shell tool. The integration is always the same — ~30 lines, no matter the SDK:

```python
# Give the agent shell access and tell it about ATI. That's it.
system_prompt = """
You have ATI on your PATH. Available commands:
- `ati tool search <query>` — find tools by keyword
- `ati tool info <name>` — inspect a tool's schema and usage
- `ati run <tool> --key value` — execute a tool
- `ati assist "<question>"` — ask for tool recommendations
"""

# Claude Agent SDK
agent = Agent(model="claude-sonnet-4-20250514", tools=[Bash()], system=system_prompt)

# OpenAI Agents SDK
agent = Agent(model="gpt-4o", tools=[shell_tool], instructions=system_prompt)

# LangChain
agent = create_react_agent(llm, [ShellTool()], prompt=system_prompt)

# ... same pattern for any framework
```

No `@tool` decorators. No function wrappers. No SDK-specific adapters. Just shell access + a system prompt.

---

## Quick Start

Get from zero to working tools in 60 seconds.

### 1. Initialize

```bash
ati init
```

Creates `~/.ati/` with directories for manifests, specs, and skills.

### 2. Try a Free Tool (No Auth Required)

DeepWiki is a free MCP server — no API key needed:

```bash
# Add DeepWiki as a provider
ati provider add-mcp deepwiki --transport http \
  --url "https://mcp.deepwiki.com/mcp" \
  --description "AI-powered docs for GitHub repos"

# See what tools were discovered
ati tool list --provider deepwiki

# Ask a question about any GitHub repo
ati run deepwiki__ask_question \
  --repoName "anthropics/claude-code" \
  --question "How does tool dispatch work?"
```

### 3. Add an Authenticated Tool

```bash
# Store your GitHub token
ati key set github_token ghp_your_token_here

# Add the GitHub MCP server
ati provider add-mcp github --transport stdio \
  --command npx --args "-y" --args "@modelcontextprotocol/server-github" \
  --env 'GITHUB_PERSONAL_ACCESS_TOKEN=${github_token}'

# Search repos, read files, manage issues...
ati run github__search_repositories --query "rust mcp"
```

### 4. Discover What's Available

```bash
# Fuzzy search across all tools
ati tool search "sanctions screening"

# LLM-powered recommendations with exact commands
ati assist "How do I check SEC filings?"

# Full tool catalog
ati tool list
```

---

## Four Provider Types

ATI supports four ways to connect tools. Each uses a different `handler` in the TOML manifest, but all produce the same interface: `ati run <tool> --arg value`.

### HTTP APIs

Hand-written TOML with full control over endpoints, parameters, and response formatting. Best for simple REST APIs.

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
ati run medical_search --term "CRISPR gene therapy" --retmax 5
```

Auth types: `bearer`, `header`, `query`, `basic`, `oauth2`, `none`.

### MCP Servers

Point ATI at any MCP server and tools are auto-discovered — no hand-written `[[tools]]` needed.

**Stdio transport** (local subprocess):

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
GITHUB_PERSONAL_ACCESS_TOKEN = "${github_token}"
```

**HTTP transport** (remote server):

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

```bash
# Tools are auto-discovered — just run them
ati run github__search_repositories --query "rust mcp"
ati run github__read_file --owner anthropics --repo claude-code --path README.md
ati run linear__list_issues --teamId "TEAM-123"
```

MCP tools are namespaced as `<provider>__<tool_name>`. ATI handles JSON-RPC framing, session management, and auth injection transparently.

### OpenAPI Specs

Auto-discover every operation from an OpenAPI 3.0 spec. One manifest replaces hundreds of lines of hand-written tool definitions.

```toml
# manifests/clinicaltrials.toml
[provider]
name = "clinicaltrials"
description = "NIH ClinicalTrials.gov — search and retrieve clinical study data"
handler = "openapi"
base_url = "https://clinicaltrials.gov/api/v2"
openapi_spec = "clinicaltrials.json"
auth_type = "none"
category = "medical"
```

That's it — ATI reads the spec, discovers all operations, and registers each as a tool with auto-generated schemas.

```bash
# Preview operations in a spec before importing
ati provider inspect-openapi https://petstore3.swagger.io/api/v3/openapi.json

# Import a spec (downloads + generates manifest)
ati provider import-openapi https://api.example.com/openapi.json --name myapi

# Run an auto-discovered tool
ati run clinicaltrials_searchStudies --query.term "cancer immunotherapy"
```

Supports tag/operation filtering (`openapi_include_tags`, `openapi_exclude_tags`) and an operation cap (`openapi_max_operations`) for large APIs.

17 OpenAPI specs are included out of the box: ClinicalTrials.gov, Finnhub, SEC EDGAR, Crossref, Semantic Scholar, PubMed Central, CourtListener, Middesk, and more.

### Local CLIs

Run `gh`, `gcloud`, `gsutil`, `kubectl`, or any CLI through ATI with credential injection. The agent calls `ati run`, ATI spawns the subprocess with a curated environment, and credentials never leak.

```toml
# manifests/gh.toml
[provider]
name = "gh"
description = "GitHub CLI"
handler = "cli"
cli_command = "gh"
auth_type = "none"

[provider.cli_env]
GH_TOKEN = "${github_token}"
```

The `@{key}` syntax materializes a keyring secret as a temporary file (0600 permissions, wiped on drop) — useful for CLIs that need a credential file path:

```toml
# manifests/gcloud.toml
[provider]
name = "gcloud"
description = "Google Cloud CLI"
handler = "cli"
cli_command = "gcloud"
cli_default_args = ["--format", "json"]
auth_type = "none"

[provider.cli_env]
GOOGLE_APPLICATION_CREDENTIALS = "@{gcp_service_account}"
```

```bash
ati run gh pr list --state open --limit 5
ati run gcloud compute instances list --project my-project
```

CLI providers get a curated environment (only `PATH`, `HOME`, `TMPDIR`, `LANG`, `USER`, `TERM` from the host) plus any resolved `cli_env` vars. The subprocess can't see your shell's full environment.

---

## Tool Discovery

### Fuzzy Search — Offline, Instant

```bash
$ ati tool search "sanctions"
PROVIDER           TOOL                           DESCRIPTION
complyadvantage    ca_person_sanctions_search      Search sanctions lists for individuals
complyadvantage    ca_business_sanctions_search    Search sanctions lists for businesses

$ ati tool search "stock price"
PROVIDER    TOOL              DESCRIPTION
finnhub     finnhub_quote     Get real-time stock quote
```

Searches across tool names, descriptions, providers, categories, tags, and hints. Works in both local and proxy mode.

### LLM-Powered Discovery

```bash
$ ati assist "How do I screen a person for sanctions?"
1. **ca_person_sanctions_search** — Search sanctions lists for individuals
   ```
   ati run ca_person_sanctions_search --search_term "Person Name" --fuzziness 0.6
   ```

2. **ca_person_pep_search** — Search for PEP matches
   ```
   ati run ca_person_pep_search --search_term "Person Name" --fuzziness 0.6
   ```
```

Recommends tools, generates exact `ati run` commands, and includes resolved skills in its context.

### Tool-Scoped Assist

Scope assist to a specific tool or provider for targeted help:

```bash
# Scoped to a tool — captures the tool's schema for precise commands
ati assist github__search_repositories "how do I search private repos?"

# Scoped to a provider — captures --help output for CLIs
ati assist gh "how do I create a pull request?"
```

### Inspection

```bash
# Full catalog
ati tool list
ati tool list --provider github

# Deep inspection — schema, auth type, transport, usage example
ati tool info github__search_repositories

# Provider overview
ati provider list
ati provider info github
```

---

## Security

Three tiers of credential protection, matched to your threat model. Pick the one that fits — they all use the same `ati run` interface.

### Dev Mode — `~/.ati/credentials`

Plaintext JSON file. Quick, no ceremony. For local development where the "agent" is you.

```bash
ati key set github_token ghp_abc123
ati key set finnhub_api_key your-key-here
ati key list
```

Stored as JSON at `~/.ati/credentials` with 0600 permissions. Also supports environment variables with `ATI_KEY_` prefix (`ATI_KEY_GITHUB_TOKEN=ghp_abc123`).

### Local Mode — `keyring.enc` + Session Key

AES-256-GCM encrypted keyring. The orchestrator provisions a one-shot session key to `/run/ati/.key` (deleted after first read). Keys are held in mlock'd memory and zeroized on drop. For sandboxed agents where keys should be encrypted at rest.

```
┌─────────────────────────────────────────────────────┐
│  Sandbox                                             │
│                                                      │
│  ┌──────────┐   ati run my_tool        ┌──────────┐ │
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

### Proxy Mode — Zero Credentials in the Sandbox

ATI forwards all calls to an external proxy server holding the real keys. The sandbox never touches credentials — it only needs manifests and a JWT token.

```
┌─────────────────────────────────────────────────────┐
│  Sandbox                                             │
│                                                      │
│  ┌──────────┐   ati run my_tool        ┌──────────┐ │
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

Switch modes with one environment variable — the agent never changes its commands:

```bash
# Local mode (default)
ati run my_tool --arg value

# Proxy mode
export ATI_PROXY_URL=http://proxy-host:8090
ati run my_tool --arg value    # same command, routed to proxy
```

| Aspect | Dev Mode | Local Mode | Proxy Mode |
|--------|----------|-----------|------------|
| **Credentials** | Plaintext file | Encrypted keyring | Not in sandbox |
| **Key exposure** | Readable on disk | In memory (mlock'd) | Never enters sandbox |
| **Setup** | `ati key set` | Keyring + session key | `ATI_PROXY_URL` env var |
| **Use case** | Local dev | Sandboxed agents | Untrusted sandboxes |

---

## JWT Scoping

Each agent session gets a JWT carrying identity, permissions, and an expiry. The proxy validates the token on every request — agents only access what they're explicitly granted.

### Scope Format

Scopes are space-delimited strings in the JWT `scope` claim:

| Scope | Grants |
|-------|--------|
| `tool:web_search` | Access to one specific tool |
| `tool:github__*` | Wildcard — all GitHub MCP tools |
| `help` | Access to `ati assist` |
| `skill:compliance-screening` | Access to a specific skill |
| `*` | Everything (dev/testing only) |

### Token Lifecycle

```bash
# Generate signing keys
ati token keygen ES256        # Asymmetric (recommended for production)
ati token keygen HS256        # Symmetric (simpler, single-machine)

# Issue a scoped token
ati token issue \
  --sub agent-7 \
  --scope "tool:web_search tool:github__* help skill:compliance-screening" \
  --ttl 3600

# Inspect what's inside (decode without verification)
$ ati token inspect $ATI_SESSION_TOKEN
{
  "sub": "agent-7",
  "scope": "tool:web_search tool:github__* help skill:compliance-screening",
  "aud": "ati-proxy",
  "exp": 1704070800,
  "iat": 1704067200,
  "jti": "a1b2c3d4..."
}

# Validate (full signature + expiry check)
ati token validate $ATI_SESSION_TOKEN
```

Each agent session gets its own JWT with the minimum scope it needs. A compliance agent gets `tool:ca_*` tools and the `compliance-screening` skill. A research agent gets `tool:arxiv_*` and `tool:deepwiki__*`. Neither can access the other's tools.

---

## Skills

Skills are methodology documents that teach agents *how* to approach a task. They're not code — they provide context about when to use which tools, how to interpret results, and what workflow to follow.

Tools provide **data access**. Skills provide **workflow**.

### Structure

Each skill lives in `~/.ati/skills/<name>/`:

```
~/.ati/skills/compliance-screening/
├── skill.toml      # Metadata and tool bindings
└── SKILL.md        # The methodology document
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

# Provider bindings
providers = ["complyadvantage"]

# Category bindings
categories = ["compliance"]

# Discovery metadata
keywords = ["sanctions", "OFAC", "AML", "PEP", "KYB", "KYC"]

# Dependencies
depends_on = []
suggests = ["tin-verification"]
```

### SKILL.md

Write it like you'd brief a junior analyst:

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

### Auto-Resolution

Skills auto-activate based on the agent's tool scope. If an agent has access to `ca_person_sanctions_search`, ATI automatically loads the `compliance-screening` skill because its `tools` binding includes that tool.

Resolution cascade:
1. **Tool binding** — exact tool name match
2. **Provider binding** — provider name match
3. **Category binding** — category match
4. **depends_on** — transitively load dependency skills

This bridges the gap between "here are 50 tools" and "here's how to do sanctions screening."

### CLI

```bash
# List and search
ati skill list
ati skill search "sanctions"
ati skill info compliance-screening

# Read the methodology
ati skill show compliance-screening

# Create a new skill scaffold
ati skill init my-skill --tools getQuote,getMetrics --provider finnhub

# Validate configuration
ati skill validate my-skill --check-tools

# Install / remove
ati skill install ./my-skill/
ati skill remove my-skill

# See what skills resolve for current scopes
ati skill resolve
```

---

## Works on Any Agent Harness

ATI doesn't care what framework you use. If it has a shell/bash tool, ATI works. The pattern is always the same: system prompt + shell access. No custom tool wrappers.

| SDK | Shell Mechanism | Example |
|-----|----------------|---------|
| [Claude Agent SDK](examples/claude-agent-sdk/) | Built-in `Bash` tool | ~100 lines |
| [OpenAI Agents SDK](examples/openai-agents-sdk/) | `@function_tool` async shell | ~100 lines |
| [Google ADK](examples/google-adk/) | `run_shell()` function tool | ~120 lines |
| [LangChain](examples/langchain/) | `ShellTool` (zero-config) | ~90 lines |
| [Codex CLI](examples/codex/) | Built-in (Codex IS a shell agent) | ~60 lines |
| [Pi](examples/pi/) | Built-in `bashTool` | ~100 lines |

Every example uses free, no-auth tools (DeepWiki, arXiv, Crossref, Hacker News) so you can run them immediately with just an LLM API key.

See the [examples/](examples/) directory for complete, runnable code.

---

## Proxy Server

For production deployments, run `ati proxy` as a central server that holds secrets and serves sandboxed agents.

```bash
# Start with API keys from credentials file
ati proxy --port 8090 --ati-dir ~/.ati

# Start with API keys from environment variables
ati proxy --port 8090 --ati-dir ~/.ati --env-keys

# Initialize with JWT key generation
ati init --proxy --es256
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Status — tool/provider/skill counts, version |
| `/call` | POST | Execute tool — `{tool_name, args}` |
| `/mcp` | POST | MCP JSON-RPC pass-through |
| `/help` | POST | LLM-powered discovery — `{query}` |
| `/skills` | GET | List/search skills |
| `/skills/:name` | GET | Show skill content and metadata |
| `/skills/resolve` | POST | Resolve skills for given scopes |
| `/.well-known/jwks.json` | GET | JWKS public key for token validation |

All endpoints except `/health` and `/.well-known/jwks.json` require `Authorization: Bearer <JWT>` when JWT is configured.

---

## CLI Reference

```
ati — Agent Tools Interface

COMMANDS:
    init       Initialize ATI directory structure (~/.ati/)
    run        Execute a tool by name
    tool       List, inspect, search, and discover tools
    provider   Add, list, remove, inspect, and import providers
    skill      Manage skills (methodology docs for agents)
    assist     LLM-powered tool discovery and recommendations
    key        Manage API keys in the credentials store
    token      JWT token management (keygen, issue, inspect, validate)
    auth       Show authentication and scope information
    proxy      Run ATI as a proxy server
    version    Print version information

OPTIONS:
    --output <FORMAT>   Output format: json, table, text [default: text]
    --verbose           Enable debug output
```

### Provider Management

```bash
ati provider add-mcp <name> --transport stdio|http [--command CMD] [--url URL] [--env 'KEY=${ref}']
ati provider add-cli <name> --command CMD [--default-args ARG] [--env 'KEY=${ref}'] [--env 'KEY=@{ref}']
ati provider import-openapi <spec> --name NAME [--auth-key KEY] [--include-tags T1,T2] [--dry-run]
ati provider inspect-openapi <spec> [--include-tags T1,T2]
ati provider list
ati provider info <name>
ati provider remove <name>
```

### Key Management

```bash
ati key set <name> <value>     # Store a key
ati key list                   # List keys (values masked)
ati key remove <name>          # Delete a key
```

### Token Management

```bash
ati token keygen ES256|HS256                                    # Generate signing key
ati token issue --sub ID --scope "..." --ttl SECONDS            # Issue scoped JWT
ati token inspect <token>                                       # Decode without verification
ati token validate <token> [--key path|--secret hex]            # Full verification
```

### Output Formats

```bash
ati run finnhub_quote --symbol AAPL                    # Default: human-readable text
ati --output json run finnhub_quote --symbol AAPL      # JSON for programmatic use
ati --output table run finnhub_quote --symbol AAPL     # Table for tabular data
```

---

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Static binary for sandboxes (no glibc dependency)
cargo build --release --target x86_64-unknown-linux-musl

# Run tests (399 tests — unit, integration, e2e)
cargo test

# Skill system e2e tests
bash scripts/test_skills_e2e.sh

# Live MCP tests (requires real API keys)
cargo test --test mcp_live_test -- --ignored
```

---

## Project Structure

```
ati/
├── Cargo.toml
├── README.md
├── manifests/              # 42 TOML provider manifests (HTTP, MCP, OpenAPI, CLI)
│   ├── example.toml        # Annotated template
│   ├── github-mcp.toml     # GitHub via MCP stdio
│   ├── linear-mcp.toml     # Linear via MCP HTTP
│   ├── deepwiki-mcp.toml   # DeepWiki via MCP HTTP (no auth)
│   ├── clinicaltrials.toml # OpenAPI handler (auto-discovered tools)
│   └── *.toml              # Finance, compliance, search, medical, legal...
├── specs/                  # 17 pre-downloaded OpenAPI 3.0 specs
│   ├── clinicaltrials.json
│   ├── finnhub.json
│   ├── sec_edgar.json
│   ├── crossref.json
│   └── *.json
├── examples/               # 6 SDK integrations (Claude, OpenAI, Google ADK, LangChain, Codex, Pi)
├── scripts/                # E2E test scripts
├── docs/
│   ├── SECURITY.md         # Threat model and security design
│   └── IDEAS.md            # Future directions
├── src/
│   ├── main.rs             # CLI entry point (clap)
│   ├── lib.rs              # Library crate
│   ├── cli/                # Command handlers (run, tool, provider, skill, assist, key, token, auth)
│   ├── core/               # Manifest registry, MCP client, OpenAPI parser, HTTP executor,
│   │                       #   keyring, JWT, scopes, skills, response processing, CLI executor
│   ├── proxy/              # Client (sandbox → proxy) and server (axum, holds keys)
│   ├── security/           # mlock/madvise/zeroize, sealed one-shot key file
│   └── output/             # JSON, table, text formatters
└── tests/                  # 399 tests — unit, integration, e2e, live MCP
```

## License

Apache-2.0
