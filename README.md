# ATI — Agent Tools Interface

**Let your agents cook.**

One binary. Any agent framework. Every tool your agent needs.

ATI gives AI agents secure access to APIs, MCP servers, OpenAPI services, and local CLIs — through one unified interface. No custom tool wrappers. No per-SDK plumbing. Your agent calls `ati run <tool> --arg value` and ATI handles auth, protocol bridging, and response formatting.

---

## See It Work — 60 Seconds, Zero Install

### Import an API from its OpenAPI spec

ClinicalTrials.gov publishes an OpenAPI spec. One command turns it into tools your agent can use:

```bash
# Initialize ATI
ati init

# Import the spec — ATI derives the provider name from the URL
ati provider import-openapi https://clinicaltrials.gov/api/v2/openapi.json
# → Saved manifest to ~/.ati/manifests/clinicaltrials.toml
# → Imported 1 operations from "ClinicalTrials.gov API"

# See what tools were discovered
ati tool list --provider clinicaltrials
# ┌───────────────────────────────┬────────────────┬───────────────────────────────┐
# │ DESCRIPTION                   ┆ PROVIDER       ┆ TOOL                          │
# ╞═══════════════════════════════╪════════════════╪═══════════════════════════════╡
# │ Search clinical trial studies ┆ clinicaltrials ┆ clinicaltrials__searchStudies │
# └───────────────────────────────┴────────────────┴───────────────────────────────┘
```

That's it. Every operation in the spec is now a tool. No `--name`, no TOML to write, no code to generate.

### Explore what you just added

```bash
# Inspect a specific tool — see its parameters, types, required fields
ati tool info clinicaltrials__searchStudies
# Tool:        clinicaltrials__searchStudies
# Provider:    clinicaltrials (ClinicalTrials.gov API)
# Handler:     openapi
# Endpoint:    GET https://clinicaltrials.gov/api/v2/studies
# Description: Search clinical trial studies
#
# Input Schema:
#   --query.term (string) **required**: Search term
#   --filter.overallStatus (string): Filter by overall study status
#   --filter.phase (string): Filter by study phase
#   --pageSize (integer, default: 10): Results per page

# Ask the LLM for help — scoped to this provider
ati assist clinicaltrials "find phase 3 cancer trials"
# ati run clinicaltrials__searchStudies --query.term "cancer" --filter.phase "Phase 3"
#
# Optional parameters you can add:
#   --filter.overallStatus "Recruiting": Show only actively recruiting trials
#   --pageSize 50: Increase results per page
```

`ati assist` reads the tool schemas and returns exact `ati run` commands you can copy-paste.

### Run it

```bash
ati run clinicaltrials__searchStudies \
  --query.term "cancer immunotherapy" --pageSize 3
# nextPageToken: ZVNj7o2Elu8o3lpoXsGvtK7umpOQJJxuYfas0A
# studies: [{protocolSection: {identificationModule: {nctId: "NCT06742801",
#   briefTitle: "Avelumab Immunotherapy in Oral Premalignant Lesions" ...
```

The agent doesn't write HTTP requests. It doesn't parse JSON responses. It calls `ati run` and gets structured text back.

### Now add an MCP server — same pattern, zero install

```bash
# DeepWiki is a free MCP server — no API key needed
ati provider add-mcp deepwiki --transport http \
  --url "https://mcp.deepwiki.com/mcp" \
  --description "AI-powered docs for any GitHub repo"
# → Saved manifest to ~/.ati/manifests/deepwiki.toml

# See the auto-discovered tools
ati tool list --provider deepwiki
# ┌─────────────────────────────────────────────────────┬──────────┬───────────────────────────────┐
# │ DESCRIPTION                                         ┆ PROVIDER ┆ TOOL                          │
# ╞═════════════════════════════════════════════════════╪══════════╪═══════════════════════════════╡
# │ Get a list of documentation topics for a GitHub ... ┆ deepwiki ┆ deepwiki__read_wiki_structure │
# │ View documentation about a GitHub repository.       ┆ deepwiki ┆ deepwiki__read_wiki_contents  │
# │ Ask any question about a GitHub repository ...      ┆ deepwiki ┆ deepwiki__ask_question        │
# └─────────────────────────────────────────────────────┴──────────┴───────────────────────────────┘

# Ask a question about any repo
ati run deepwiki__ask_question \
  --repoName "anthropics/claude-code" \
  --question "How does tool dispatch work?"
# Tool dispatch in Claude Code involves a dynamic system that handles both
# built-in and external Model Context Protocol (MCP) tools.
#
# 1. **Tool Name Check**: The system first checks if the tool name starts
#    with `mcp__`. If not, it's routed to the built-in tool pipeline.
# 2. **MCP Tool Resolution**: Server and tool names are extracted from the
#    `mcp__<servername>__<toolname>` format, the server is connected, and
#    the tool is invoked using a `call_tool` RPC.
# 3. **Output Handling**: Text output is returned; images are handled
#    during streaming.
```

MCP tools are namespaced as `<provider>__<tool_name>`. ATI handles JSON-RPC framing, session management, and auth injection.

---

## Four Provider Types

Every provider type produces the same interface: `ati run <tool> --arg value`. The agent doesn't know or care what's behind it.

### OpenAPI Specs — Auto-discovered from any spec

Point ATI at an OpenAPI 3.0 spec URL or file. It downloads the spec, discovers every operation, and registers each as a tool with auto-generated schemas.

```bash
# Preview what's in a spec before importing
ati provider inspect-openapi https://petstore3.swagger.io/api/v3/openapi.json

# Import it — name derived from the URL (or pass --name to override)
ati provider import-openapi https://api.example.com/openapi.json

# If the API needs auth, ATI tells you what key to set
ati key set example_api_key sk-your-key-here
```

Supports tag/operation filtering (`--include-tags`, `--exclude-tags`) and an operation cap (`openapi_max_operations`) for large APIs.

17 OpenAPI specs ship out of the box: ClinicalTrials.gov, Finnhub, SEC EDGAR, Crossref, Semantic Scholar, PubMed Central, CourtListener, Middesk, and more.

### MCP Servers — Auto-discovered via protocol

Any MCP server — stdio subprocess or remote HTTP — gets its tools auto-discovered. No hand-written tool definitions.

```bash
# Remote MCP server (HTTP transport)
ati provider add-mcp linear --transport http \
  --url "https://mcp.linear.app/mcp" \
  --auth bearer --auth-key linear_api_key

# Local MCP server (stdio transport)
ati provider add-mcp github --transport stdio \
  --command npx --args "-y" --args "@modelcontextprotocol/server-github" \
  --env 'GITHUB_PERSONAL_ACCESS_TOKEN=${github_token}'

# Store the key, then use the tools
ati key set github_token ghp_your_token_here
ati run github__search_repositories --query "rust mcp"
ati run github__read_file --owner anthropics --repo claude-code --path README.md
```

### Local CLIs — Wrap any command with credential injection

Run `gh`, `gcloud`, `kubectl`, or any CLI through ATI. The agent calls `ati run`, ATI spawns the subprocess with a curated environment, and credentials never leak to the agent.

```bash
# Wrap the GitHub CLI
ati provider add-cli gh --command gh \
  --env 'GH_TOKEN=${github_token}'

# Wrap gcloud with a credential file
ati provider add-cli gcloud --command gcloud \
  --default-args "--format" --default-args "json" \
  --env 'GOOGLE_APPLICATION_CREDENTIALS=@{gcp_service_account}'

# Use them
ati run gh pr list --state open --limit 5
ati run gcloud compute instances list --project my-project
```

The `${key}` syntax injects a keyring secret as an env var. The `@{key}` syntax materializes it as a temporary file (0600 permissions, wiped on process exit) — for CLIs that need a credential file path.

CLI providers get a curated environment (only `PATH`, `HOME`, `TMPDIR`, `LANG`, `USER`, `TERM` from the host). The subprocess can't see your shell's full environment.

### HTTP Tools — Hand-written TOML for full control

For APIs where you want precise control over endpoints, parameters, and response extraction, write TOML manifests directly:

```toml
# ~/.ati/manifests/pubmed.toml
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

---

## Manifests — Your Provider Catalog

Every provider is a `.toml` file in `~/.ati/manifests/`. The `ati provider` commands generate these for you, but you can also edit them directly for full control.

```bash
# What you've got
ati provider list
ati provider info github

# Add via CLI
ati provider add-mcp ...
ati provider add-cli ...
ati provider import-openapi ...

# Or edit manifests directly
$EDITOR ~/.ati/manifests/my-provider.toml

# Remove
ati provider remove my-provider
```

ATI ships with 42 pre-built manifests covering finance, compliance, medical, legal, search, and developer tools. Use them as-is or as templates for your own.

---

## Tool Discovery

Three tiers of finding the right tool.

### Search — Offline, Instant

```bash
$ ati tool search "sanctions"
PROVIDER           TOOL                           DESCRIPTION
complyadvantage    ca_person_sanctions_search      Search sanctions lists for individuals
complyadvantage    ca_business_sanctions_search    Search sanctions lists for businesses

$ ati tool search "stock price"
PROVIDER    TOOL              DESCRIPTION
finnhub     finnhub_quote     Get real-time stock quote
```

Fuzzy search across tool names, descriptions, providers, categories, tags, and hints.

### Inspect — Full Schema

```bash
$ ati tool info clinicaltrials__searchStudies
Tool:        clinicaltrials__searchStudies
Provider:    clinicaltrials (ClinicalTrials.gov API)
Handler:     openapi
Endpoint:    GET https://clinicaltrials.gov/api/v2/studies
Description: Search clinical trial studies
Tags:        Clinical Trials

Input Schema:
  --query.term (string) **required**: Search term
  --filter.overallStatus (string): Filter by overall study status
  --filter.phase (string): Filter by study phase
  --pageSize (integer, default: 10): Results per page

Usage:
  ati run clinicaltrials__searchStudies --query.term "cancer" --pageSize 10
```

### Assist — LLM-Powered Recommendations

```bash
# Broad — searches all tools
$ ati assist "How do I screen a person for sanctions?"
1. ca_person_sanctions_search — Search sanctions lists for individuals
   ati run ca_person_sanctions_search --search_term "Person Name" --fuzziness 0.6

2. ca_person_pep_search — Search for PEP matches
   ati run ca_person_pep_search --search_term "Person Name" --fuzziness 0.6

# Scoped to a provider — captures --help output for CLIs
$ ati assist gh "how do I create a pull request?"

# Scoped to a tool — uses the full schema for precise commands
$ ati assist github__search_repositories "search private repos only"
```

---

## Security

Three tiers of credential protection, matched to your threat model. All use the same `ati run` interface.

### Dev Mode — Plaintext Credentials

Quick, no ceremony. For local development.

```bash
ati key set github_token ghp_abc123
ati key set finnhub_api_key your-key-here
ati key list                              # values masked
```

Stored at `~/.ati/credentials` with 0600 permissions. Also supports `ATI_KEY_` env var prefix.

### Local Mode — Encrypted Keyring

AES-256-GCM encrypted keyring. The orchestrator provisions a one-shot session key to `/run/ati/.key` (deleted after first read). Keys held in mlock'd memory, zeroized on drop.

```
┌─────────────────────────────────────────────────────┐
│  Sandbox                                             │
│                                                      │
│  ┌──────────┐   ati run my_tool        ┌──────────┐ │
│  │  Agent    │ ────────────────────────▶│   ATI    │ │
│  │          │                          │  binary  │ │
│  │          │◀────────────────────────│          │ │
│  └──────────┘   structured result      └────┬─────┘ │
│                                              │       │
│                    reads encrypted keyring ───┘       │
│                    injects auth headers               │
│                    enforces scopes                    │
│                                                      │
│  /run/ati/.key  (session key, deleted after read)    │
└─────────────────────────────────────────────────────┘
```

### Proxy Mode — Zero Credentials in the Sandbox

ATI forwards all calls to a central proxy server holding the real keys. The sandbox never touches credentials.

```
┌──────────────────────────┐         ┌────────────────────────────┐
│  Sandbox                  │         │  Proxy Server (ati proxy)   │
│                          │         │                            │
│  Agent → ATI binary ─────│── POST ─│──▶ keyring + MCP servers   │
│                          │  /call  │     injects auth            │
│  No keys. No keyring.    │  /mcp   │     routes by tool name     │
│  Only manifests + JWT.   │         │     calls upstream APIs     │
└──────────────────────────┘         └────────────────────────────┘
```

Switch modes with one env var — the agent never changes its commands:

```bash
# Local mode (default)
ati run my_tool --arg value

# Proxy mode — same command, routed to proxy
export ATI_PROXY_URL=http://proxy-host:8090
ati run my_tool --arg value
```

| | Dev Mode | Local Mode | Proxy Mode |
|--|----------|-----------|------------|
| **Credentials** | Plaintext file | Encrypted keyring | Not in sandbox |
| **Key exposure** | Readable on disk | mlock'd memory | Never enters sandbox |
| **Setup** | `ati key set` | Keyring + session key | `ATI_PROXY_URL` |
| **Use case** | Local dev | Sandboxed agents | Untrusted sandboxes |

---

## JWT Scoping

Each agent session gets a JWT with identity, permissions, and an expiry. The proxy validates on every request — agents only access what they're granted.

| Scope | Grants |
|-------|--------|
| `tool:web_search` | One specific tool |
| `tool:github__*` | Wildcard — all GitHub MCP tools |
| `help` | Access to `ati assist` |
| `skill:compliance-screening` | A specific skill |
| `*` | Everything (dev/testing only) |

```bash
# Generate signing keys
ati token keygen ES256        # Asymmetric (production)
ati token keygen HS256        # Symmetric (simpler)

# Issue a scoped token
ati token issue \
  --sub agent-7 \
  --scope "tool:web_search tool:github__* help" \
  --ttl 3600

# Inspect / validate
ati token inspect $ATI_SESSION_TOKEN
ati token validate $ATI_SESSION_TOKEN
```

A compliance agent gets `tool:ca_*` and `skill:compliance-screening`. A research agent gets `tool:arxiv_*` and `tool:deepwiki__*`. Neither can access the other's tools.

---

## Skills

Skills are methodology documents that teach agents *how* to approach a task — when to use which tools, how to interpret results, what workflow to follow.

Tools provide **data access**. Skills provide **workflow**.

```
~/.ati/skills/compliance-screening/
├── skill.toml      # Metadata: tool bindings, keywords, dependencies
└── SKILL.md        # The methodology document
```

Skills auto-activate based on the agent's tool scope. If an agent has access to `ca_person_sanctions_search`, ATI automatically loads the `compliance-screening` skill because its `tools` binding includes that tool. Resolution walks: tool → provider → category → `depends_on` transitively.

```bash
ati skill list                              # List all skills
ati skill search "sanctions"                # Search by keyword
ati skill show compliance-screening         # Read the methodology
ati skill init my-skill --tools T1,T2       # Scaffold a new skill
ati skill install ./my-skill/               # Install
ati skill resolve                           # See what resolves for current scopes
```

---

## Works on Any Agent Harness

If your framework has a shell tool, ATI works. The pattern is always the same — system prompt + shell access. No custom tool wrappers, no SDK-specific adapters.

```python
system_prompt = """
You have ATI on your PATH. Available commands:
- `ati tool search <query>` — find tools by keyword
- `ati tool info <name>` — inspect a tool's schema
- `ati run <tool> --key value` — execute a tool
- `ati assist "<question>"` — ask for recommendations
"""

# Claude Agent SDK
agent = Agent(model="claude-sonnet-4-20250514", tools=[Bash()], system=system_prompt)

# OpenAI Agents SDK
agent = Agent(model="gpt-4o", tools=[shell_tool], instructions=system_prompt)

# LangChain
agent = create_react_agent(llm, [ShellTool()], prompt=system_prompt)
```

| SDK | Shell Mechanism | Example |
|-----|----------------|---------|
| [Claude Agent SDK](examples/claude-agent-sdk/) | Built-in `Bash` tool | ~100 lines |
| [OpenAI Agents SDK](examples/openai-agents-sdk/) | `@function_tool` async shell | ~100 lines |
| [Google ADK](examples/google-adk/) | `run_shell()` function tool | ~120 lines |
| [LangChain](examples/langchain/) | `ShellTool` (zero-config) | ~90 lines |
| [Codex CLI](examples/codex/) | Built-in shell agent | ~60 lines |
| [Pi](examples/pi/) | Built-in `bashTool` | ~100 lines |

Every example uses free, no-auth tools so you can run them immediately with just an LLM API key. See [examples/](examples/).

---

## Proxy Server

For production, run `ati proxy` as a central server holding secrets:

```bash
ati proxy --port 8090 --ati-dir ~/.ati            # From credentials file
ati proxy --port 8090 --ati-dir ~/.ati --env-keys  # From env vars
ati init --proxy --es256                           # Initialize with JWT keys
```

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Status — tool/provider/skill counts |
| `/call` | POST | Execute tool — `{tool_name, args}` |
| `/mcp` | POST | MCP JSON-RPC pass-through |
| `/help` | POST | LLM-powered discovery |
| `/skills` | GET | List/search skills |
| `/skills/:name` | GET | Skill content and metadata |
| `/skills/resolve` | POST | Resolve skills for scopes |
| `/.well-known/jwks.json` | GET | JWKS public key |

All endpoints except `/health` and JWKS require `Authorization: Bearer <JWT>` when JWT is configured.

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
    --output <FORMAT>   json, table, text [default: text]
    --verbose           Enable debug output
```

### Provider Management

```bash
ati provider import-openapi <spec> [--name NAME] [--include-tags T1,T2] [--dry-run]
ati provider inspect-openapi <spec> [--include-tags T1,T2]
ati provider add-mcp <name> --transport stdio|http [--command CMD] [--url URL] [--env 'KEY=${ref}']
ati provider add-cli <name> --command CMD [--default-args ARG] [--env 'KEY=${ref}'] [--env 'KEY=@{ref}']
ati provider list
ati provider info <name>
ati provider remove <name>
```

### Key & Token Management

```bash
ati key set <name> <value>                                     # Store a key
ati key list                                                   # List (values masked)
ati key remove <name>                                          # Delete

ati token keygen ES256|HS256                                   # Generate signing key
ati token issue --sub ID --scope "..." --ttl SECONDS           # Issue scoped JWT
ati token inspect <token>                                      # Decode without verification
ati token validate <token> [--key path|--secret hex]           # Full verification
```

### Output Formats

```bash
ati run finnhub_quote --symbol AAPL                    # Human-readable text (default)
ati --output json run finnhub_quote --symbol AAPL      # JSON for programmatic use
ati --output table run finnhub_quote --symbol AAPL     # Table for tabular data
```

---

## Building

```bash
cargo build                                            # Debug
cargo build --release                                  # Release
cargo build --release --target x86_64-unknown-linux-musl  # Static binary (no glibc)

cargo test                                             # 399 tests
bash scripts/test_skills_e2e.sh                        # Skill e2e tests
cargo test --test mcp_live_test -- --ignored           # Live MCP tests (needs API keys)
```

---

## Project Structure

```
ati/
├── Cargo.toml
├── manifests/              # 42 provider manifests (HTTP, MCP, OpenAPI, CLI)
├── specs/                  # 17 pre-downloaded OpenAPI 3.0 specs
├── examples/               # 6 SDK integrations (Claude, OpenAI, ADK, LangChain, Codex, Pi)
├── scripts/                # E2E test scripts
├── docs/
│   ├── SECURITY.md         # Threat model and security design
│   └── IDEAS.md            # Future directions
├── src/
│   ├── main.rs             # CLI entry point (clap)
│   ├── lib.rs              # Library crate
│   ├── cli/                # Command handlers
│   ├── core/               # Registry, MCP client, OpenAPI parser, HTTP executor,
│   │                       #   keyring, JWT, scopes, skills, response processing
│   ├── proxy/              # Client + server (axum)
│   ├── security/           # mlock/madvise/zeroize, sealed key file
│   └── output/             # JSON, table, text formatters
└── tests/                  # Unit, integration, e2e, live MCP
```

## License

Apache-2.0
