[![CI](https://img.shields.io/github/actions/workflow/status/Parcha-ai/ati/ci.yml?branch=main&label=CI)](https://github.com/Parcha-ai/ati/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/Parcha-ai/ati)](LICENSE)
[![642 tests](https://img.shields.io/badge/tests-642-brightgreen)](#building)
[![PyPI](https://img.shields.io/pypi/v/ati-client)](https://pypi.org/project/ati-client/)
[![crates.io](https://img.shields.io/crates/v/agent-tools-interface)](https://crates.io/crates/agent-tools-interface)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS-blue)](#building)

# ATI — Agent Tools Interface

**Let your agents cook.**

One binary. Any agent framework. Every tool your agent needs.

ATI gives AI agents secure access to APIs, MCP servers, OpenAPI services, and local CLIs — through one unified interface. No custom tool wrappers. No per-SDK plumbing. Your agent calls `ati run <tool> --arg value` and ATI handles auth, protocol bridging, and response formatting.

---

## Install

### Pre-built binary (recommended)

Download the latest release for your platform:

```bash
# macOS (Apple Silicon)
curl -fsSL https://github.com/Parcha-ai/ati/releases/latest/download/ati-aarch64-apple-darwin.tar.gz \
  | tar xz && sudo mv ati /usr/local/bin/

# macOS (Intel)
curl -fsSL https://github.com/Parcha-ai/ati/releases/latest/download/ati-x86_64-apple-darwin.tar.gz \
  | tar xz && sudo mv ati /usr/local/bin/

# Linux (x86_64, static musl binary)
curl -fsSL https://github.com/Parcha-ai/ati/releases/latest/download/ati-x86_64-unknown-linux-musl.tar.gz \
  | tar xz && sudo mv ati /usr/local/bin/

# Linux (ARM64, static musl binary)
curl -fsSL https://github.com/Parcha-ai/ati/releases/latest/download/ati-aarch64-unknown-linux-musl.tar.gz \
  | tar xz && sudo mv ati /usr/local/bin/
```

### From source

```bash
# From crates.io
cargo install agent-tools-interface

# Or from git
cargo install --git https://github.com/Parcha-ai/ati.git

# Or clone and build
git clone https://github.com/Parcha-ai/ati.git && cd ati
cargo build --release
# Binary at target/release/ati
```

### Quick start

```bash
# Initialize ATI (creates ~/.ati/)
ati init

# Add a free API — zero config, no API key needed
ati provider import-openapi https://clinicaltrials.gov/api/v2/openapi.json

# Try it
ati run clinicaltrials:searchStudies --query.term "cancer" --pageSize 3
```

---

## See It Work

### Import an API from its OpenAPI spec

Finnhub publishes an OpenAPI spec with 110 endpoints — stock quotes, company financials, insider transactions, market news. One command turns it into tools:

```bash
# Import the spec — ATI auto-derives provider name, auth, endpoints
ati provider import-openapi https://finnhub.io/api/v2/spec.json
# → Saved manifest to ~/.ati/manifests/finnhub.toml
# → Imported 85 operations from "Finnhub — Real-time stock quotes..."

# Store your API key
ati key set finnhub_api_key "your-key-here"

# 85 tools, instantly available
ati tool list --provider finnhub | head -5
# ┌──────────────────────┬──────────┬────────────────────────────────┐
# │ DESCRIPTION          ┆ PROVIDER ┆ TOOL                           │
# ╞══════════════════════╪══════════╪════════════════════════════════╡
# │ Symbol Lookup        ┆ finnhub  ┆ finnhub:symbol-search         │
# │ Company Profile      ┆ finnhub  ┆ finnhub:company-profile2      │
# │ Quote                ┆ finnhub  ┆ finnhub:quote                 │
# │ Insider Transactions ┆ finnhub  ┆ finnhub:insider-transactions  │
# │ Basic Financials     ┆ finnhub  ┆ finnhub:company-basic-...     │
# └──────────────────────┴──────────┴────────────────────────────────┘
```

Every operation in the spec is now a tool. No `--name`, no TOML to write, no code to generate.

### Explore what you just added

```bash
# Agent asks: "research Apple stock — price, insider activity, and sentiment"
ati assist finnhub "research Apple stock — price, insider activity, and sentiment"
# Here are the exact commands to research Apple (AAPL) stock:
#
# 1. Current Price
#   ati run finnhub:quote --symbol AAPL
#
# 2. Insider Transactions
#   ati run finnhub:insider-transactions --symbol AAPL
#
# 3. News Sentiment
#   ati run finnhub:news-sentiment --symbol AAPL
```

`ati assist` answers like a knowledgeable colleague — which tools, what order, key params, gotchas — with commands you can run immediately.

### Run it

```bash
ati run finnhub:quote --symbol AAPL
# c: 262.52         ← current price
# d: -1.23          ← change
# dp: -0.4664       ← percent change
# h: 266.15         ← day high
# l: 261.43         ← day low
# o: 264.65         ← open
# pc: 263.75        ← previous close

ati run finnhub:insider-transactions --symbol AAPL
# data: [{name: "COOK TIMOTHY D", transactionCode: "S",
#   change: -59751, share: 3280295, transactionPrice: 257.57,
#   filingDate: "2025-10-03"}, ...]
```

The agent doesn't write HTTP requests. It doesn't parse JSON responses. It calls `ati run` and gets structured data back — real Apple stock price, real Tim Cook insider sells.

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
# │ Get a list of documentation topics for a GitHub ... ┆ deepwiki ┆ deepwiki:read_wiki_structure │
# │ View documentation about a GitHub repository.       ┆ deepwiki ┆ deepwiki:read_wiki_contents  │
# │ Ask any question about a GitHub repository ...      ┆ deepwiki ┆ deepwiki:ask_question        │
# └─────────────────────────────────────────────────────┴──────────┴───────────────────────────────┘

# Ask a question about any repo
ati run deepwiki:ask_question \
  --repoName "anthropics/claude-code" \
  --question "How does tool dispatch work?"
# Tool dispatch in Claude Code involves a dynamic system that handles both
# built-in and external Model Context Protocol (MCP) tools.
#
# 1. **Tool Name Check**: The system first checks if the tool name starts
#    with `mcp:`. If not, it's routed to the built-in tool pipeline.
# 2. **MCP Tool Resolution**: Server and tool names are extracted from the
#    `mcp:<servername>:<toolname>` format, the server is connected, and
#    the tool is invoked using a `call_tool` RPC.
# 3. **Output Handling**: Text output is returned; images are handled
#    during streaming.
```

MCP tools are namespaced as `<provider>:<tool_name>`. ATI handles JSON-RPC framing, session management, and auth injection.

---

## Built by Agents, for Agents

The examples above show a human typing commands. But ATI is designed so agents do all of this themselves — init, discover, store secrets, search across providers, and execute — with zero human intervention.

### 1. Agent discovers APIs and MCP servers

The agent can import any OpenAPI spec by URL — name auto-derived — and connect to MCP servers. No human has to write config files. ATI auto-creates `~/.ati/` on first use.

```bash
# Import APIs from their specs
ati provider import-openapi https://clinicaltrials.gov/api/v2/openapi.json
ati provider import-openapi https://finnhub.io/api/v1/openapi.json

# Connect MCP servers
ati provider add-mcp deepwiki --transport http \
  --url "https://mcp.deepwiki.com/mcp"
ati provider add-mcp linear --transport http \
  --url "https://mcp.linear.app/mcp" \
  --auth bearer --auth-key linear_api_key
```

### 3. Agent stores secrets

```bash
ati key set finnhub_api_key sk-your-key
ati key set linear_api_key lin_api_abc123

ati key list
# cerebras_api_key               csk-...tj3k
# finnhub_api_key                sk-...r-key
# github_token                   ghs-...O6RE
# linear_api_key                 lin-...c123
```

Keys are masked on output. The agent never sees raw values after storing them.

### 4. Agent searches across everything

This is the key part. The agent now has dozens of providers and hundreds of tools. It doesn't need to know which provider has what — it just asks.

```bash
ati assist "do we have a tool to search for stock prices?"
# Yes, we have several tools for stock prices:
#
# **For current/latest prices:**
# - `financial_datasets:getStockPriceSnapshot` — latest price snapshot
# - `finnhub:quote` — real-time quote data (US stocks)
#
# **For historical data:**
# - `financial_datasets:getStockPrices` — OHLCV data with date ranges
#
#   ati run financial_datasets:getStockPriceSnapshot --ticker AAPL
#   ati run finnhub:quote --symbol AAPL
#   ati run financial_datasets:getStockPrices --ticker AAPL \
#     --start_date 2024-12-01 --end_date 2024-12-31 --interval day

ati tool search "sanctions"
# PROVIDER          TOOL                            DESCRIPTION
# complyadvantage   ca_business_sanctions_search    Search sanctions lists for businesses
# complyadvantage   ca_person_sanctions_search      Search sanctions lists for individuals
```

`ati assist` answers naturally — which tools, why, and exact commands — like asking a colleague. `ati tool search` is instant and offline. The agent picks the right tool and runs it — no human in the loop.

### 5. It works with CLIs too

Wrap any CLI. The agent calls `ati run`, ATI spawns the subprocess with credentials injected. The agent never sees the raw token.

```bash
ati provider add-cli gh --command gh \
  --env 'GH_TOKEN=${github_token}'

# Agent asks how to use it
ati assist gh "how do I create a pull request?"
# Use the `pr create` subcommand:
#   ati run gh -- pr create --title "Fix login bug" --body "Resolves #123"
# Your branch must be pushed first. Add --draft to open as draft,
# or --base main --head feature/new-auth to target specific branches.

# Agent runs it
ati run gh -- repo view anthropics/claude-code --json name,stargazerCount
# name: claude-code
# stargazerCount: 73682
```

### 6. Security scales with your threat model

Three tiers — same `ati run` interface, different credential exposure:

| | Dev Mode | Local Mode | Proxy Mode |
|--|----------|-----------|------------|
| **Credentials** | Plaintext file | Encrypted keyring | Not in sandbox |
| **Key exposure** | Readable on disk | mlock'd memory | Never enters sandbox |
| **Setup** | `ati key set` | Keyring + session key | `ATI_PROXY_URL` |
| **Use case** | Local dev | Sandboxed agents | Untrusted sandboxes |

In proxy mode, the agent's sandbox has zero credentials. All calls route through `ati proxy`, which holds the keys, validates JWTs, and enforces per-tool scopes:

```bash
# Orchestrator issues a scoped token
ati token issue --sub agent-7 \
  --scope "tool:clinicaltrials:* tool:finnhub:* help" --ttl 3600

# Agent's sandbox — only has the binary and a JWT
export ATI_PROXY_URL=http://proxy:8090
export ATI_SESSION_TOKEN=eyJhbG...

# Same commands, routed through proxy, scoped to allowed tools
ati run clinicaltrials:searchStudies --query.term "cancer"  # ✓ allowed
ati run ca_person_sanctions_search --search_term "Name"      # ✗ denied
```

---

## Five Provider Types

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

3 OpenAPI specs ship out of the box: ClinicalTrials.gov, Finnhub, and Crossref. Additional specs are available in `contrib/specs/`.

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
ati run github:search_repositories --query "rust mcp"
ati run github:read_file --owner anthropics --repo claude-code --path README.md
```

### Skills — Install a skill, get tools automatically

A skill is a SKILL.md that teaches agents how to use an API — endpoints, auth patterns, parameters, workflows. On `ati skill install`, ATI reads the SKILL.md and uses a fast LLM call (Cerebras) to extract a full provider manifest automatically. No hand-written TOML, no OpenAPI spec needed. The SKILL.md is the only source of truth.

```bash
# From a git URL — ATI clones, reads SKILL.md, generates the manifest
ati skill install https://github.com/org/ati-skills#fal-generate
Generating manifest for 'fal' from SKILL.md...
Generated manifest for 'fal' at ~/.ati/manifests/fal.toml
  Hint: run `ati key set fal_api_key <your-key>` to configure credentials.
Installed 'fal-generate' to ~/.ati/skills/fal-generate

# From a local directory — same thing, ATI copies it into ~/.ati/skills/
ati skill install ./my-skills/fal-generate/

# Either way, tools are immediately available
ati tool list
┌─────────────────────────────────────────────────────────────────────────┬──────────┬─────────────┐
│ DESCRIPTION                                                             ┆ PROVIDER ┆ TOOL        │
╞═════════════════════════════════════════════════════════════════════════╪══════════╪═════════════╡
│ Submit a generation job to fal.ai queue. Returns request_id for polling. ┆ fal      ┆ fal:submit │
│ Check status of a queued fal.ai job.                                     ┆ fal      ┆ fal:status │
│ Get the result of a completed fal.ai job. Returns generated media URLs.  ┆ fal      ┆ fal:result │
│ Cancel a queued fal.ai job.                                              ┆ fal      ┆ fal:cancel │
└─────────────────────────────────────────────────────────────────────────┴──────────┴─────────────┘

# Set the key and cook
ati key set fal_api_key sk-your-key-here
ati assist "generate a portrait photo"
```

The skill creator writes the SKILL.md — that's it. ATI + Cerebras extracts everything: base URL, auth type, endpoints, parameters, HTTP methods. Local paths get copied into `~/.ati/skills/`, git URLs get cloned — either way the manifest is auto-generated and cached in `~/.ati/manifests/`.

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

**Example: Google Workspace — 25 APIs, one CLI.** ATI ships a pre-built manifest for [`gws`](https://github.com/googleworkspace/cli) (Google Workspace CLI). It covers Drive, Gmail, Calendar, Sheets, Docs, Slides, Chat, Admin, and 18 more services — all auto-discovered from Google's Discovery Service.

```bash
# Install gws, store your service account, go
npm install -g @googleworkspace/cli
ati key set google_workspace_credentials "$(cat service-account.json)"

# Agent asks how to create a presentation
ati assist google_workspace "how do I create a new Google Slides presentation?"
# Create a new presentation with:
#
#   ati run google_workspace -- slides presentations create \
#     --json '{"title": "My Presentation"}'
#
# --json is required for the request body (POST). title is the only required field.
# Returns the presentation ID and URL.
#
# Check the schema first for all available fields:
#   ati run google_workspace -- schema slides.presentations.create

# Agent runs it
ati run google_workspace -- slides presentations create \
  --json '{"title": "Q1 Review"}'

# List Drive files, search Gmail, check calendar
ati run google_workspace -- drive files list --params '{"pageSize": 10}'
ati run google_workspace -- gmail messages list \
  --params '{"userId": "me", "q": "from:ceo@company.com is:unread"}'
```

ATI materializes the service account JSON as a temp file (0600, wiped on exit) via the `@{key}` syntax — the agent never sees raw credentials. In proxy mode, service accounts create files in their own invisible Drive. To have files appear in a real user's Drive, enable [domain-wide delegation](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority) and set the impersonated user:

```bash
ati key set google_workspace_user analyst@company.com
# Now slides, docs, sheets are created in the analyst's Drive
```

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

ATI ships with 8 curated manifests covering the main provider types — HTTP, OpenAPI, MCP, and CLI. Use them as-is or as templates for your own. Additional manifests are available in `contrib/`.

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
$ ati tool info clinicaltrials:searchStudies
Tool:        clinicaltrials:searchStudies
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
  ati run clinicaltrials:searchStudies --query.term "cancer" --pageSize 10
```

### Assist — Like Asking a Colleague

`ati assist` answers naturally — which tools, what order, gotchas — not a numbered command list.

```bash
# Broad — searches all tools
$ ati assist "How do I screen a person for sanctions?"
# For sanctions screening, use `ca_person_sanctions_search`:
#
#   ati run ca_person_sanctions_search --search_term "John Smith" --fuzziness 0.6
#
# Set fuzziness between 0.4–0.8 depending on how strict you need matching.
# You'll also want to check PEP lists in the same pass:
#
#   ati run ca_person_pep_search --search_term "John Smith" --fuzziness 0.6

# Scoped to a provider — captures --help output for CLIs
$ ati assist gh "how do I create a pull request?"
# Use the `pr create` subcommand:
#
#   ati run gh -- pr create --title "Fix login bug" --body "Resolves #123"
#
# Your branch must be pushed to the remote first. Use `--base main` to
# target a specific branch, or `--draft` to open as a draft PR.

# Scoped to a tool — uses the full schema for precise commands
$ ati assist github:search_repositories "search private repos only"
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
| `tool:github:*` | Wildcard — all GitHub MCP tools |
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
  --scope "tool:web_search tool:github:* help" \
  --ttl 3600

# Inspect / validate
ati token inspect $ATI_SESSION_TOKEN
ati token validate $ATI_SESSION_TOKEN
```

A compliance agent gets `tool:ca_*` and `skill:compliance-screening`. A research agent gets `tool:arxiv_*` and `tool:deepwiki:*`. Neither can access the other's tools.

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

When an agent calls `ati assist`, skills are automatically loaded into the LLM's context — the agent gets methodology-aware recommendations, not just raw command syntax.

```bash
ati skill list                              # List all skills
ati skill search "sanctions"                # Search by keyword
ati skill show compliance-screening         # Read the methodology
ati skill read --tool fal:submit           # Dump all skills for a tool (agent-optimized)
ati skill init my-skill --tools T1,T2       # Scaffold a new skill
ati skill install ./my-skill/               # Install from local dir
ati skill install https://github.com/org/repo#skill-name  # Install from git URL
ati skill resolve                           # See what resolves for current scopes
```

### End-to-End Example: Image → Voice → Lip-Sync Video

This is a real workflow an agent ran using ATI — three fal.ai models chained together, guided by skills. The agent generated an image, synthesized speech, and produced a lip-synced talking head video.

**The result:** [fal-lipsync.mp4](docs/assets/fal-lipsync.mp4)

<img src="docs/assets/fal-streamer.jpg" width="280" align="right" style="margin-left: 16px" />

#### Step 1 — Generate an image with Flux

```bash
ati run fal:submit \
  --endpoint_id "fal-ai/flux/dev" \
  --prompt "Gen Z female tech streamer, colorful RGB lighting, confident smile" \
  --image_size "portrait_4_3"
# request_id: 1d491d8e-5c22-417b-a62b-471aa7f380e3
# status: IN_QUEUE

ati run fal:result --endpoint_id "fal-ai/flux" \
  --request_id "1d491d8e-5c22-417b-a62b-471aa7f380e3"
# images: [{url: "https://v3b.fal.media/files/.../streamer.jpg"}]
```

#### Step 2 — Generate speech with ElevenLabs (via fal)

```bash
ati run fal:submit \
  --endpoint_id "fal-ai/elevenlabs/tts/eleven-v3" \
  --text "Check out ATI — one binary, every tool your agent needs." \
  --voice_id "cjVigY5qzO86Huf0OWal"
# request_id: f9b24972-9ea9-47bd-9e6c-1fc8f48c70c5

ati run fal:result --endpoint_id "fal-ai/elevenlabs" \
  --request_id "f9b24972-9ea9-47bd-9e6c-1fc8f48c70c5"
# audio: {url: "https://v3b.fal.media/files/.../output.mp3"}
```

#### Step 3 — Lip-sync with VEED Fabric

```bash
ati run fal:submit \
  --endpoint_id "veed/fabric-1.0" \
  --image_url "https://v3b.fal.media/files/.../streamer.jpg" \
  --audio_url "https://v3b.fal.media/files/.../output.mp3" \
  --resolution "720p"
# request_id: 1c7bdab9-3572-45fe-829d-c5c87071e7d9

ati run fal:result --endpoint_id "veed/fabric-1.0" \
  --request_id "1c7bdab9-3572-45fe-829d-c5c87071e7d9"
# video: {url: "https://v3b.fal.media/files/.../lipsync.mp4"}
```

The agent didn't know any of this workflow. It asked `ati assist`:

```bash
ati assist fal "I want to create a lip-synced talking head video"
# To create a lip-synced talking head video, you'll use the VEED Fabric 1.0
# model on fal.ai. This requires:
# - A face image URL (portrait/headshot)
# - An audio URL (speech)
#
# Step 1: Generate speech with ElevenLabs TTS...
# Step 2: Submit the lip-sync job to veed/fabric-1.0...
# Step 3: Poll status and get result...
#
# Best Practices:
#   Face Image: Front-facing, good lighting, neutral expression
#   Audio: Clean speech, no background noise
#   Duration: Keep under 60 seconds per segment
```

`ati assist` loaded skills for `fal-generate`, `elevenlabs-tts-api`, and `veed-fabric-lip-sync` — giving the agent model-specific best practices, not just raw command syntax.

### Declaring Skills in Manifests

Providers can declare associated skills in their manifest. When an agent imports a provider, it can install the skills in one command:

```toml
# ~/.ati/manifests/fal.toml
[provider]
name = "fal"
base_url = "https://queue.fal.run"
skills = [
  "https://github.com/org/ati-skills#fal-generate",
  "https://github.com/org/ati-skills#veed-fabric-lip-sync",
]
```

```bash
# See what skills are declared
ati provider info fal
# Skills: 2 declared (1 installed, 1 not installed)
#   Install: ati provider install-skills fal

# Install all declared skills
ati provider install-skills fal
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
- `ati assist "<question>"` — ask which tools to use and how
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
| `/help` | POST | LLM-powered tool guidance |
| `/skills` | GET | List/search skills |
| `/skills/:name` | GET | Skill content and metadata |
| `/skills/resolve` | POST | Resolve skills for scopes |
| `/.well-known/jwks.json` | GET | JWKS public key |

All endpoints except `/health` and JWKS require `Authorization: Bearer <JWT>` when JWT is configured.

---

## Python SDK

The `ati-client` Python package provides orchestrator provisioning and JWT token utilities for integrating ATI into Python orchestrators.

```bash
pip install ati-client
```

### Orchestrator Provisioning

```python
from ati import AtiOrchestrator

orch = AtiOrchestrator(
    proxy_url="https://ati-proxy.example.com",
    secret="17332cf135d362f79a2ed700b13e1215978be1d6ae6e133d25b6b3f21fa10299",
)

# One call — returns env vars to inject into the sandbox
env_vars = orch.provision_sandbox(
    agent_id=f"sandbox:{sandbox_id}",
    tools=["finnhub_quote", "web_search", "github:*"],
    skills=["financial-analysis"],
    ttl_seconds=7200,
    rate={"tool:github:*": "10/hour"},
)
# env_vars = {"ATI_PROXY_URL": "...", "ATI_SESSION_TOKEN": "eyJ..."}
```

### Token Utilities

```python
from ati import issue_token, validate_token, inspect_token

token = issue_token(
    secret="17332cf135d362f79a...",
    sub="agent-7",
    scope="tool:web_search tool:finnhub_quote",
    ttl_seconds=3600,
)

claims = validate_token(token, secret="17332cf135d362f79a...")
print(claims.sub)       # "agent-7"
print(claims.scopes())  # ["tool:web_search", "tool:finnhub_quote"]
```

Tokens are HS256-signed JWTs fully compatible with the Rust proxy — tested bidirectionally. See [`ati-client/python/`](ati-client/python/) for full docs.

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
    assist     Ask which tools to use and how (LLM-powered)
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

cargo test                                             # 642 tests
bash scripts/test_skills_e2e.sh                        # Skill e2e tests
cargo test --test mcp_live_test -- --ignored           # Live MCP tests (needs API keys)
```

---

## Project Structure

```
ati/
├── Cargo.toml
├── manifests/              # 8 curated provider manifests (HTTP, MCP, OpenAPI, CLI)
├── specs/                  # 3 OpenAPI specs for curated providers
├── contrib/                # 35+ additional manifests and specs (gitignored)
├── skills/                 # Skill methodology documents
├── examples/               # 6 SDK integrations (Claude, OpenAI, ADK, LangChain, Codex, Pi)
├── ati-client/python/      # Python SDK (pip install ati-client)
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
