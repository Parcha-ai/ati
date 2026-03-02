# ATI — Agent Tools Interface

**Secure CLI that gives AI agents access to external tools without exposing API keys.**

ATI replaces three fragile patterns in agent infrastructure — MCP stdio servers, Python-wrapped HTTP tools, and hand-rolled skill scripts — with a single binary and a directory of TOML manifests.

---

## The Problem

AI agents running in sandboxes need to call external APIs: search the web, look up SEC filings, decode a VIN, check stock prices. Today this works through a stack of moving parts:

**MCP stdio servers** — Every tool is an `npx` process speaking JSON-RPC over stdin/stdout. Agents spin up 5+ node processes just to search the web and fetch financial data. MCP adds protocol overhead, requires a running Node runtime, and creates a process-per-provider model that doesn't scale.

**Python-wrapped HTTP tools** — For APIs too simple for MCP, the backend wraps `httpx.get()` calls in tool functions. Each tool is 100-300 lines of Python: parse args, check for API key in `os.getenv()`, build request, format response. Twenty tools means twenty files doing basically the same thing.

**Hardcoded skills** — Methodology documents baked into system prompts or saved as Markdown files, with no versioning, no discoverability, and no way for agents to request new ones at runtime.

All three patterns share the same core problem: **API keys live in environment variables** where the agent can read them with `printenv`, `cat /proc/self/environ`, or `os.getenv()`. The agent is simultaneously the user of the tool and a potential adversary.

## What ATI Does

ATI is a compiled Rust binary that:

1. **Reads encrypted credentials** from a keyring file, decrypts them in memory, and locks that memory so it never hits swap or core dumps
2. **Makes HTTP requests** on behalf of the agent, injecting auth headers/params that the agent never sees
3. **Enforces scopes** — the agent can only call tools it's been authorized to use, with expiration timestamps
4. **Formats responses** — JSONPath extraction, table formatting, text summarization — so agents get clean data instead of raw API dumps

From the agent's perspective, calling a tool looks like this:

```bash
# Search the web
ati call web_search --query "Parcha AI compliance"

# Get Apple's income statement
ati call getIncomeStatement --ticker AAPL --period annual --limit 5

# Look up a VIN
ati call vehicle_vin_lookup --vin 1HGBH41JXMN109186

# Discover available tools
ati tools list
```

No API keys. No Node.js. No JSON-RPC. Just a CLI call that returns structured text.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Sandbox (Daytona / Docker / Firecracker)            │
│                                                      │
│  ┌──────────┐   ati call web_search    ┌──────────┐ │
│  │  Agent    │ ────────────────────────▶│   ATI    │ │
│  │ (Claude)  │                          │  binary  │ │
│  │           │◀────────────────────────│          │ │
│  └──────────┘   structured text result  └────┬─────┘ │
│                                              │       │
│                    ┌─────────────────────────┘       │
│                    │  reads encrypted keyring         │
│                    │  injects auth headers            │
│                    │  enforces scopes                 │
│                    ▼                                  │
│              ┌───────────┐      HTTPS       ┌──────┐│
│              │keyring.enc│  ──────────────▶  │ API  ││
│              └───────────┘                   └──────┘│
│                                                      │
│  /run/ati/.key  (session key, deleted after read)    │
│  ~/.ati/manifests/*.toml  (tool definitions)         │
│  ~/.ati/scopes.json  (allowed tools + expiry)        │
│  ~/.ati/skills/  (methodology docs)                  │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  Orchestrator (parcha-backend)                       │
│                                                      │
│  1. Generate 256-bit session key                     │
│  2. Encrypt needed API keys → keyring.enc            │
│  3. Upload keyring.enc + session key + manifests     │
│  4. Agent starts, ATI reads key, deletes file        │
└─────────────────────────────────────────────────────┘
```

### Security Model

API keys never appear in environment variables, files, or process arguments. See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

| Attack Vector | Mitigation |
|--------------|------------|
| `printenv` / `os.getenv()` | No secrets in env vars |
| `cat /run/ati/.key` | Deleted after first read |
| `strings /usr/local/bin/ati` | Binary has no embedded secrets |
| `cat ~/.ati/keyring.enc` | AES-256-GCM encrypted; session key is gone |
| `/proc/$(pgrep ati)/mem` | `ptrace` blocked by sandbox seccomp |
| Core dump / swap | `mlock()` + `madvise(DONTDUMP)` |

## Tool Manifests

Every external API is defined in a TOML file. No Python, no JavaScript, no custom classes:

```toml
[provider]
name = "finnhub"
description = "Real-time stock quotes and financial metrics"
base_url = "https://finnhub.io/api/v1"
auth_type = "header"
auth_header_name = "X-Finnhub-Token"
auth_key_name = "finnhub_api_key"

[[tools]]
name = "finnhub_quote"
description = "Get current stock price for a ticker symbol"
endpoint = "/quote"
method = "GET"
scope = "tool:market_data_finnhub"

[tools.input_schema]
type = "object"
required = ["symbol"]

[tools.input_schema.properties.symbol]
type = "string"
description = "Stock ticker symbol (e.g. AAPL, MSFT)"

[tools.response]
format = "json"
```

That's it. No 200-line Python file. No `httpx.AsyncClient`. No `os.getenv("FINNHUB_API_KEY")`. ATI handles auth injection, request building, and response formatting.

### Auth Types

| Type | Header/Param | Example APIs |
|------|-------------|--------------|
| `bearer` | `Authorization: Bearer <key>` | Parallel.ai, Middesk, Semantic Scholar |
| `header` | Custom header name | `X-API-KEY` (Financial Datasets), `X-Finnhub-Token` |
| `query` | URL query parameter | `?api_key=<key>` (FRED, SerpAPI) |
| `basic` | HTTP Basic auth | Legacy APIs |
| `none` | No auth needed | PubMed, arXiv, ClinicalTrials.gov, SEC EDGAR |

### Manifest Directory

See [`manifests/`](manifests/) for all available providers, or [`manifests/example.toml`](manifests/example.toml) for a fully annotated template.

## CLI Reference

```
ati — Agent Tools Interface

USAGE:
    ati [OPTIONS] <COMMAND>

COMMANDS:
    call       Execute a tool by name
    tools      List, inspect, and discover tools
    skills     Manage skill files (methodology docs for agents)
    help       LLM-powered tool discovery
    auth       Authentication and scope information
    version    Print version information

OPTIONS:
    --output <FORMAT>   Output format: json, table, text [default: text]
    --verbose           Enable debug output
```

### Common Usage

```bash
# Call a tool with arguments
ati call web_search --query "Parcha AI" --max_results 5

# List all tools available to this agent
ati tools list

# List tools from a specific provider
ati tools list --provider finnhub

# Show detailed info about a tool (schema, auth, description)
ati tools info getIncomeStatement

# List all providers
ati tools providers

# Check auth status and scope expiry
ati auth status

# LLM-powered discovery — ask what tool to use
ati help "I need to look up a company's SEC filings"
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

## Skills

Skills are methodology documents — structured instructions that tell agents *how* to approach a research task. They live in `~/.ati/skills/<skill-name>/SKILL.md`.

```bash
# List available skills
ati skills list

# Read a skill
ati skills show financial-due-diligence

# Save a new skill from a directory
ati skills save ./my-skill/
```

Skills complement tools: tools provide *data access*, skills provide *methodology*. An agent researching a company might use `ati skills show financial-due-diligence` to get the approach, then `ati call getIncomeStatement` to get the data.

## Why Not Just MCP?

MCP (Model Context Protocol) is excellent for interactive, local tool use — connecting Claude Desktop to a Postgres database or a Git repo. But it has friction in production agent infrastructure:

| Concern | MCP | ATI |
|---------|-----|-----|
| **Process model** | One process per server, JSON-RPC over stdio | Single binary, all providers |
| **Runtime** | Needs Node.js (`npx`) or Python | Compiled Rust, zero dependencies |
| **Auth** | Keys in env vars or config files | Encrypted keyring, memory-locked |
| **Scope control** | All-or-nothing per server | Per-tool scopes with expiry |
| **Adding a tool** | Write a server (JS/Python), register, deploy | Write a TOML file |
| **Sandbox fit** | Heavyweight — 5 node processes for 5 providers | One binary, ~5MB |

ATI isn't a replacement for MCP everywhere. MCP is still used for local-only tools (Chrome DevTools, computer-use) and admin-only tools (GitHub, Sentry, Linear) where the user *is* the operator. ATI targets the specific case of **agents in sandboxes calling HTTP APIs with secrets they shouldn't see**.

## Building

```bash
cd ati

# Build (debug)
cargo build

# Build (release, for sandbox deployment)
cargo build --release

# Run tests
cargo test

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
├── Cargo.toml              # Dependencies
├── README.md               # This file
├── docs/
│   ├── SECURITY.md         # Threat model and security design
│   └── IDEAS.md            # Future directions (not building yet)
├── manifests/              # TOML tool definitions
│   ├── example.toml        # Annotated template
│   ├── parallel.toml       # Web search & fetch
│   ├── pubmed.toml         # Medical literature
│   ├── epo.toml            # Patent search
│   ├── middesk.toml        # Business verification
│   ├── _llm.toml           # Internal LLM for ati help
│   └── README.md           # Manifest format docs
├── src/
│   ├── main.rs             # CLI entry point (clap)
│   ├── cli/                # Subcommand handlers
│   │   ├── call.rs         # ati call <tool> --args
│   │   ├── tools.rs        # ati tools list/info/providers
│   │   ├── skills.rs       # ati skills list/show/save
│   │   ├── help.rs         # ati help "query" (LLM-powered)
│   │   └── auth.rs         # ati auth status
│   ├── core/               # Core logic
│   │   ├── manifest.rs     # TOML manifest parsing
│   │   ├── http.rs         # HTTP request execution + auth injection
│   │   ├── keyring.rs      # Encrypted credential storage
│   │   ├── scope.rs        # Tool scope enforcement
│   │   └── response.rs     # JSONPath extraction + formatting
│   ├── security/           # Memory safety
│   │   ├── memory.rs       # mlock, madvise, zeroize
│   │   └── sealed_file.rs  # One-shot file read + unlink
│   ├── output/             # Output formatters
│   │   ├── json.rs
│   │   ├── table.rs
│   │   └── text.rs
│   └── providers/          # Provider-specific logic
│       └── generic.rs      # Generic HTTP provider (handles all manifests)
└── tests/                  # Integration tests
    ├── manifest_test.rs
    ├── keyring_test.rs
    ├── scope_test.rs
    └── call_test.rs
```

## Roadmap

- **Phase 1** (done): Core binary — keyring encryption, manifest loading, HTTP execution, scope enforcement
- **Phase 2** (done): Sandbox integration — JWT proxy, session key delivery, Daytona client wiring
- **Phase 3** (current): Replace third-party MCP servers with TOML manifests — Financial Datasets, Finnhub, FRED, SerpAPI, free academic/legal/medical APIs
- **Phase 4** (planned): `ati_provisioner.py` — orchestrator-side keyring generation, scope building, manifest upload
- **Future**: Progressive learning registry, WASM plugins, tool composition pipelines (see [docs/IDEAS.md](docs/IDEAS.md))

## License

Apache-2.0
