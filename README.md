# ATI — Agent Tools Interface

**Secure tool execution for AI agents. One binary, TOML manifests, encrypted credentials.**

ATI is a Rust CLI that sits between an AI agent and external APIs. The agent calls `ati call <tool>`, ATI injects the right credentials and makes the HTTP request. The agent never sees API keys — they exist only in ATI's memory-locked process space.

---

## Why ATI Exists

AI agents need to call external APIs — search the web, query databases, fetch documents, check stock prices. The standard approaches all have the same problem: **credentials are accessible to the agent**.

Whether you pass keys as environment variables, write them to config files, or embed them in MCP server configs, the agent process can read them. In a sandbox where the agent has shell access, `printenv`, `cat`, or `os.getenv()` is all it takes.

Beyond security, there's a tooling problem. Every new API integration requires writing code — an MCP server, a wrapper function, a plugin. For simple REST APIs (which is most of them), this is boilerplate: parse args, build URL, add auth header, make request, format response. The logic is identical across hundreds of tools; only the URL, auth method, and parameters differ.

ATI solves both problems:

1. **Security** — Credentials are AES-256-GCM encrypted, decrypted into `mlock()`'d memory, and never written to files, env vars, or process arguments.
2. **Manifest-driven tools** — New APIs are added by writing a TOML file. No code, no deployment, no build step.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│  Sandbox                                                 │
│                                                          │
│  ┌────────────┐   ati call web_search    ┌────────────┐ │
│  │   Agent    │ ────────────────────────▶│    ATI     │ │
│  │ (any LLM   │                          │   binary   │ │
│  │  harness)  │◀────────────────────────│            │ │
│  └────────────┘   structured result      └─────┬──────┘ │
│                                                │        │
│                       ┌────────────────────────┘        │
│                       │  decrypt keyring (in memory)     │
│                       │  inject auth headers/params      │
│                       │  enforce scopes                  │
│                       ▼                                  │
│                 ┌───────────┐     HTTPS      ┌────────┐ │
│                 │keyring.enc│ ──────────────▶│  API   │ │
│                 └───────────┘                └────────┘ │
│                                                          │
│  /run/ati/.key     session key (deleted after first read)│
│  ~/.ati/manifests/ tool definitions (TOML)               │
│  ~/.ati/scopes.json allowed tools + expiry               │
│  ~/.ati/skills/    methodology documents                 │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  Orchestrator (your backend)                             │
│                                                          │
│  1. Generate 256-bit session key                         │
│  2. Encrypt needed API keys → keyring.enc                │
│  3. Upload keyring.enc + session key + manifests         │
│  4. Start agent — ATI reads key, deletes file            │
└─────────────────────────────────────────────────────────┘
```

The agent harness can be anything — Claude Agent SDK, LangChain, CrewAI, a custom loop, a bash script. ATI is just a CLI binary on the `$PATH`. If the agent can run shell commands, it can use ATI.

## Tool Manifests

Every external API is defined in a TOML file:

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
description = "Get real-time stock price for a ticker symbol"
endpoint = "/quote"
method = "GET"
scope = "tool:finnhub_quote"

[tools.input_schema]
type = "object"
required = ["symbol"]

[tools.input_schema.properties.symbol]
type = "string"
description = "Stock ticker symbol (e.g. AAPL, MSFT)"

[tools.response]
format = "json"
```

Adding a new API is writing a TOML file and dropping it in the manifests directory. ATI handles:

- **Auth injection** — Bearer tokens, custom headers, query params, Basic auth
- **Request building** — GET params, POST JSON bodies, URL construction
- **Response processing** — JSONPath extraction, table/text/JSON formatting
- **Scope enforcement** — Agent can only call tools listed in its `scopes.json`

### Auth Types

| Type | Behavior | Example |
|------|----------|---------|
| `bearer` | `Authorization: Bearer <key>` | Most modern APIs |
| `header` | Custom header: `<auth_header_name>: <key>` | `X-API-KEY`, `X-Finnhub-Token` |
| `query` | URL param: `?<auth_query_name>=<key>` | `?api_key=...` (FRED, SerpAPI) |
| `basic` | HTTP Basic auth | Legacy APIs |
| `none` | No auth | PubMed, arXiv, SEC EDGAR |

See [`manifests/example.toml`](manifests/example.toml) for a fully annotated template.

## Security

API keys never appear in environment variables, files (after boot), or process arguments. See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

| Attack Vector | Mitigation |
|--------------|------------|
| `printenv` / `os.getenv()` | No secrets in env vars |
| `cat /run/ati/.key` | File deleted after first read |
| `strings /usr/local/bin/ati` | Binary has no embedded secrets |
| `cat ~/.ati/keyring.enc` | AES-256-GCM encrypted; session key is gone |
| `/proc/$(pgrep ati)/mem` | `ptrace` blocked by sandbox seccomp |
| Core dump / swap | `mlock()` + `madvise(DONTDUMP)` |

**Encryption**: AES-256-GCM with 256-bit random session key, 96-bit random nonce. Decrypted keys held in `mlock()`'d memory, `Zeroize`'d on drop.

## CLI

```bash
# Call a tool
ati call web_search --query "quantum computing breakthroughs"
ati call finnhub_quote --symbol AAPL
ati call getIncomeStatement --ticker MSFT --period annual --limit 5

# Discover tools
ati tools list                          # all available tools
ati tools list --provider finnhub       # tools from one provider
ati tools info getIncomeStatement       # schema, auth, description
ati tools providers                     # list all providers

# Skills (methodology docs for agents)
ati skills list
ati skills show financial-due-diligence

# LLM-powered discovery
ati help "I need to find SEC filings for a company"

# Auth status
ati auth status                         # scopes, expiry, agent info

# Output formats
ati --output json call finnhub_quote --symbol AAPL
ati --output table call getIncomeStatement --ticker AAPL --limit 3
```

## Skills

Skills are methodology documents — structured instructions that tell agents *how* to approach a task. They complement tools: tools provide data access, skills provide methodology.

```
~/.ati/skills/
  financial-due-diligence/
    SKILL.md          # Step-by-step methodology
  patent-search/
    SKILL.md
```

An agent might load `ati skills show financial-due-diligence` to get the research approach, then call `ati call getIncomeStatement` and `ati call sec_filing_search` to gather data.

## How ATI Relates to MCP

ATI is not a replacement for MCP. They solve different problems and work well together.

**MCP** (Model Context Protocol) is a protocol for connecting LLMs to tool servers. It supports multiple transports (stdio, HTTP+SSE, streamable HTTP) and provides a standard way for models to discover and invoke tools. MCP servers can maintain state, stream responses, and handle complex multi-turn interactions.

**ATI** is a credential broker and HTTP proxy. It doesn't define a protocol — it's a CLI binary that agents invoke via shell. Its job is narrow: decrypt credentials, make authenticated HTTP requests, enforce scopes, return results.

Where they overlap and where they don't:

| | MCP | ATI |
|---|-----|-----|
| **Good at** | Stateful tool servers, streaming, complex protocols, interactive use | Simple HTTP APIs, credential isolation, scope enforcement |
| **Transport** | stdio, HTTP+SSE, streamable HTTP | Shell invocation (`ati call ...`) |
| **State** | Servers can maintain sessions | Stateless per invocation |
| **Credential model** | Configured per-server (env vars, config) | Encrypted keyring, memory-locked |
| **Adding tools** | Write a server in any language | Write a TOML file |
| **Best for** | Databases, file systems, complex APIs with sessions | REST APIs, search endpoints, data lookups |

In practice, you'd use both: MCP for tools that need sessions or streaming (database queries, browser automation, code execution), and ATI for the long tail of REST APIs where each tool is just "make this HTTP request with this auth".

## Building

```bash
cd ati

# Debug build
cargo build

# Release build (for deployment)
cargo build --release

# Run tests
cargo test

# Static binary for Linux sandboxes (no glibc dependency)
cargo build --release --target x86_64-unknown-linux-musl
```

## Project Structure

```
ati/
├── Cargo.toml
├── README.md
├── docs/
│   ├── SECURITY.md          # Threat model and security design
│   └── IDEAS.md             # Future directions
├── manifests/               # TOML tool definitions
│   ├── example.toml         # Annotated template
│   ├── parallel.toml        # Web search & fetch
│   ├── pubmed.toml          # Medical literature (free)
│   ├── epo.toml             # European Patent Office
│   ├── middesk.toml         # Business verification
│   ├── arxiv.toml           # arXiv papers (free)
│   ├── crossref.toml        # Academic papers (free)
│   ├── semantic_scholar.toml # Semantic Scholar
│   ├── courtlistener.toml   # US legal cases
│   ├── hackernews.toml      # Hacker News (free)
│   ├── nhtsa.toml           # VIN decoder (free)
│   ├── clinicaltrials.toml  # ClinicalTrials.gov (free)
│   ├── sec_edgar.toml       # SEC EDGAR filings (free)
│   ├── _llm.toml            # Internal LLM for ati help
│   └── README.md            # Manifest format docs
├── src/
│   ├── main.rs              # CLI entry point (clap)
│   ├── cli/                 # Subcommand handlers
│   │   ├── call.rs          # ati call <tool> --args
│   │   ├── tools.rs         # ati tools list/info/providers
│   │   ├── skills.rs        # ati skills list/show/save
│   │   ├── help.rs          # ati help "query" (LLM-powered)
│   │   └── auth.rs          # ati auth status
│   ├── core/
│   │   ├── manifest.rs      # TOML manifest parsing
│   │   ├── http.rs          # HTTP execution + auth injection
│   │   ├── keyring.rs       # Encrypted credential storage
│   │   ├── scope.rs         # Scope enforcement
│   │   └── response.rs      # JSONPath extraction + formatting
│   ├── security/
│   │   ├── memory.rs        # mlock, madvise, zeroize
│   │   └── sealed_file.rs   # One-shot file read + unlink
│   ├── output/
│   │   ├── json.rs
│   │   ├── table.rs
│   │   └── text.rs
│   └── providers/
│       └── generic.rs       # Generic HTTP provider
└── tests/
    ├── manifest_test.rs
    ├── keyring_test.rs
    ├── scope_test.rs
    └── call_test.rs
```

## License

Apache-2.0
