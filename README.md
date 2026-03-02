<p align="center">
  <h1 align="center">ATI</h1>
  <p align="center"><strong>Agent Tools Interface</strong></p>
  <p align="center">The unified tool layer for AI agents. MCP servers, REST APIs, CLIs, and skills — one secure binary.</p>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> &nbsp;&bull;&nbsp;
  <a href="#built-for-agents">Built for Agents</a> &nbsp;&bull;&nbsp;
  <a href="#security">Security</a> &nbsp;&bull;&nbsp;
  <a href="#tool-manifests">Manifests</a> &nbsp;&bull;&nbsp;
  <a href="#vision">Vision</a> &nbsp;&bull;&nbsp;
  <a href="docs/SECURITY.md">Security Docs</a>
</p>

---

## The Problem

AI agents need tools. Search the web, query a database, check a stock price, file a patent search, decode a VIN. Today, giving an agent access to an external API means one of:

1. **Expose API keys** in environment variables, config files, or MCP server configs — readable by the agent with `printenv`, `cat`, or `os.getenv()`
2. **Write integration code** for every API — an MCP server, a wrapper function, a plugin — even when the logic is always the same: parse args, add auth, make request, format response
3. **Manage a zoo of runtimes** — Node.js for this MCP server, Python for that wrapper, Go for this CLI tool

The result: agents swim in leaked credentials, teams drown in boilerplate, and every new API is a deployment.

## The Solution

ATI is a single Rust binary that unifies how agents interact with external tools.

```bash
# The agent runs this. That's it.
ati call web_search --query "quantum computing breakthroughs 2026"
```

No API keys in the environment. No MCP server to spin up. No Python wrapper. ATI decrypts the credential from its encrypted keyring, injects the auth header, makes the request, formats the response, and returns it. The agent never sees the key.

### Quickstart

```bash
# Install
cargo install --path .

# Agent discovers what tools are available
ati tools list

# Agent calls a tool
ati call finnhub_quote --symbol AAPL

# Agent asks what tool to use (LLM-powered)
ati help "I need to look up SEC filings for Tesla"

# Agent loads a research methodology
ati skills show financial-due-diligence
```

---

## Built for Agents

ATI isn't a developer tool that agents happen to use. It's designed from the ground up for autonomous AI agents operating in sandboxed environments.

### Natural Language Tool Discovery

Agents don't read manifests. They ask questions.

```bash
$ ati help "I need to find academic papers about transformer architectures"

Found 3 relevant tools:

  academic_search_arxiv        Search arXiv preprint repository
  academic_search_crossref     Search published papers via Crossref
  academic_search_semantic_scholar  Search Semantic Scholar with citation data

Suggested: academic_search_semantic_scholar
  Best for finding papers with citation context and influence scores.

Example:
  ati call academic_search_semantic_scholar --query "transformer attention mechanism" --limit 10
```

`ati help` uses a fast LLM to match natural language queries to available tools, explains *why* it recommends one, and gives a ready-to-run command. The agent can pipe this directly into its next action.

### Context-Aware Output

Large API responses waste tokens. ATI processes responses *before* they reach the agent:

```bash
# JSONPath extraction — only return what matters
ati call getIncomeStatement --ticker AAPL --limit 20
# Response config extracts $.income_statements[*].{revenue, net_income, period}

# Structured formats the agent can parse efficiently
ati --output table call finnhub_quote --symbol AAPL
ati --output json call web_search --query "Parcha AI"
```

Every manifest can define a `[tools.response]` section with JSONPath extraction and output format. The agent gets clean, minimal data instead of 50KB JSON dumps. Inspired by context optimization approaches like [Context+](https://github.com/ForLoopCodes/contextplus) — reducing token waste is a first-class concern.

### Skill Discovery and Methodology

Tools give agents data. Skills give agents *judgment*.

```bash
$ ati skills list

  financial-due-diligence     Step-by-step financial analysis methodology
  patent-search               Patent landscape analysis approach
  adverse-media-screening     Media screening with source verification
  competitive-intel           Competitive intelligence gathering framework

$ ati skills show financial-due-diligence

# Financial Due Diligence
## Step 1: Company Identification
  Verify entity using SEC EDGAR CIK lookup and cross-reference with...
## Step 2: Financial Health
  Pull 3 years of income statements, balance sheets, and cash flows...
## Step 3: Risk Signals
  Check for material weaknesses, auditor changes, restatements...
```

Skills are versioned methodology documents in `~/.ati/skills/<name>/SKILL.md`. They're the "how to think about this" that turns a tool-calling agent into a domain expert. Think [Tessl](https://tessl.io/) for agent skills — structured context that makes agents behave like experienced practitioners, not just API callers.

---

## Architecture

```mermaid
graph TB
    subgraph Sandbox
        Agent["Agent<br/><small>Claude SDK, LangChain,<br/>CrewAI, custom harness</small>"]
        ATI["ATI Binary<br/><small>Rust, ~5MB, zero deps</small>"]
        JWT["session.jwt<br/><small>signed token with<br/>scopes + keyring key</small>"]
        Keyring["keyring.enc<br/><small>AES-256-GCM</small>"]
        Skills["~/.ati/skills/<br/><small>methodology docs</small>"]
        Manifests["~/.ati/manifests/<br/><small>TOML tool defs</small>"]
    end

    subgraph APIs["External APIs"]
        API1["REST APIs<br/><small>Finnhub, FRED, SerpAPI...</small>"]
        API2["Free APIs<br/><small>PubMed, arXiv, SEC...</small>"]
        MCP["MCP Servers<br/><small>stdio, HTTP+SSE,<br/>streamable HTTP</small>"]
    end

    subgraph Orchestrator["Orchestrator (your backend)"]
        Sign["Sign JWT with scopes<br/>+ encryption key"]
        Encrypt["Encrypt API keys<br/>→ keyring.enc"]
        Upload["Upload to sandbox"]
    end

    Agent -->|"ati call web_search"| ATI
    ATI -->|"decrypt + inject auth"| API1
    ATI -->|"no auth needed"| API2
    ATI -->|"proxy MCP calls"| MCP
    ATI --- JWT
    ATI --- Keyring
    ATI --- Manifests
    Agent -->|"ati skills show"| Skills

    Sign --> Encrypt --> Upload -->|"session.jwt + keyring.enc"| JWT

    style ATI fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style JWT fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    style Agent fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

### The Session JWT

Everything about a sandbox session — scopes, expiry, agent identity, and the keyring decryption key — lives in a single signed JWT. No separate `scopes.json`. No standalone HMAC. One token, one verification, one source of truth.

```json
{
  "sub": "financial-analyst-42",
  "iss": "orchestrator",
  "iat": 1741089600,
  "exp": 1741176000,
  "scopes": [
    "tool:finnhub_*",
    "tool:getIncomeStatement",
    "tool:getBalanceSheet",
    "tool:fred_*"
  ],
  "keyring_key": "base64-encoded-256-bit-AES-key",
  "keyring_hash": "sha256-of-keyring.enc"
}
```

The JWT is signed by the orchestrator's private key. ATI validates the signature, reads the scopes, extracts the keyring decryption key, verifies `keyring_hash` matches the `keyring.enc` on disk, then decrypts. The JWT file is deleted after first read — same as before, but now scopes and key are cryptographically bound together.

**Why a JWT instead of separate files:**
- **Tamper-proof scopes** — signature verification, not a bolted-on HMAC
- **Bound together** — scopes and keyring key travel as one signed artifact; can't mix-and-match
- **Standard format** — any language can generate JWTs; any tool can verify them
- **One file to manage** — orchestrator writes one JWT, ATI reads one JWT, done

### Key Delivery Flow

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant S as Sandbox
    participant ATI as ATI Binary
    participant API as External API

    O->>O: Generate 256-bit AES key
    O->>O: Encrypt needed API keys → keyring.enc
    O->>O: Sign JWT (scopes + AES key + expiry)
    O->>S: Upload keyring.enc + manifests + session.jwt
    O->>S: Start agent

    Note over ATI: First invocation
    ATI->>S: Read /run/ati/session.jwt
    ATI->>S: unlink() JWT file immediately
    ATI->>ATI: Verify JWT signature (orchestrator public key)
    ATI->>ATI: Check exp claim (not expired)
    ATI->>ATI: Extract AES key from JWT claims
    ATI->>ATI: Verify keyring_hash matches keyring.enc
    ATI->>ATI: Decrypt keyring (AES-256-GCM)
    ATI->>ATI: mlock() decrypted memory
    ATI->>ATI: Zero AES key from stack

    Note over ATI: Agent calls tool
    ATI->>ATI: Check JWT scopes (cached in memory)
    ATI->>ATI: Load manifest for tool
    ATI->>ATI: Inject auth from keyring
    ATI->>API: HTTPS request
    API-->>ATI: Response
    ATI->>ATI: JSONPath extract + format
    ATI-->>S: Structured result to stdout
```

The agent harness can be anything — [Claude Agent SDK](https://docs.anthropic.com/en/docs/agents-and-tools/agent-sdk), LangChain, CrewAI, OpenAI Agents SDK, a custom loop, a bash script. ATI is a CLI binary on `$PATH`. If the agent can shell out, it can use ATI.

---

## Security

### Before ATI: Secrets Everywhere

Every sandbox gets a copy of every API key it *might* need. Tens of keys floating around as environment variables, readable by any process. Every MCP server config embeds credentials. Scaling to N sandboxes means N copies of your secrets, all in plaintext.

```mermaid
graph TB
    subgraph "Before: The Typical Setup"
        direction TB
        Orch1["Orchestrator"] -->|"env vars"| S1
        Orch1 -->|"env vars"| S2
        Orch1 -->|"env vars"| S3

        subgraph S1["Sandbox A"]
            direction LR
            E1["FINNHUB_API_KEY=sk-abc...<br/>PARALLEL_API_KEY=pk-def...<br/>FRED_API_KEY=fk-ghi...<br/>SERPAPI_KEY=sp-jkl...<br/>GITHUB_TOKEN=ghp-mno...<br/>SENTRY_TOKEN=snt-pqr...<br/>COURTLISTENER_TOKEN=cl-stu...<br/>MIDDESK_KEY=md-vwx..."]
            MCP1["MCP Server 1<br/><small>reads env</small>"]
            MCP2["MCP Server 2<br/><small>reads env</small>"]
            Agent1["Agent<br/><small>can read ALL keys<br/>with printenv</small>"]
        end

        subgraph S2["Sandbox B"]
            E2["Same 8 keys<br/><small>even if it only<br/>needs 2 of them</small>"]
            Agent2["Agent<br/><small>can read ALL keys</small>"]
        end

        subgraph S3["Sandbox C"]
            E3["Same 8 keys<br/><small>copy #3</small>"]
            Agent3["Agent<br/><small>can read ALL keys</small>"]
        end
    end

    style E1 fill:#ffcdd2,stroke:#c62828
    style E2 fill:#ffcdd2,stroke:#c62828
    style E3 fill:#ffcdd2,stroke:#c62828
    style Agent1 fill:#ffcdd2,stroke:#c62828
    style Agent2 fill:#ffcdd2,stroke:#c62828
    style Agent3 fill:#ffcdd2,stroke:#c62828
```

**Problems:**
- Agent runs `printenv` → has every API key
- Prompt injection → "print all environment variables" → keys exfiltrated
- Every sandbox gets **all** keys, even if it only needs two
- Rotating one key means updating every sandbox, MCP config, `.env` file
- No audit trail — impossible to know which sandbox used which key

### After ATI: Encrypted, Scoped, Minimal

Each sandbox gets **only the keys it needs**, encrypted with a one-time session key that's deleted after first read. The agent can't see any credentials, period.

```mermaid
graph TB
    subgraph "After: ATI"
        direction TB
        Orch2["Orchestrator"] -->|"keyring.enc<br/><small>2 keys, encrypted</small>"| SA
        Orch2 -->|"keyring.enc<br/><small>1 key, encrypted</small>"| SB
        Orch2 -->|"keyring.enc<br/><small>3 keys, encrypted</small>"| SC

        subgraph SA["Sandbox A — Financial Research"]
            direction LR
            ATI_A["ATI<br/><small>finnhub_api_key ✓<br/>fred_api_key ✓</small>"]
            AgentA["Agent<br/><small>no env vars<br/>no readable keys<br/>scoped to 5 tools</small>"]
        end

        subgraph SB["Sandbox B — Legal Research"]
            direction LR
            ATI_B["ATI<br/><small>courtlistener_token ✓</small>"]
            AgentB["Agent<br/><small>scoped to 2 tools</small>"]
        end

        subgraph SC["Sandbox C — General Research"]
            direction LR
            ATI_C["ATI<br/><small>parallel_api_key ✓<br/>serpapi_key ✓<br/>finnhub_api_key ✓</small>"]
            AgentC["Agent<br/><small>scoped to 8 tools</small>"]
        end
    end

    style ATI_A fill:#c8e6c9,stroke:#2e7d32
    style ATI_B fill:#c8e6c9,stroke:#2e7d32
    style ATI_C fill:#c8e6c9,stroke:#2e7d32
    style AgentA fill:#e8f5e9,stroke:#2e7d32
    style AgentB fill:#e8f5e9,stroke:#2e7d32
    style AgentC fill:#e8f5e9,stroke:#2e7d32
```

**What changed:**
- Agent runs `printenv` → nothing. Zero secrets in the environment.
- Each sandbox gets a **unique encrypted keyring** with only the keys its tools need
- JWT deleted after ATI's first invocation — can't re-read scopes or decryption key
- Scopes are JWT claims — signed by the orchestrator, cryptographically tamper-proof
- Key rotation happens once in the orchestrator — JWTs and keyrings are fresh per session

### Scoped Permissions

Not every agent should access every tool. Scopes live inside the signed JWT — the orchestrator decides what each sandbox can do at session creation time.

```mermaid
graph LR
    subgraph "Orchestrator signs a JWT per sandbox"
        O["Orchestrator"]
    end

    O -->|"JWT: scopes=[finnhub_*, fred_*]<br/>keyring: 2 keys"| SA["Sandbox A<br/><b>Financial Analyst</b>"]
    O -->|"JWT: scopes=[courtlistener, sec_*]<br/>keyring: 1 key"| SB["Sandbox B<br/><b>Legal Researcher</b>"]
    O -->|"JWT: scopes=[web_*, finnhub_*, arxiv]<br/>keyring: 3 keys"| SC["Sandbox C<br/><b>General Agent</b>"]

    subgraph SA_tools["Sandbox A can use:"]
        T1["finnhub_quote ✓"]
        T2["finnhub_profile ✓"]
        T3["getIncomeStatement ✓"]
        T4["getBalanceSheet ✓"]
        T5["fred_series_observations ✓"]
    end

    subgraph SB_tools["Sandbox B can use:"]
        T6["legal_search_courtlistener ✓"]
        T7["sec_filing_search ✓"]
    end

    subgraph SC_tools["Sandbox C can use:"]
        T8["web_search ✓"]
        T9["web_fetch ✓"]
        T10["finnhub_quote ✓"]
        T11["academic_search_arxiv ✓"]
        T12["hackernews_stories ✓"]
    end

    SA --- SA_tools
    SB --- SB_tools
    SC --- SC_tools

    style SA fill:#e3f2fd,stroke:#1565c0
    style SB fill:#fff3e0,stroke:#ef6c00
    style SC fill:#f3e5f5,stroke:#7b1fa2
```

The JWT `scopes` claim is all ATI needs:

```json
{
  "sub": "legal-researcher-7",
  "exp": 1741176000,
  "scopes": ["tool:legal_search_courtlistener", "tool:sec_*"],
  "keyring_key": "...",
  "keyring_hash": "..."
}
```

**How scoping works:**
- **Wildcard patterns** — `tool:finnhub_*` grants access to all Finnhub tools
- **JWT expiry** — the `exp` claim is the session expiry; no separate per-scope timestamps needed (if you want fine-grained expiry per scope, you sign a new JWT)
- **Signed, not HMACd** — the orchestrator's private key signs the JWT; ATI verifies with the public key. The agent can't forge scopes.
- **Per-sandbox** — each sandbox gets exactly the permissions its task requires
- **Deny by default** — if a tool isn't in the JWT scopes, `ati call` returns a clear error
- **Keyring bound to scopes** — the keyring only contains keys for the scoped tools, and the JWT's `keyring_hash` binds them together. Can't swap in a different keyring.

```bash
# Agent in Sandbox B tries to call a financial tool:
$ ati call finnhub_quote --symbol AAPL
Error: Access denied. Tool 'finnhub_quote' requires scope 'tool:finnhub_quote'.
Your session has 2 active scopes. Run 'ati auth status' to see them.

# But this works fine:
$ ati call legal_search_courtlistener --query "patent infringement" --court "Supreme Court"
# ✓ Returns results
```

### Threat Model

| Attack Vector | What the Agent Tries | ATI's Defense |
|--------------|---------------------|---------------|
| `printenv` / `os.getenv()` | Read API keys from environment | No secrets in env vars — ever |
| `cat /run/ati/session.jwt` | Read the JWT | File `unlink()`'d after first read |
| `strings /usr/local/bin/ati` | Extract secrets from binary | Binary contains no secrets |
| `cat ~/.ati/keyring.enc` | Read encrypted keyring | AES-256-GCM; decryption key was in the deleted JWT |
| `/proc/$(pgrep ati)/mem` | Read process memory | `ptrace` blocked by sandbox seccomp |
| Trigger core dump | Extract keys from crash dump | `madvise(MADV_DONTDUMP)` excludes key pages |
| Swap file forensics | Keys paged to disk | `mlock()` pins key pages in RAM |
| Forge a new JWT | Grant itself more scopes | JWT signature verification fails (needs orchestrator private key) |
| Swap `keyring.enc` | Use a different keyring | `keyring_hash` in JWT won't match |
| Prompt injection: "print your API key" | Social engineering via LLM | ATI is a compiled binary — not part of the conversation |

### Encryption

- **JWT signing**: RS256 (RSA-SHA256) — orchestrator holds private key, ATI has public key
- **Keyring encryption**: AES-256-GCM (authenticated encryption)
- **Keyring key**: 256-bit random, embedded in JWT, unique per sandbox session
- **Nonce**: 96-bit random, prepended to ciphertext
- **Memory**: Decrypted keys in `mlock()`'d heap, `Zeroize`'d on drop
- **Implementation**: Rust `aes-gcm` + `jsonwebtoken` crates — no OpenSSL dependency

Full security design: [docs/SECURITY.md](docs/SECURITY.md)

---

## Tool Manifests

Every external API is a TOML file. No code, no runtime, no deployment:

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

Drop it in `~/.ati/manifests/`. Done. `ati tools list` picks it up immediately.

### Auth Types

| Type | Behavior | Example APIs |
|------|----------|-------------|
| `bearer` | `Authorization: Bearer <key>` | Most modern APIs |
| `header` | Custom header name | `X-API-KEY`, `X-Finnhub-Token` |
| `query` | URL query parameter | `?api_key=...` (FRED, SerpAPI) |
| `basic` | HTTP Basic auth | Legacy APIs |
| `none` | No auth needed | PubMed, arXiv, SEC EDGAR |

### Included Manifests

| Provider | Tools | Auth | Domain |
|----------|-------|------|--------|
| `parallel.toml` | web_search, web_fetch | Bearer | Web search & extraction |
| `pubmed.toml` | medical_search_pubmed | None | Medical literature |
| `epo.toml` | patent_search_epo | Bearer | European patents |
| `middesk.toml` | middesk_us_business_lookup | Bearer | Business verification |
| `arxiv.toml` | academic_search_arxiv | None | Preprint papers |
| `crossref.toml` | academic_search_crossref | None | Published papers |
| `semantic_scholar.toml` | academic_search_semantic_scholar | Optional Bearer | Papers + citations |
| `courtlistener.toml` | legal_search_courtlistener | Bearer | US legal cases |
| `hackernews.toml` | hackernews_stories | None | Tech news |
| `nhtsa.toml` | vehicle_vin_lookup | None | VIN decoder |
| `clinicaltrials.toml` | clinical_trial_search | None | Clinical trials |
| `sec_edgar.toml` | sec_filing_search | None | SEC filings |

See [`manifests/example.toml`](manifests/example.toml) for a fully annotated template.

---

## Registry Management

You don't have to hand-write TOML files. ATI's CLI can add providers, tools, secrets, and MCP servers interactively:

### Add a REST API

```bash
# Interactive — ATI asks for base URL, auth type, endpoints
$ ati add provider

  Provider name: finnhub
  Base URL: https://finnhub.io/api/v1
  Auth type (bearer/header/query/basic/none): header
  Auth header name [X-Api-Key]: X-Finnhub-Token
  Key name in keyring: finnhub_api_key

  Created manifests/finnhub.toml

  Add a tool? [Y/n] y
  Tool name: finnhub_quote
  Description: Get real-time stock price
  Endpoint: /quote
  Method (GET/POST) [GET]: GET
  Required params (comma-separated): symbol

  Added finnhub_quote to manifests/finnhub.toml
  Add another tool? [Y/n]
```

Or one-liner for scripting:

```bash
# Non-interactive
ati add provider finnhub \
  --base-url https://finnhub.io/api/v1 \
  --auth header \
  --auth-header-name "X-Finnhub-Token" \
  --key-name finnhub_api_key

ati add tool finnhub finnhub_quote \
  --endpoint /quote \
  --method GET \
  --param "symbol:string:required:Stock ticker symbol"
```

### Add an MCP Server

```bash
# stdio-based MCP server
$ ati add mcp github \
  --transport stdio \
  --command "npx -y @modelcontextprotocol/server-github" \
  --key-name github_token

  Connecting to MCP server...
  Discovered 12 tools via tools/list
  Created manifests/github.toml with 12 tools

# Remote MCP server (HTTP+SSE)
$ ati add mcp linear \
  --transport sse \
  --url https://mcp.linear.app/sse \
  --key-name linear_api_key

  Discovered 8 tools via tools/list
  Created manifests/linear.toml with 8 tools
```

ATI introspects the MCP server's `tools/list`, auto-generates the manifest with proper input schemas, and wires up auth. The agent never talks MCP — it just calls `ati call linear_create_issue`.

### Add Secrets

```bash
# Add a key to the keyring
$ ati auth add-key finnhub_api_key
  Enter value: ****
  Encrypted and saved to keyring.

# Import from environment (for migration from env-var based setups)
$ ati auth import-env FINNHUB_API_KEY --as finnhub_api_key
  Imported, encrypted, and saved. You can now unset FINNHUB_API_KEY.

# List keys (names only, never values)
$ ati auth keys
  finnhub_api_key       (header auth)
  parallel_api_key      (bearer auth)
  fred_api_key          (query auth)

# Rotate a key
$ ati auth rotate finnhub_api_key
  Enter new value: ****
  Rotated and re-encrypted.
```

### Add Scopes

```bash
# Grant a tool scope to the current session
$ ati auth grant tool:finnhub_quote --expires 24h

# Grant all tools from a provider
$ ati auth grant "tool:finnhub_*" --expires 7d

# Revoke a scope
$ ati auth revoke tool:finnhub_quote

# Show current session (from JWT claims)
$ ati auth status
  Agent: research-agent-42
  Session expires: 2026-03-03T12:00:00Z
  Scopes (3):
    tool:web_search
    tool:finnhub_*
    tool:academic_search_*
  Keyring: 3 keys loaded, memory locked
```

### From Docs URL (LLM-Powered)

```bash
# Point ATI at API docs, it generates the manifest
$ ati add from-docs https://developer.finnhub.io/docs/api

  Analyzing API documentation...
  Found 14 endpoints across 5 categories.

  Generated manifest with 14 tools:
    finnhub_quote, finnhub_profile, finnhub_news,
    finnhub_peers, finnhub_metrics, finnhub_candles, ...

  Save to manifests/finnhub.toml? [Y/n]
```

---

## One Interface, Everything Behind It

The agent calls `ati call <tool>`. It doesn't know — or care — what's behind that tool.

```mermaid
graph TB
    Agent["Agent"] -->|"ati call <tool>"| ATI["ATI"]

    ATI -->|"Direct HTTP"| REST["REST APIs<br/><small>Finnhub, FRED, SerpAPI,<br/>PubMed, SEC EDGAR...</small>"]
    ATI -->|"stdio proxy"| MCP_Stdio["MCP Servers (stdio)<br/><small>npx-based servers,<br/>local tools</small>"]
    ATI -->|"HTTP+SSE / streamable"| MCP_HTTP["MCP Servers (HTTP)<br/><small>Remote MCP endpoints,<br/>hosted services</small>"]
    ATI -->|"Shell exec"| CLI["CLI Tools<br/><small>git, docker, kubectl,<br/>custom scripts</small>"]

    style ATI fill:#e8f5e9,stroke:#2e7d32,stroke-width:3px
    style Agent fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

Behind the scenes, ATI can:

- **Call a REST API** directly (TOML manifest → HTTP request with injected auth)
- **Proxy an MCP server** over any transport — stdio, HTTP+SSE, streamable HTTP — without the agent managing MCP connections or knowing the protocol exists
- **Wrap a CLI tool** — shell out to `git`, `kubectl`, whatever, with structured input/output
- **Chain tools** — compose multiple calls into one invocation

The agent gets one consistent interface: `ati call <tool_name> --args`. ATI handles the protocol, the credentials, and the response formatting. MCP, REST, CLI — they're all just backends.

This is the point: **agents shouldn't think about transport protocols**. They should think about what data they need. ATI is the abstraction layer that makes "search the web," "query Postgres," and "check a stock price" all look the same from the agent's perspective — while keeping credentials locked down regardless of which backend handles the request.

---

## Vision

ATI today handles HTTP APIs with TOML manifests. Here's where it's going.

### MCP Auto-Discovery

Agents find new tools in the wild. Today they're stuck. Tomorrow:

```mermaid
sequenceDiagram
    participant Agent
    participant ATI
    participant Web as "Web / MCP Registry"
    participant User as "User (secure channel)"

    Agent->>Web: Searches for "Garmin health data API"
    Web-->>Agent: Finds MCP server at mcp.garmin.com
    Agent->>ATI: ati discover mcp.garmin.com
    ATI->>Web: Fetch MCP tools/list
    Web-->>ATI: Tool schemas + auth requirements
    ATI->>ATI: Auto-generate manifest from MCP schema
    ATI->>User: "Garmin MCP needs OAuth. Authorize?"
    User->>ATI: Provides credentials (secure side-channel)
    ATI->>ATI: Encrypt into keyring
    ATI-->>Agent: "3 new tools available: garmin_activity, garmin_sleep, garmin_heart_rate"
    Agent->>ATI: ati call garmin_activity --user_id me --days 7
```

The agent finds an MCP server, ATI introspects it via `tools/list`, auto-generates a manifest, and requests credentials through a **secure side-channel** (never through the agent conversation). The agent gets new tools instantly — zero restart, zero code.

Key principle: **credentials never flow through the agent chat**. The user authorizes via a separate channel (dashboard, CLI prompt, QR code), and ATI encrypts them into the keyring.

### Progressive Learning

Agents encounter repetitive patterns. ATI learns from them:

```bash
# Agent keeps writing the same curl pattern
$ ati learn --from-history

Detected 12 calls to api.acme.com/v2/* with Bearer auth.
Suggested manifest:

  [provider]
  name = "acme"
  base_url = "https://api.acme.com/v2"
  auth_type = "bearer"
  auth_key_name = "acme_api_key"

  [[tools]]
  name = "acme_search"
  endpoint = "/search"
  ...

Save to ~/.ati/manifests/acme.toml? [Y/n]
```

ATI watches what the agent does — repeated `curl` calls, `httpx` requests, API patterns — and suggests manifests. The agent turns ad-hoc HTTP calls into reusable, scoped, credential-secured tools. Over time, the tool library grows organically from actual usage.

For trusted agents with track records, auto-approval: the manifest is saved without human review. For new agents, human-in-the-loop.

### Skill Registry

Skills today are local files. The vision is a shared registry — like [Tessl](https://tessl.io/) for agent methodology:

```bash
# Discover skills from the registry
$ ati skills search "due diligence for fintech companies"

  fintech-dd (v2.3)          Fintech due diligence methodology
    by: compliance-team       downloads: 1,240
    Covers: licensing, AML, PCI-DSS, SOC2, state money transmitter...

  financial-dd (v4.1)        General financial due diligence
    by: research-team         downloads: 3,891

# Install a skill
$ ati skills install fintech-dd

# Agent uses it
$ ati skills show fintech-dd
```

Skills are versioned, shareable, and evaluatable. Teams publish internal methodologies. The community shares domain expertise. Agents get structured context that drives [measurable improvements](https://tessl.io/) in task quality — not just raw API access, but the judgment to use it well.

### Context Optimization

Large API responses kill agent performance. ATI already does JSONPath extraction, but the vision goes further — inspired by [Context+](https://github.com/ForLoopCodes/contextplus):

```bash
# Semantic extraction — LLM post-processes the response
$ ati call getIncomeStatement --ticker AAPL --limit 20 \
    --filter "only show years where revenue declined"

# Token budget enforcement
$ ati call web_search --query "AI regulation 2026" --max-tokens 2000

# Cumulative tracking
$ ati usage
  Session tokens: 12,450 / 50,000 budget
  API calls: 23 (8 cached)
  Cache hit rate: 34%
```

ATI becomes the agent's context manager — not just proxying API calls but actively reducing token waste through extraction, filtering, caching, and budget enforcement.

### Tool Composition

Chain tools without agent round-trips:

```bash
# Search → fetch first result → extract key facts
$ ati pipe "web_search --query 'Acme Corp' \
    | web_fetch --url {$.results[0].url} \
    | summarize --format bullets"
```

One shell command instead of three agent turns. Reduces latency, saves tokens, and lets agents express complex workflows declaratively.

### WASM Plugins

For tools that need complex multi-step logic — OAuth flows, pagination, scraping with retry:

```bash
# WASM plugin sandboxed inside ATI
[provider]
name = "complex_api"
handler = "wasm"
wasm_module = "complex_api.wasm"
```

WASM modules run in Wasmtime with network access limited to their declared `base_url`. They receive keyring credentials via imports — can't exfiltrate them. Anyone can write plugins in Rust, Go, or C.

---

## CLI Reference

```
ati — Agent Tools Interface

USAGE:
    ati [OPTIONS] <COMMAND>

COMMANDS:
    call       Execute a tool by name
    tools      List, inspect, and discover tools
    add        Add providers, tools, MCP servers, or generate from docs
    auth       Manage secrets, scopes, and session info
    skills     Manage skill files (methodology docs)
    help       LLM-powered tool discovery
    version    Print version

OPTIONS:
    --output <FORMAT>   json, table, text [default: text]
    --verbose           Debug output
```

```bash
# Call tools
ati call web_search --query "quantum computing" --max_results 5
ati call finnhub_quote --symbol AAPL
ati call getIncomeStatement --ticker MSFT --period annual --limit 5

# Discover tools
ati tools list
ati tools list --provider finnhub
ati tools info getIncomeStatement
ati tools providers

# Add providers and tools
ati add provider finnhub --base-url https://finnhub.io/api/v1 --auth header
ati add tool finnhub finnhub_quote --endpoint /quote --method GET
ati add mcp github --transport stdio --command "npx -y @modelcontextprotocol/server-github"
ati add from-docs https://developer.finnhub.io/docs/api

# Manage secrets and scopes
ati auth add-key finnhub_api_key
ati auth import-env FINNHUB_API_KEY --as finnhub_api_key
ati auth keys
ati auth grant "tool:finnhub_*" --expires 7d
ati auth status

# Skills
ati skills list
ati skills show financial-due-diligence

# LLM-powered discovery
ati help "I need to find SEC filings for a company"

# Output formats
ati --output json call finnhub_quote --symbol AAPL
ati --output table call getIncomeStatement --ticker AAPL --limit 3
```

---

## Building

```bash
# Debug
cargo build

# Release
cargo build --release

# Tests
cargo test

# Static binary (no glibc dependency — ideal for containers/sandboxes)
cargo build --release --target x86_64-unknown-linux-musl
```

## Project Structure

```
ati/
├── Cargo.toml
├── README.md
├── docs/
│   ├── SECURITY.md              # Full threat model
│   └── IDEAS.md                 # Future directions
├── manifests/                   # TOML tool definitions
│   ├── example.toml             # Annotated template
│   ├── parallel.toml            # Web search & fetch
│   ├── pubmed.toml              # Medical literature
│   ├── arxiv.toml               # arXiv papers
│   ├── crossref.toml            # Academic papers
│   ├── semantic_scholar.toml    # Papers + citations
│   ├── courtlistener.toml       # US legal cases
│   ├── hackernews.toml          # Tech news
│   ├── sec_edgar.toml           # SEC filings
│   ├── clinicaltrials.toml      # Clinical trials
│   ├── nhtsa.toml               # VIN decoder
│   ├── epo.toml                 # European patents
│   ├── middesk.toml             # Business verification
│   └── _llm.toml                # Internal (ati help)
├── src/
│   ├── main.rs                  # CLI entry (clap)
│   ├── cli/                     # Subcommand handlers
│   │   ├── call.rs              # ati call
│   │   ├── tools.rs             # ati tools
│   │   ├── skills.rs            # ati skills
│   │   ├── help.rs              # ati help
│   │   └── auth.rs              # ati auth
│   ├── core/
│   │   ├── manifest.rs          # TOML parsing
│   │   ├── http.rs              # HTTP + auth injection
│   │   ├── keyring.rs           # Encrypted credentials
│   │   ├── scope.rs             # Scope enforcement
│   │   └── response.rs          # JSONPath + formatting
│   ├── security/
│   │   ├── memory.rs            # mlock, madvise, zeroize
│   │   └── sealed_file.rs       # One-shot file read
│   ├── output/
│   │   ├── json.rs
│   │   ├── table.rs
│   │   └── text.rs
│   └── providers/
│       └── generic.rs           # Generic HTTP provider
└── tests/
    ├── manifest_test.rs
    ├── keyring_test.rs
    ├── scope_test.rs
    └── call_test.rs
```

## License

Apache-2.0
