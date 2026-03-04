# ATI + Codex CLI Examples

These examples show how to give OpenAI's Codex CLI access to external tools through ATI. Codex is already a shell agent — it runs commands directly. We just give it an `AGENTS.md` that explains ATI commands and let it work.

## Examples

| Example | Provider Types | Tools Used | What It Does |
|---------|---------------|------------|-------------|
| `mcp_agent.sh` / `.py` | MCP (Streamable HTTP) | DeepWiki | Researches GitHub repos via AI-powered documentation |
| `openapi_agent.sh` / `.py` | OpenAPI + HTTP | Crossref, arXiv, Hacker News | Multi-source academic & tech research |

## Prerequisites

- Node.js 18+ (for Codex CLI)
- Rust toolchain (for building ATI)
- `OPENAI_API_KEY` environment variable

No other API keys needed — all tools in these examples are free and unauthenticated.

## Setup

```bash
# 1. Build ATI
cd /path/to/ati
cargo build --release

# 2. Install Codex CLI
npm i -g @openai/codex

# 3. Set environment variables
export OPENAI_API_KEY="sk-..."          # or CODEX_API_KEY
export CODEX_API_KEY="$OPENAI_API_KEY"  # Codex looks for this
export ATI_DIR=/path/to/ati
export PATH="/path/to/ati/target/release:$PATH"
```

## Run

```bash
cd examples/codex

# Shell scripts (simplest)
./mcp_agent.sh
./mcp_agent.sh "Research the rust-lang/rust repo and explain its module system"

./openapi_agent.sh
./openapi_agent.sh "Find recent papers on quantum error correction"

# Python wrappers (consistent with other ATI examples)
python mcp_agent.py
python openapi_agent.py "Search arXiv for 2 papers on reinforcement learning"
```

### Model override

Both examples default to `gpt-4.1-mini`. Override with:

```bash
export CODEX_MODEL=gpt-4.1-mini
export CODEX_MODEL=o4-mini
```

## How It Works

```
Codex CLI (built-in shell agent)
  |
  +-- AGENTS.md (teaches Codex about ATI commands)
  |
  +-- shell commands (Codex runs these directly)
       |
       +-- ati tools search <query>     ->  discover available tools
       +-- ati tools info <name>        ->  inspect tool schema
       +-- ati call <tool> --key val    ->  execute tool
             |
             +-- MCP provider    ->  JSON-RPC to remote MCP server (DeepWiki)
             +-- OpenAPI provider ->  auto-classified HTTP request (Crossref)
             +-- HTTP provider    ->  hand-written endpoint call (arXiv, HN)
             |
             +-- structured response -> Codex continues reasoning
```

Codex reads `AGENTS.md` automatically when it starts. No shell tool setup needed — Codex IS a shell agent. The `AGENTS.md` file is the system prompt equivalent.

## Files

| File | Purpose |
|------|---------|
| `AGENTS.md` | Instructions for Codex — explains ATI commands and available tools |
| `mcp_agent.sh` | Shell script — runs `codex exec` with MCP research prompt |
| `openapi_agent.sh` | Shell script — runs `codex exec` with OpenAPI research prompt |
| `mcp_agent.py` | Python wrapper around `codex exec` (stdlib only, no deps) |
| `openapi_agent.py` | Python wrapper around `codex exec` (stdlib only, no deps) |

## Also See

- [Claude Agent SDK examples](../claude-agent-sdk/) — same pattern with Claude's built-in Bash tool
- [OpenAI Agents SDK examples](../openai-agents-sdk/) — @function_tool shell function
- [Google ADK examples](../google-adk/) — ADK function tool for shell access
- [LangChain examples](../langchain/) — create_agent with ShellTool
- [Pi examples](../pi/) — Pi's built-in bashTool (TypeScript)
