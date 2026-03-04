# ATI + Claude Agent SDK Examples

These examples show how to give Claude agents access to external tools through ATI. The agent just uses `Bash` to call the `ati` CLI — no custom tool wrappers, no MCP plumbing, no boilerplate. A system prompt explains what ATI commands are available and the agent figures out the rest.

## Examples

| Example | Provider Types | Tools Used | What It Does |
|---------|---------------|------------|-------------|
| `mcp_agent.py` | MCP (Streamable HTTP) | DeepWiki | Researches GitHub repos via AI-powered documentation |
| `openapi_agent.py` | OpenAPI + HTTP | Crossref, arXiv, Hacker News | Multi-source academic & tech research |

## Prerequisites

- Python 3.10+
- Rust toolchain (for building ATI)
- `ANTHROPIC_API_KEY` environment variable

No other API keys needed — all tools in these examples are free and unauthenticated.

## Setup

```bash
# 1. Build ATI
cd /path/to/ati
cargo build --release

# 2. Install Python deps
cd examples/claude-agent-sdk
pip install -r requirements.txt

# 3. Set environment variables
export ANTHROPIC_API_KEY="sk-ant-..."
export ATI_DIR=/path/to/ati          # so ATI finds its manifests/
export PATH="/path/to/ati/target/release:$PATH"
```

## Run

```bash
# MCP example — research a GitHub repo through DeepWiki
python mcp_agent.py
python mcp_agent.py "Research the rust-lang/rust repo and explain its module system"

# OpenAPI example — multi-source research
python openapi_agent.py
python openapi_agent.py "Find recent papers on quantum error correction and check HN for related discussions"
```

### Model override

Both examples default to `claude-haiku-4-5` (fast and cheap for demos). Override with:

```bash
export CLAUDE_MODEL=claude-sonnet-4-5    # more capable
export CLAUDE_MODEL=claude-opus-4-6      # most capable
```

### `ati assist` — LLM-powered tool discovery

Works out of the box with `ANTHROPIC_API_KEY` (uses Haiku):

```bash
ati assist "find academic papers about climate change"
# Returns recommended tools with exact `ati run` commands
```

For **10x faster** recommendations, add a free [Cerebras API key](https://cloud.cerebras.ai/):

```bash
export CEREBRAS_API_KEY="csk-..."   # that's it — ati assist auto-detects it
```

## How It Works

```
Claude Agent (SDK)
  │
  └─ Bash tool
       │
       ├─ ati tool search <query>      →  discover available tools
       ├─ ati tool info <name>         →  inspect tool schema
       └─ ati run <tool> --key val     →  execute tool
             │
             ├─ MCP provider    →  JSON-RPC to remote MCP server (DeepWiki)
             ├─ OpenAPI provider →  auto-classified HTTP request (Crossref)
             └─ HTTP provider    →  hand-written endpoint call (arXiv, HN)
             │
             └─ structured response → agent continues reasoning
```

The agent gets `Bash` and a system prompt. That's it. No `@tool` decorators, no custom MCP servers, no wrapper functions. The agent calls `ati` via Bash the same way a human would from a terminal.

## Example 1: MCP Provider (DeepWiki)

`mcp_agent.py` — the agent researches GitHub repos through [DeepWiki](https://deepwiki.com), a remote MCP server. ATI handles the Streamable HTTP + SSE transport transparently.

The agent discovers tools like `deepwiki__ask_question` at runtime and calls them through `ati run`.

## Example 2: OpenAPI + HTTP Providers (Crossref, arXiv, HN)

`openapi_agent.py` — the agent combines three different provider types:

- **Crossref** (OpenAPI) — tools auto-discovered from an OAS 3.0 spec, parameters auto-classified by location
- **arXiv** (HTTP) — hand-written TOML manifest
- **Hacker News** (HTTP) — hand-written TOML manifest

Same `ati run` interface for all three. The agent doesn't know the difference.

## Also See

- [OpenAI Agents SDK examples](../openai-agents-sdk/) — @function_tool shell function
- [Codex examples](../codex/) — Codex is already a shell agent, just needs instructions
- [Google ADK examples](../google-adk/) — ADK function tool for shell access
- [LangChain examples](../langchain/) — create_agent with ShellTool
- [Pi examples](../pi/) — Pi's built-in bashTool (TypeScript)
