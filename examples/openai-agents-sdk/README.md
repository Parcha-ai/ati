# ATI + OpenAI Agents SDK Examples

These examples show how to give OpenAI agents access to external tools through ATI. The agent uses a `@function_tool` to run shell commands — the SDK's standard way to give agents custom capabilities. A system prompt explains what ATI commands are available and the agent figures out the rest.

## Examples

| Example | Provider Types | Tools Used | What It Does |
|---------|---------------|------------|-------------|
| `mcp_agent.py` | MCP (Streamable HTTP) | DeepWiki | Researches GitHub repos via AI-powered documentation |
| `openapi_agent.py` | OpenAPI + HTTP | Crossref, arXiv, Hacker News | Multi-source academic & tech research |

## Prerequisites

- Python 3.10+
- Rust toolchain (for building ATI)
- `OPENAI_API_KEY` environment variable

No other API keys needed — all tools in these examples are free and unauthenticated.

## Setup

```bash
# 1. Build ATI
cd /path/to/ati
cargo build --release

# 2. Install Python deps
cd examples/openai-agents-sdk
pip install -r requirements.txt

# 3. Set environment variables
export OPENAI_API_KEY="sk-..."
export ATI_DIR=/path/to/ati
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

Both examples default to `gpt-4.1-mini` (fast and cheap for demos). Override with:

```bash
export OPENAI_MODEL=gpt-4.1       # more capable
export OPENAI_MODEL=gpt-5.1       # most capable
```

## How It Works

```
OpenAI Agent (Agents SDK)
  |
  +-- run_shell() function tool
       |
       +-- ati tool search <query>      ->  discover available tools
       +-- ati tool info <name>         ->  inspect tool schema
       +-- ati run <tool> --key val     ->  execute tool
             |
             +-- MCP provider    ->  JSON-RPC to remote MCP server (DeepWiki)
             +-- OpenAPI provider ->  auto-classified HTTP request (Crossref)
             +-- HTTP provider    ->  hand-written endpoint call (arXiv, HN)
             |
             +-- structured response -> agent continues reasoning
```

The agent gets `run_shell()` and a system prompt. That's it. The `@function_tool` decorator (~10 lines) is the SDK's standard pattern for giving agents capabilities — works with any model, no special API features required.

## Also See

- [Claude Agent SDK examples](../claude-agent-sdk/) — same pattern with Claude's built-in Bash tool
- [Codex examples](../codex/) — Codex is already a shell agent, just needs instructions
- [Google ADK examples](../google-adk/) — ADK function tool for shell access
- [LangChain examples](../langchain/) — create_agent with ShellTool
- [Pi examples](../pi/) — Pi's built-in bashTool (TypeScript)
