# ATI + LangChain/LangGraph Examples

These examples show how to give LangChain agents access to external tools through ATI. The agent uses LangChain's built-in `ShellTool` (zero-config) with LangChain's `create_agent` — no custom tool wrappers, no MCP plumbing, no boilerplate. A system prompt explains what ATI commands are available and the agent figures out the rest.

## Examples

| Example | Provider Types | Tools Used | What It Does |
|---------|---------------|------------|-------------|
| `mcp_agent.py` | MCP (Streamable HTTP) | DeepWiki | Researches GitHub repos via AI-powered documentation |
| `openapi_agent.py` | OpenAPI + HTTP | Crossref, arXiv, Hacker News | Multi-source academic & tech research |

## Prerequisites

- Python 3.10+
- Rust toolchain (for building ATI)
- `OPENAI_API_KEY` environment variable (default LLM provider)

No other API keys needed — all ATI tools in these examples are free and unauthenticated.

## Setup

```bash
# 1. Build ATI
cd /path/to/ati
cargo build --release

# 2. Install Python deps
cd examples/langchain
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
export LANGCHAIN_MODEL=gpt-4.1       # more capable
export LANGCHAIN_MODEL=gpt-5.1       # most capable
```

LangChain is model-agnostic — swap to Anthropic, Google, or any other provider by changing the LLM class. See [LangChain chat model integrations](https://python.langchain.com/docs/integrations/chat/).

## How It Works

```
LangChain Agent
  |
  +-- ShellTool (langchain-community, zero-config)
       |
       +-- ati tools search <query>     ->  discover available tools
       +-- ati tools info <name>        ->  inspect tool schema
       +-- ati call <tool> --key val    ->  execute tool
             |
             +-- MCP provider    ->  JSON-RPC to remote MCP server (DeepWiki)
             +-- OpenAPI provider ->  auto-classified HTTP request (Crossref)
             +-- HTTP provider    ->  hand-written endpoint call (arXiv, HN)
             |
             +-- structured response -> agent continues reasoning
```

The agent gets `ShellTool()` and a system prompt. That's it. `ShellTool` is zero-config (no executor class needed), and `create_agent` sets up the full agent loop in one line. The system prompt is passed directly to the agent.

## Also See

- [Claude Agent SDK examples](../claude-agent-sdk/) — same pattern with Claude's built-in Bash tool
- [OpenAI Agents SDK examples](../openai-agents-sdk/) — @function_tool shell function
- [Codex examples](../codex/) — Codex is already a shell agent, just needs instructions
- [Google ADK examples](../google-adk/) — ADK function tool for shell access
- [Pi examples](../pi/) — Pi's built-in bashTool (TypeScript)
