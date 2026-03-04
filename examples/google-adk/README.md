# ATI + Google ADK Examples

These examples show how to give Google ADK agents access to external tools through ATI. The agent uses a plain Python function (`run_shell`) as its tool — this is how ADK tools work natively, not an ATI-specific wrapper. A system prompt explains what ATI commands are available and the agent figures out the rest.

## Examples

| Example | Provider Types | Tools Used | What It Does |
|---------|---------------|------------|-------------|
| `mcp_agent.py` | MCP (Streamable HTTP) | DeepWiki | Researches GitHub repos via AI-powered documentation |
| `openapi_agent.py` | OpenAPI + HTTP | Crossref, arXiv, Hacker News | Multi-source academic & tech research |

## Prerequisites

- Python 3.10+
- Rust toolchain (for building ATI)
- `GOOGLE_API_KEY` environment variable

No other API keys needed — all tools in these examples are free and unauthenticated.

## Setup

```bash
# 1. Build ATI
cd /path/to/ati
cargo build --release

# 2. Install Python deps
cd examples/google-adk
pip install -r requirements.txt

# 3. Set environment variables
export GOOGLE_API_KEY="AIza..."
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

Both examples default to `gemini-3-flash-preview` (fast and cheap for demos). Override with:

```bash
export GOOGLE_MODEL=gemini-2.5-pro-preview     # more capable
export GOOGLE_MODEL=gemini-2.5-flash           # alternative
```

## How It Works

```
ADK Agent (google-adk)
  |
  +-- run_shell() function tool (~8 lines)
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

The agent gets a `run_shell()` function and a system prompt. The shell function is ~8 lines — it's how ADK tools work natively (plain Python functions with docstrings), not an ATI wrapper. ADK reads the function's type hints and docstring to generate the tool schema automatically.

## Also See

- [Claude Agent SDK examples](../claude-agent-sdk/) — same pattern with Claude's built-in Bash tool
- [OpenAI Agents SDK examples](../openai-agents-sdk/) — @function_tool shell function
- [Codex examples](../codex/) — Codex is already a shell agent, just needs instructions
- [LangChain examples](../langchain/) — create_agent with ShellTool
- [Pi examples](../pi/) — Pi's built-in bashTool (TypeScript)
