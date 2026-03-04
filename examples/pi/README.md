# ATI + Pi SDK Examples

These examples show how to give [Pi](https://github.com/badlogic/pi-mono) agents access to external tools through ATI. The agent uses Pi's built-in `bashTool` to call the `ati` CLI — the same tool Pi's own coding agent uses. A system prompt explains what ATI commands are available and the agent figures out the rest.

Pi is a TypeScript agentic toolkit, so these examples are `.ts` files (run with `npx tsx`).

## Examples

| Example | Provider Types | Tools Used | What It Does |
|---------|---------------|------------|-------------|
| `mcp_agent.ts` | MCP (Streamable HTTP) | DeepWiki | Researches GitHub repos via AI-powered documentation |
| `openapi_agent.ts` | OpenAPI + HTTP | Crossref, arXiv, Hacker News | Multi-source academic & tech research |

## Prerequisites

- Node.js 18+
- Rust toolchain (for building ATI)
- An LLM API key (`ANTHROPIC_API_KEY` by default, or any provider Pi supports)

No other API keys needed — all ATI tools in these examples are free and unauthenticated.

## Setup

```bash
# 1. Build ATI
cd /path/to/ati
cargo build --release

# 2. Install Node.js deps
cd examples/pi
npm install

# 3. Set environment variables
export ANTHROPIC_API_KEY="sk-ant-..."
export ATI_DIR=/path/to/ati
export PATH="/path/to/ati/target/release:$PATH"
```

## Run

```bash
# MCP example — research a GitHub repo through DeepWiki
npx tsx mcp_agent.ts
npx tsx mcp_agent.ts "Research the rust-lang/rust repo and explain its module system"

# OpenAPI example — multi-source research
npx tsx openapi_agent.ts
npx tsx openapi_agent.ts "Find recent papers on quantum error correction and check HN for related discussions"

# Or via npm scripts
npm run mcp
npm run openapi
```

### Model override

Both examples default to `claude-haiku-4-5` via Anthropic (fast and cheap for demos). Override with:

```bash
# Different Anthropic model
export PI_MODEL=claude-sonnet-4-20250514

# Different provider entirely
export PI_PROVIDER=openai
export PI_MODEL=gpt-4.1-mini
export OPENAI_API_KEY="sk-..."
```

Pi supports 15+ providers including Anthropic, OpenAI, Google, Groq, Cerebras, xAI, and any OpenAI-compatible endpoint.

## How It Works

```
Pi Agent (pi-coding-agent SDK)
  |
  +-- bashTool (built-in, same as Pi's own coding agent)
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

The agent gets `bashTool` and a system prompt. That's it. `bashTool` is Pi's native shell tool — the same one its coding agent uses to run commands. No custom wrappers needed.

## Also See

- [Claude Agent SDK examples](../claude-agent-sdk/) — same pattern with Claude's built-in Bash tool
- [OpenAI Agents SDK examples](../openai-agents-sdk/) — @function_tool shell function
- [Codex examples](../codex/) — Codex is already a shell agent, just needs instructions
- [Google ADK examples](../google-adk/) — ADK function tool for shell access
- [LangChain examples](../langchain/) — create_agent with ShellTool
