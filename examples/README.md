# ATI Examples

These examples show how to integrate ATI with popular agentic AI SDKs. The core pattern is identical across all: the agent gets a shell/bash tool, a system prompt explains `ati` commands, and the agent calls `ati` via shell like a human would. No custom `@tool` wrappers around ATI — just shell access.

## SDK Examples

| SDK | Directory | Shell Mechanism | API Key | Default Model |
|-----|-----------|----------------|---------|---------------|
| [Claude Agent SDK](claude-agent-sdk/) | `claude-agent-sdk/` | Built-in `Bash` tool | `ANTHROPIC_API_KEY` | `claude-haiku-4-5` |
| [OpenAI Agents SDK](openai-agents-sdk/) | `openai-agents-sdk/` | `@function_tool` async shell | `OPENAI_API_KEY` | `gpt-5.2` |
| [Codex CLI](codex/) | `codex/` | Built-in (Codex IS a shell agent) | `OPENAI_API_KEY` | `gpt-5.2` |
| [Google ADK](google-adk/) | `google-adk/` | `run_shell()` function tool | `GOOGLE_API_KEY` | `gemini-3-flash-preview` |
| [LangChain/LangGraph](langchain/) | `langchain/` | `ShellTool` (zero-config) | `OPENAI_API_KEY` | `gpt-5.2` |
| [Pi](pi/) | `pi/` | Built-in `bashTool` | `ANTHROPIC_API_KEY` | `claude-haiku-4-5` |

## Each Example Includes

| File | Purpose |
|------|---------|
| `mcp_agent.py` (or `.ts`) | Research agent using DeepWiki (MCP provider) |
| `openapi_agent.py` (or `.ts`) | Multi-source research using Crossref, arXiv, HN (OpenAPI + HTTP providers) |
| `README.md` | Setup, prerequisites, run commands |
| `requirements.txt` / `package.json` | Dependencies |

## Quick Start

```bash
# 1. Build ATI
cd /path/to/ati
cargo build --release

# 2. Set common env vars
export ATI_DIR=/path/to/ati
export PATH="/path/to/ati/target/release:$PATH"

# 3. Pick an SDK and run
cd examples/claude-agent-sdk    # or openai-agents-sdk, google-adk, langchain, codex, pi
pip install -r requirements.txt  # or `npm install` for pi/codex
export ANTHROPIC_API_KEY="..."   # or OPENAI_API_KEY, GOOGLE_API_KEY
python mcp_agent.py              # or `npx tsx mcp_agent.ts` for pi
```

## Tools Used (All Free, No Auth Required)

All examples use the same set of free, unauthenticated tools:

| Tool | Provider Type | What It Does |
|------|--------------|--------------|
| `deepwiki__ask_question` | MCP (Streamable HTTP) | AI-powered documentation for any GitHub repo |
| `academic_search_arxiv` | HTTP | arXiv preprint paper search |
| `crossref__get_works` | OpenAPI | Published academic papers with DOI metadata |
| `hackernews_top_stories` | HTTP | Hacker News top stories |

## The Pattern

```
Any AI Agent (any SDK)
  |
  +-- shell tool (Bash, ShellTool, run_shell, etc.)
       |
       +-- ati tool search <query>      ->  discover available tools
       +-- ati tool info <name>         ->  inspect tool schema
       +-- ati run <tool> --key val     ->  execute tool
             |
             +-- MCP provider    ->  JSON-RPC to remote MCP server
             +-- OpenAPI provider ->  auto-classified HTTP request
             +-- HTTP provider    ->  hand-written endpoint call
             |
             +-- structured response -> agent continues reasoning
```

The agent gets a shell tool and a system prompt. That's it. ATI handles auth injection, protocol bridging, scope enforcement, and response formatting. The agent doesn't know (or care) whether a tool is MCP, OpenAPI, or hand-written HTTP.
