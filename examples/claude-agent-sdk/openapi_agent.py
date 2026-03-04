#!/usr/bin/env python3
"""
ATI + Claude Agent SDK: OpenAPI + HTTP Provider Example

The agent uses Bash to call `ati` commands directly — no custom tools needed.
Shows ATI's unified interface across different provider types:
- Crossref (OpenAPI provider) — tools auto-discovered from an OAS 3.0 spec
- arXiv (HTTP provider) — hand-written TOML manifest
- Hacker News (HTTP provider) — hand-written TOML manifest

Same `ati call` interface for all three. The agent doesn't care which backend.

Usage:
    python openapi_agent.py
    python openapi_agent.py "Find clinical trials related to CRISPR gene therapy"

Requires:
    ANTHROPIC_API_KEY environment variable
    ATI binary on PATH (or set ATI_DIR env var)
"""

import os
import sys
from pathlib import Path

import anyio
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    query,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ATI_DIR = os.environ.get("ATI_DIR", str(REPO_ROOT))
MODEL = os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5")

SYSTEM_PROMPT = f"""\
You are a research agent. You have access to ATI (Agent Tools Interface) via the \
`ati` CLI on your PATH.

ATI gives you tools from multiple providers through a unified interface:

- **Crossref** (OpenAPI) — published academic papers with DOI metadata and citations. \
Tools auto-discovered from an OAS 3.0 spec, names like `crossref__get_works`.
- **arXiv** (HTTP) — preprint paper search. Tool: `academic_search_arxiv`.
- **Hacker News** (HTTP) — tech news from Y Combinator. Tools: `hackernews_top_stories`, \
`hackernews_new_stories`, `hackernews_best_stories`.

## ATI Commands

```bash
# Ask ATI for help (LLM-powered tool recommendations)
ati assist "find academic papers"

# Discover tools by keyword
ati tools search "arxiv"
ati tools search "crossref"
ati tools search "hackernews"

# Inspect a tool's schema
ati tools info academic_search_arxiv
ati tools info crossref__get_works

# Call a tool
ati call academic_search_arxiv --search_query "quantum error correction" --max_results 5
ati call crossref__get_works --query "quantum computing" --rows 5
ati call hackernews_top_stories
```

ATI_DIR is set to `{ATI_DIR}` — the ati binary will find its manifests there.

Cross-reference results from multiple sources. Synthesize findings into a clear, \
structured research briefing.\
"""

DEFAULT_PROMPT = (
    "Research quantum computing: find recent arXiv papers on quantum error correction, "
    "search Crossref for published academic papers on the topic, and check what's trending "
    "on Hacker News. Synthesize a structured research briefing."
)


async def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROMPT

    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        model=MODEL,
        max_turns=15,
        permission_mode="bypassPermissions",
        allowed_tools=["Bash"],
        env={"ATI_DIR": ATI_DIR},
    )

    print(f"[OpenAPI Agent] Prompt: {prompt}\n")

    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    print(block.text, end="", flush=True)
                elif isinstance(block, ToolUseBlock):
                    if block.name == "Bash":
                        cmd = block.input.get("command", "")
                        print(f"\n> {cmd}", flush=True)
        if isinstance(message, ResultMessage):
            print(f"\n\n--- Done (cost: ${message.total_cost_usd:.4f}) ---")


if __name__ == "__main__":
    anyio.run(main)
