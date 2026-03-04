#!/usr/bin/env python3
"""
ATI + Claude Agent SDK: MCP Provider Example

The agent uses Bash to call `ati` commands directly — no custom tools needed.
ATI bridges to DeepWiki's remote MCP server transparently.

Usage:
    python mcp_agent.py
    python mcp_agent.py "Research the rust-lang/rust repo and explain its module system"

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

ATI gives you tools backed by an MCP server called DeepWiki — it provides AI-powered \
documentation for any GitHub repository.

## ATI Commands

```bash
# Ask ATI for help (LLM-powered tool recommendations)
ati assist "research a github repository"

# Discover tools (find what's available)
ati tool search "deepwiki"

# Inspect a tool's input schema before calling it
ati tool info deepwiki__ask_question

# Call a tool
ati run deepwiki__ask_question --repoName "owner/repo" --question "How does X work?"
```

MCP tool names follow the pattern `deepwiki__<tool_name>`. Use `ati tool search` \
to discover them, `ati tool info` to see their schemas, then `ati run` to execute.

ATI_DIR is set to `{ATI_DIR}` — the ati binary will find its manifests there.

Be thorough: explore the repo structure first, then dive into specifics. \
Synthesize your findings into a clear, well-organized summary.\
"""

DEFAULT_PROMPT = (
    "Using ATI's DeepWiki tools, research the anthropics/claude-code repository: "
    "examine its structure, understand how tool dispatch works, and summarize the architecture."
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

    print(f"[MCP Agent] Prompt: {prompt}\n")

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
