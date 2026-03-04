#!/usr/bin/env python3
"""
ATI + LangChain/LangGraph: MCP Provider Example

The agent uses LangChain's built-in ShellTool to call `ati` commands — no custom
tool wrappers needed. ATI bridges to DeepWiki's remote MCP server transparently.

Usage:
    python mcp_agent.py
    python mcp_agent.py "Research the rust-lang/rust repo and explain its module system"

Requires:
    OPENAI_API_KEY environment variable
    ATI binary on PATH (or set ATI_DIR env var)
"""

import os
import sys
from pathlib import Path

from langchain_community.tools import ShellTool
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ATI_DIR = os.environ.get("ATI_DIR", str(REPO_ROOT))
MODEL = os.environ.get("LANGCHAIN_MODEL", "gpt-5.2")

# Ensure ATI_DIR is in the environment for subprocess calls
os.environ["ATI_DIR"] = ATI_DIR

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
ati tools search "deepwiki"

# Inspect a tool's input schema before calling it
ati tools info deepwiki__ask_question

# Call a tool
ati call deepwiki__ask_question --repoName "owner/repo" --question "How does X work?"
```

MCP tool names follow the pattern `deepwiki__<tool_name>`. Use `ati tools search` \
to discover them, `ati tools info` to see their schemas, then `ati call` to execute.

ATI_DIR is set to `{ATI_DIR}` — the ati binary will find its manifests there.

Be thorough: explore the repo structure first, then dive into specifics. \
Synthesize your findings into a clear, well-organized summary.\
"""

DEFAULT_PROMPT = (
    "Using ATI's DeepWiki tools, research the anthropics/claude-code repository: "
    "examine its structure, understand how tool dispatch works, and summarize the architecture."
)


def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROMPT
    print(f"[MCP Agent] Prompt: {prompt}\n")

    llm = ChatOpenAI(model=MODEL)
    shell_tool = ShellTool()
    agent = create_agent(llm, [shell_tool], system_prompt=SYSTEM_PROMPT)

    result = agent.invoke(
        {"messages": [{"role": "user", "content": prompt}]}
    )

    # Print the final assistant message
    for message in reversed(result["messages"]):
        if hasattr(message, "content") and message.type == "ai" and message.content:
            print(message.content)
            break


if __name__ == "__main__":
    main()
