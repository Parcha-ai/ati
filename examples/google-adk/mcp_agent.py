#!/usr/bin/env python3
"""
ATI + Google ADK: MCP Provider Example

The agent uses a plain Python function as its shell tool — this is how ADK tools
work, not an ATI-specific wrapper. ATI bridges to DeepWiki's remote MCP server
transparently.

Usage:
    python mcp_agent.py
    python mcp_agent.py "Research the rust-lang/rust repo and explain its module system"

Requires:
    GOOGLE_API_KEY environment variable
    ATI binary on PATH (or set ATI_DIR env var)
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path

from google.adk.agents import Agent
from google.adk.runners import InMemoryRunner
from google.genai import types

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ATI_DIR = os.environ.get("ATI_DIR", str(REPO_ROOT))
MODEL = os.environ.get("GOOGLE_MODEL", "gemini-3-flash-preview")


def run_shell(command: str) -> dict:
    """Execute a shell command and return stdout/stderr.

    Args:
        command: The shell command to execute.

    Returns:
        dict with status, stdout, stderr.
    """
    env = {**os.environ, "ATI_DIR": ATI_DIR}
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=60, env=env
        )
        return {
            "status": "success" if result.returncode == 0 else "error",
            "stdout": result.stdout[:15000],
            "stderr": result.stderr[:5000],
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "stdout": "", "stderr": "Command timed out after 60s"}


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

root_agent = Agent(
    name="ati_research",
    model=MODEL,
    instruction=SYSTEM_PROMPT,
    tools=[run_shell],
)


async def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROMPT
    print(f"[MCP Agent] Prompt: {prompt}\n")

    runner = InMemoryRunner(agent=root_agent, app_name="ati")
    user_id = "user"
    session = await runner.session_service.create_session(
        app_name="ati", user_id=user_id
    )

    content = types.Content(role="user", parts=[types.Part(text=prompt)])
    async for event in runner.run_async(
        user_id=user_id, session_id=session.id, new_message=content
    ):
        if event.is_final_response() and event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    print(part.text)


if __name__ == "__main__":
    asyncio.run(main())
