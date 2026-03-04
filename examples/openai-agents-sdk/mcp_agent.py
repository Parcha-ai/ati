#!/usr/bin/env python3
"""
ATI + OpenAI Agents SDK: MCP Provider Example

The agent uses a @function_tool to run shell commands — the SDK's standard way
to give agents custom capabilities. ATI bridges to DeepWiki's remote MCP server
transparently.

Usage:
    python mcp_agent.py
    python mcp_agent.py "Research the rust-lang/rust repo and explain its module system"

Requires:
    OPENAI_API_KEY environment variable
    ATI binary on PATH (or set ATI_DIR env var)
"""

import asyncio
import os
import sys
from pathlib import Path

from agents import Agent, Runner, function_tool

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ATI_DIR = os.environ.get("ATI_DIR", str(REPO_ROOT))
MODEL = os.environ.get("OPENAI_MODEL", "gpt-5.2")


@function_tool
async def run_shell(command: str) -> str:
    """Execute a shell command and return its output.

    Args:
        command: The shell command to execute.
    """
    env = {**os.environ, "ATI_DIR": ATI_DIR}
    proc = await asyncio.create_subprocess_shell(
        command,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await proc.communicate()
    stdout = stdout_bytes.decode()[:15000]
    stderr = stderr_bytes.decode()[:5000]
    if proc.returncode != 0:
        return f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}\nEXIT CODE: {proc.returncode}"
    return stdout


SYSTEM_PROMPT = f"""\
You are a research agent. You have access to ATI (Agent Tools Interface) via the \
`ati` CLI. Use the run_shell tool to execute commands.

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

agent = Agent(
    name="ATI Research Agent",
    model=MODEL,
    instructions=SYSTEM_PROMPT,
    tools=[run_shell],
)


async def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROMPT
    print(f"[MCP Agent] Prompt: {prompt}\n")
    result = await Runner.run(agent, input=prompt)
    print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
