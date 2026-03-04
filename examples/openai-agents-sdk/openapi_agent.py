#!/usr/bin/env python3
"""
ATI + OpenAI Agents SDK: OpenAPI + HTTP Provider Example

The agent uses a @function_tool to run shell commands — the SDK's standard way
to give agents custom capabilities. Shows ATI's unified interface across different
provider types:
- Crossref (OpenAPI provider) — tools auto-discovered from an OAS 3.0 spec
- arXiv (HTTP provider) — hand-written TOML manifest
- Hacker News (HTTP provider) — hand-written TOML manifest

Same `ati run` interface for all three. The agent doesn't care which backend.

Usage:
    python openapi_agent.py
    python openapi_agent.py "Find clinical trials related to CRISPR gene therapy"

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
ati tool search "arxiv"
ati tool search "crossref"
ati tool search "hackernews"

# Inspect a tool's schema
ati tool info academic_search_arxiv
ati tool info crossref__get_works

# Call a tool
ati run academic_search_arxiv --search_query "quantum error correction" --max_results 5
ati run crossref__get_works --query "quantum computing" --rows 5
ati run hackernews_top_stories
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

agent = Agent(
    name="ATI Research Agent",
    model=MODEL,
    instructions=SYSTEM_PROMPT,
    tools=[run_shell],
)


async def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROMPT
    print(f"[OpenAPI Agent] Prompt: {prompt}\n")
    result = await Runner.run(agent, input=prompt)
    print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
