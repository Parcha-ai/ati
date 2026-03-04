#!/usr/bin/env python3
"""
ATI + Google ADK: OpenAPI + HTTP Provider Example

The agent uses a plain Python function as its shell tool — this is how ADK tools
work, not an ATI-specific wrapper. Shows ATI's unified interface across different
provider types:
- Crossref (OpenAPI provider) — tools auto-discovered from an OAS 3.0 spec
- arXiv (HTTP provider) — hand-written TOML manifest
- Hacker News (HTTP provider) — hand-written TOML manifest

Same `ati call` interface for all three. The agent doesn't care which backend.

Usage:
    python openapi_agent.py
    python openapi_agent.py "Find clinical trials related to CRISPR gene therapy"

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

root_agent = Agent(
    name="ati_research",
    model=MODEL,
    instruction=SYSTEM_PROMPT,
    tools=[run_shell],
)


async def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROMPT
    print(f"[OpenAPI Agent] Prompt: {prompt}\n")

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
