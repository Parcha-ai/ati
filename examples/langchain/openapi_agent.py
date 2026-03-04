#!/usr/bin/env python3
"""
ATI + LangChain/LangGraph: OpenAPI + HTTP Provider Example

The agent uses LangChain's built-in ShellTool to call `ati` commands — no custom
tool wrappers needed. Shows ATI's unified interface across different provider types:
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


def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROMPT
    print(f"[OpenAPI Agent] Prompt: {prompt}\n")

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
