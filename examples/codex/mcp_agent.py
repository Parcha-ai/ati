#!/usr/bin/env python3
"""
ATI + Codex CLI: MCP Provider Example (Python wrapper)

Thin wrapper around `codex exec` for consistency with other ATI examples.
Codex is already a shell agent — it runs commands directly. The AGENTS.md file
in this directory teaches it about ATI commands.

Usage:
    python mcp_agent.py
    python mcp_agent.py "Research the rust-lang/rust repo and explain its module system"

Requires:
    OPENAI_API_KEY environment variable
    @openai/codex installed (npm i -g @openai/codex)
    ATI binary on PATH (or set ATI_DIR env var)
"""

import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
ATI_DIR = os.environ.get("ATI_DIR", str(REPO_ROOT))
MODEL = os.environ.get("CODEX_MODEL", "gpt-5.2")

DEFAULT_PROMPT = (
    "Using ATI's DeepWiki tools, research the anthropics/claude-code repository: "
    "examine its structure, understand how tool dispatch works, and summarize the architecture."
)


def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROMPT
    print(f"[MCP Agent] Prompt: {prompt}\n")

    env = {
        **os.environ,
        "ATI_DIR": ATI_DIR,
        "PATH": f"{ATI_DIR}/target/release:{os.environ.get('PATH', '')}",
    }

    result = subprocess.run(
        [
            "codex", "exec",
            "--model", MODEL,
            "--dangerously-bypass-approvals-and-sandbox",
            prompt,
        ],
        env=env,
        cwd=str(SCRIPT_DIR),
    )
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
