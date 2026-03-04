#!/usr/bin/env bash
# ATI + Codex CLI: MCP Provider Example
#
# Codex already has a built-in shell — it runs commands directly.
# We just give it an AGENTS.md that explains ATI commands and let it work.
#
# Usage:
#   ./mcp_agent.sh
#   ./mcp_agent.sh "Research the rust-lang/rust repo and explain its module system"
#
# Requires:
#   OPENAI_API_KEY environment variable
#   @openai/codex installed (npm i -g @openai/codex)
#   ATI binary on PATH

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export ATI_DIR="${ATI_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
export PATH="${ATI_DIR}/target/release:$PATH"

MODEL="${CODEX_MODEL:-gpt-5.2}"

PROMPT="${1:-Using ATI DeepWiki tools, research the anthropics/claude-code repository: examine its structure, understand how tool dispatch works, and summarize the architecture.}"

echo "[MCP Agent] Prompt: $PROMPT"
echo

cd "$SCRIPT_DIR"
codex exec \
  --model "$MODEL" \
  --dangerously-bypass-approvals-and-sandbox \
  "$PROMPT"
