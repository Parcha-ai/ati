#!/usr/bin/env bash
# ATI + Codex CLI: OpenAPI + HTTP Provider Example
#
# Codex already has a built-in shell — it runs commands directly.
# We just give it an AGENTS.md that explains ATI commands and let it work.
#
# Usage:
#   ./openapi_agent.sh
#   ./openapi_agent.sh "Find clinical trials related to CRISPR gene therapy"
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

PROMPT="${1:-Research quantum computing: find recent arXiv papers on quantum error correction, search Crossref for published academic papers on the topic, and check what is trending on Hacker News. Synthesize a structured research briefing.}"

echo "[OpenAPI Agent] Prompt: $PROMPT"
echo

cd "$SCRIPT_DIR"
codex exec \
  --model "$MODEL" \
  --dangerously-bypass-approvals-and-sandbox \
  "$PROMPT"
