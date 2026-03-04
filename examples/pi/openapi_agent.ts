#!/usr/bin/env npx tsx
/**
 * ATI + Pi SDK: OpenAPI + HTTP Provider Example
 *
 * The agent uses Pi's built-in bashTool to call `ati` commands — same as its
 * native coding agent. Shows ATI's unified interface across different provider types:
 * - Crossref (OpenAPI provider) — tools auto-discovered from an OAS 3.0 spec
 * - arXiv (HTTP provider) — hand-written TOML manifest
 * - Hacker News (HTTP provider) — hand-written TOML manifest
 *
 * Same `ati call` interface for all three. The agent doesn't care which backend.
 *
 * Usage:
 *   npx tsx openapi_agent.ts
 *   npx tsx openapi_agent.ts "Find clinical trials related to CRISPR gene therapy"
 *
 * Requires:
 *   ANTHROPIC_API_KEY (or any supported provider key)
 *   ATI binary on PATH (or set ATI_DIR env var)
 */

import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { createAgentSession, createBashTool, SessionManager, DefaultResourceLoader } from "@mariozechner/pi-coding-agent";
import { getModel } from "@mariozechner/pi-ai";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "../..");
const ATI_DIR = process.env.ATI_DIR ?? REPO_ROOT;
const MODEL_PROVIDER = process.env.PI_PROVIDER ?? "anthropic";
const MODEL_ID = process.env.PI_MODEL ?? "claude-haiku-4-5-20251001";

// Ensure ATI_DIR is in the environment for subprocess calls
process.env.ATI_DIR = ATI_DIR;

const SYSTEM_PROMPT = `\
You are a research agent. You have access to ATI (Agent Tools Interface) via the \
\`ati\` CLI on your PATH.

ATI gives you tools from multiple providers through a unified interface:

- **Crossref** (OpenAPI) — published academic papers with DOI metadata and citations. \
Tools auto-discovered from an OAS 3.0 spec, names like \`crossref__get_works\`.
- **arXiv** (HTTP) — preprint paper search. Tool: \`academic_search_arxiv\`.
- **Hacker News** (HTTP) — tech news from Y Combinator. Tools: \`hackernews_top_stories\`, \
\`hackernews_new_stories\`, \`hackernews_best_stories\`.

## ATI Commands

\`\`\`bash
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
\`\`\`

ATI_DIR is set to \`${ATI_DIR}\` — the ati binary will find its manifests there.

Cross-reference results from multiple sources. Synthesize findings into a clear, \
structured research briefing.`;

const DEFAULT_PROMPT =
  "Research quantum computing: find recent arXiv papers on quantum error correction, " +
  "search Crossref for published academic papers on the topic, and check what's trending " +
  "on Hacker News. Synthesize a structured research briefing.";

const prompt = process.argv[2] ?? DEFAULT_PROMPT;
console.log(`[OpenAPI Agent] Prompt: ${prompt}\n`);

const cwd = process.cwd();
const resourceLoader = new DefaultResourceLoader({
  systemPromptOverride: () => SYSTEM_PROMPT,
  appendSystemPromptOverride: () => [],
});

const { session } = await createAgentSession({
  cwd,
  model: getModel(MODEL_PROVIDER, MODEL_ID),
  thinkingLevel: "off",
  tools: [createBashTool(cwd)],
  sessionManager: SessionManager.inMemory(),
  resourceLoader,
});

session.subscribe((event) => {
  if (event.type === "message_update") {
    const msg = event.assistantMessageEvent;
    if (msg.type === "text_delta") {
      process.stdout.write(msg.delta);
    } else if (msg.type === "tool_use_begin") {
      console.log(`\n> [${msg.name}]`);
    }
  }
});

await session.prompt(prompt);
console.log("\n\n--- Done ---");
