#!/usr/bin/env npx tsx
/**
 * ATI + Pi SDK: MCP Provider Example
 *
 * The agent uses Pi's built-in bashTool to call `ati` commands — same as its
 * native coding agent. ATI bridges to DeepWiki's remote MCP server transparently.
 *
 * Usage:
 *   npx tsx mcp_agent.ts
 *   npx tsx mcp_agent.ts "Research the rust-lang/rust repo and explain its module system"
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

ATI gives you tools backed by an MCP server called DeepWiki — it provides AI-powered \
documentation for any GitHub repository.

## ATI Commands

\`\`\`bash
# Ask ATI for help (LLM-powered tool recommendations)
ati assist "research a github repository"

# Discover tools (find what's available)
ati tool search "deepwiki"

# Inspect a tool's input schema before calling it
ati tool info deepwiki__ask_question

# Call a tool
ati run deepwiki__ask_question --repoName "owner/repo" --question "How does X work?"
\`\`\`

MCP tool names follow the pattern \`deepwiki__<tool_name>\`. Use \`ati tool search\` \
to discover them, \`ati tool info\` to see their schemas, then \`ati run\` to execute.

ATI_DIR is set to \`${ATI_DIR}\` — the ati binary will find its manifests there.

Be thorough: explore the repo structure first, then dive into specifics. \
Synthesize your findings into a clear, well-organized summary.`;

const DEFAULT_PROMPT =
  "Using ATI's DeepWiki tools, research the anthropics/claude-code repository: " +
  "examine its structure, understand how tool dispatch works, and summarize the architecture.";

const prompt = process.argv[2] ?? DEFAULT_PROMPT;
console.log(`[MCP Agent] Prompt: ${prompt}\n`);

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
