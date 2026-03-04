# IDEAS — Future Directions for ATI

These are ideas we're NOT building yet. Captured here for future reference.

## 1. Progressive Learning Registry

Agents suggest new tools at runtime. When an agent web-searches and finds a useful API:
- `ati registry suggest "pdf_merge" "Merge PDFs via ilovepdf.com" --docs-url https://developer.ilovepdf.com`
- Suggestion stored locally, synced to a central registry after sandbox session
- Human reviews → approves → manifest auto-generated → tool available in next session
- Future: auto-generate TOML manifest by fetching API docs URL and parsing with LLM
- Future: auto-approve for trusted agents with good track records

## 2. MCP Auto-Discovery & Instant Use

Agent discovers an MCP server in the wild:
- Agent tells user: "I found a Garmin MCP server. I need credentials to authenticate."
- User provides credentials through a **secure side-channel** (never through agent chat):
  - Option A: `ati auth add-provider garmin --interactive`
  - Option B: User adds via web dashboard → writes to keyring
  - Option C: ATI generates QR code / one-time URL for secure cred entry
- Credentials encrypted into keyring immediately
- ATI auto-generates manifest from MCP server's `tools/list`
- Agent uses new MCP tools instantly — zero restart

Key principle: **user credentials NEVER flow through the agent's conversation**

## 3. WASM Plugin System

For tools needing complex multi-step logic (scraping + pagination, OAuth, retry):
- Tool handler = WASM module in wasmtime sandbox
- Network access limited to declared `base_url` only
- WASM module gets keyring keys via imports, can't exfiltrate
- Anyone can write plugins in Rust/Go/C and distribute

## 4. Token Usage Optimization

- `ati run --filter "only companies in California"` — post-process with fast LLM
- `ati run --jsonpath "$.results[?(@.score > 0.8)]"` — JSONPath client-side filtering
- Track cumulative token usage per session: `ati usage`
- Budget enforcement: `ati run --max-tokens 5000`

## 5. Tool Composition / Pipelines

```bash
ati pipe "web_search --query 'Acme Corp' | parcha_scrape --url {$.results[0].url}"
```
- Chain tool outputs as inputs
- Reduces agent round-trips (one bash command instead of two)

## 6. Offline Mode / Caching

- `ati run --cache 1h web_search --query "test"` — cache results
- Useful when agent retries or explores variations
- Cache in `~/.ati/cache/` with TTL-based eviction

## 7. Multi-Sandbox Key Sharing

- Multiple sandboxes for same user share a keyring
- Orchestrator generates ONE keyring, distributes to all related sandboxes
- Revocation: remotely invalidate session key via signed revocation list
