# ATI — Agent Tools Interface

## Overview

ATI is a compiled Rust binary that gives AI agents secure access to external tools (HTTP APIs + MCP servers) without exposing API keys. One CLI, unified manifest format, encrypted credential storage.

## Build & Test

```bash
# Build
cargo build
cargo build --release

# Tests (145+ — unit, integration, e2e, and live MCP)
cargo test
bash scripts/test_skills_e2e.sh

# Cross-compile for sandboxes
cargo build --release --target x86_64-unknown-linux-musl
```

## Module Organization

### `src/cli/` — CLI commands (clap)
- `call.rs` — `ati call` — routes to HTTP, MCP, xAI, or proxy
- `tools.rs` — `ati tools list/info/search/providers`
- `skills.rs` — `ati skills list/show/init/install/remove/validate/resolve/search/info`
- `help.rs` — `ati assist` — LLM-powered discovery with skill context injection
- `openapi.rs` — `ati openapi inspect/import` — OpenAPI spec tools
- `auth.rs` — `ati auth status`

### `src/core/` — Core logic
- `manifest.rs` — TOML manifest parsing + registry (HTTP, MCP, OpenAPI providers)
- `openapi.rs` — OpenAPI 3.0 spec parsing, tool registration, param classification
- `skill.rs` — Skill metadata, registry, scope-driven resolution, transitive dependencies
- `mcp_client.rs` — MCP client — stdio + Streamable HTTP transport
- `http.rs` — HTTP execution + auth injection + classified params (path/query/header/body)
- `keyring.rs` — AES-256-GCM encrypted credential storage
- `scope.rs` — Per-tool scope enforcement with expiry + wildcard support
- `response.rs` — JSONPath extraction + output formatting
- `xai.rs` — xAI/Grok agentic handler

### `src/proxy/` — Proxy server
- `server.rs` — axum proxy server — `/call`, `/mcp`, `/help`, `/skills`, `/skills/:name`, `/skills/resolve`
- `client.rs` — HTTP + MCP JSON-RPC + skills forwarding to proxy (Bearer auth via `ATI_PROXY_TOKEN`)

### `src/security/` — Memory protection
- `memory.rs` — mlock, madvise, zeroize
- `sealed_file.rs` — One-shot key file read + unlink

### `tests/` — Test suite
- `manifest_test.rs` — TOML parsing, MCP/OpenAPI provider fields
- `openapi_test.rs` — OpenAPI spec parsing, tool generation, filtering
- `skill_test.rs` — Skill loading, resolution, search, transitive deps
- `keyring_test.rs` — Encryption, key resolution
- `scope_test.rs` — Scope enforcement + wildcards
- `call_test.rs` — CLI dispatch (HTTP + MCP routing)
- `help_test.rs` — LLM-powered discovery with skill context
- `proxy_test.rs` — Proxy client forwarding
- `proxy_server_test.rs` — Proxy server endpoints including /mcp and /skills
- `mcp_live_test.rs` — Live MCP integration (GitHub, Linear, DeepWiki, Everything)

## Key Types

- `ProviderManifest` — Parsed TOML provider (HTTP, MCP, or OpenAPI handler)
- `ToolDefinition` — A single tool (name, schema, endpoint, method, etc.)
- `OpenApiToolOverride` — Per-operation customization for OpenAPI tools
- `SkillMeta` — Skill metadata from skill.toml (bindings, keywords, deps)
- `SkillRegistry` — Loads, indexes, resolves skills by tool/provider/category scope
- `McpClient` — Connects to MCP servers (stdio/HTTP), discovers tools, proxies calls
- `ClassifiedParams` — HTTP params split by location (path/query/header/body)

## Manifest Directory

`manifests/` — TOML tool definitions. Three provider types:

1. **HTTP** (`handler` absent or `"http"`) — Hand-written `[[tools]]` blocks
2. **MCP** (`handler = "mcp"`) — Auto-discovered via MCP `tools/list`
3. **OpenAPI** (`handler = "openapi"`) — Auto-discovered from OAS 3.0 spec

## Specs Directory

`specs/` — OpenAPI 3.0 spec files referenced by `openapi_spec` field in manifests. 17 included specs for public APIs.

## Proxy Server Architecture

Endpoints:
- `GET /health` — Health check (tool/provider/skill counts)
- `POST /call` — Execute HTTP tool
- `POST /mcp` — MCP JSON-RPC proxy
- `POST /help` — LLM-powered discovery
- `GET /skills` — List skills (supports `?category=X&provider=Y&tool=Z&search=Q`)
- `GET /skills/:name` — Show skill content (supports `?meta=true&refs=true`)
- `POST /skills/resolve` — Resolve skills for given scopes

## Auth Types

bearer, header, query, basic, oauth2, none — all injected transparently by ATI.

## Proxy Auth

`ATI_PROXY_TOKEN` env var — Bearer token sent on all proxy client requests.
