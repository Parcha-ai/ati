# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) and other AI coding agents when working with code in this repository.

## What ATI Is

ATI (Agent Tools Interface) is a single compiled Rust binary that gives AI agents secure, scoped access to external tools — HTTP APIs, MCP servers, and OpenAPI-backed services — without exposing API keys. Agents call `ati run <tool> --arg value` and ATI handles auth injection, protocol bridging, scope enforcement, and response formatting.

Two execution modes, auto-detected by the `ATI_PROXY_URL` environment variable:
- **Local mode** (default): ATI decrypts `keyring.enc` with a one-shot session key, calls APIs directly, keys held in mlock'd memory
- **Proxy mode**: ATI forwards all calls to an external proxy server holding the real keys; the sandbox has zero credentials

Three provider types, set by the `handler` field in TOML manifests:
- **HTTP** (default): Hand-written `[[tools]]` sections with endpoints and schemas
- **MCP** (`handler = "mcp"`): Tools auto-discovered via MCP `tools/list` protocol. Supports stdio (subprocess) and Streamable HTTP transports
- **OpenAPI** (`handler = "openapi"`): Tools auto-discovered from an OAS 3.0 spec file. Parameters auto-classified by location (path/query/header/body) using `x-ati-param-location` metadata

## Build & Test

```bash
cargo build                                            # debug build
cargo build --release                                  # release build
cargo build --release --target x86_64-unknown-linux-musl  # static binary for sandboxes

cargo test                                             # all unit + integration tests (~270)
cargo test --test manifest_test                        # single test file
cargo test test_parse_parallel_manifest                # single test by name
cargo test mcp_client                                  # tests matching a pattern
cargo test --test mcp_live_test -- --ignored           # live MCP tests (need real API keys)

bash scripts/test_skills_e2e.sh                        # skill lifecycle e2e (starts proxy, ~30 cases)
bash scripts/test_proxy_e2e.sh                         # proxy mode routing e2e
bash scripts/test_proxy_server_e2e.sh                  # full proxy→upstream round-trip e2e
```

## Architecture

### Call Dispatch

```
main.rs (clap)
  Commands::Run → cli/call.rs
    ├─ ATI_PROXY_URL set? → proxy/client.rs POST /call
    └─ Local:
         ManifestRegistry::load(manifests/) → get_tool(name) → check scopes → load keyring
         dispatch on provider.handler:
           "mcp"     → core/mcp_client.rs  (stdio subprocess or HTTP+SSE)
           "xai"     → core/xai.rs         (agentic endpoint, custom response extraction)
           _         → core/http.rs        (generic HTTP with classified params)
```

Other commands:
- `ati tool {list,info,search}` → `cli/tools.rs` — fuzzy search with scoring across name/description/tags/category/hints
- `ati provider {add-mcp,import-openapi,inspect-openapi,list,remove,info}` → `cli/provider.rs` — unified provider management
- `ati assist <query>` → `cli/help.rs` — builds tool+skill context, calls LLM, returns recommendations with exact `ati run` commands
- `ati skill {list,show,search,info,install,remove,init,validate,resolve}` → `cli/skills.rs`
- `ati key {set,list,remove}` → `cli/keys.rs` — credential management
- `ati token {keygen,issue,inspect,validate}` → `cli/token.rs` — JWT key management and token lifecycle
- `ati proxy --port 8090` → `proxy/server.rs` — axum server with `/call`, `/mcp`, `/help`, `/skills`, `/health`

### Module Map

**Public API** (exposed via `lib.rs` for integration tests and embedding):
- `core` — manifest registry, openapi parser, skill system, mcp client, http executor, keyring, scopes, response processing, xai handler
- `proxy` — client (forwards to proxy) and server (axum, holds keys)
- `security` — mlock/madvise/zeroize wrappers, sealed one-shot key file

**Binary-only** (not in `lib.rs`):
- `cli` — command handlers
- `output` — json/table/text formatters
- `providers` — generic HTTP provider glue

### Key Types

| Type | Module | Role |
|------|--------|------|
| `ManifestRegistry` | `core/manifest.rs` | Parses all `manifests/*.toml`, indexes tools by name via `HashMap<String, (usize, usize)>` for O(1) lookup. For OpenAPI providers, loads spec and auto-registers tools at load time. |
| `Provider` | `core/manifest.rs` | One `[provider]` per manifest file. Carries auth config, handler type, MCP transport settings, OpenAPI spec reference, extra headers. |
| `Tool` | `core/manifest.rs` | One `[[tools]]` entry. Name, endpoint, method, input schema, response config, tags, hints. |
| `McpClient` | `core/mcp_client.rs` | Connects to MCP server via stdio (subprocess, newline-delimited JSON-RPC) or Streamable HTTP (POST with SSE parsing). Manages `Mcp-Session-Id` for HTTP transport. Caches discovered tools. |
| `ClassifiedParams` | `core/http.rs` | Splits args into path/query/header/body based on `x-ati-param-location` metadata injected by the OpenAPI parser. Falls back to legacy mode (GET→query, POST→body) for hand-written tools. |
| `SkillMeta` | `core/skill.rs` | Parsed `skill.toml` — name, version, author, description, tool/provider/category bindings, keywords, depends_on, suggests. |
| `SkillRegistry` | `core/skill.rs` | Loads `~/.ati/skills/*/`, indexes by tool/provider/category for fast lookup. Resolves skills transitively from scopes. |
| `Keyring` | `core/keyring.rs` | AES-256-GCM encrypted key-value store. Session key read once from `/run/ati/.key` then unlinked. Memory mlock'd and zeroized on drop. |
| `JwtConfig` | `core/jwt.rs` | JWT validation/issuance config: algorithm (ES256/HS256), keys, required issuer/audience, leeway. |
| `TokenClaims` | `core/jwt.rs` | JWT claims: sub, aud, scope (space-delimited), exp, iat, jti, ati namespace. |
| `ScopeConfig` | `core/scope.rs` | Per-tool allowlist with expiry timestamps. Supports wildcards (`tool:github:*`). Built from JWT claims. |
| `ProxyState` | `proxy/server.rs` | Axum shared state: registry + skill_registry + keyring + jwt_config + verbose flag. |

### MCP Tool Naming

MCP-discovered tools are namespaced as `<provider>:<tool_name>` (colon separator). When dispatching a call, the provider prefix is stripped before sending to the MCP server. Example: `ati run github:search_repositories` → MCP `tools/call` with name `search_repositories`.

### OpenAPI Parameter Classification

The OpenAPI parser (`core/openapi.rs`) injects `x-ati-param-location` into each property's JSON Schema when generating tools. At execution time, `core/http.rs::classify_params()` reads this metadata to route parameters:
- `path` → substituted into URL template (`/pet/{petId}` → `/pet/5`)
- `query` → appended as query string
- `header` → added as HTTP headers
- `body` → sent as JSON request body

Hand-written HTTP tools (no `x-ati-param-location`) use legacy mode: GET sends all args as query params, POST/PUT/DELETE sends all as JSON body.

### Skill Resolution Cascade

When `ati assist` or `/skills/resolve` runs, skills are auto-loaded by walking scopes:
1. Explicit `skill:X` scope → load skill X directly
2. `tool:Y` scope → skills whose `tools[]` binding includes Y
3. Tool Y's provider → skills whose `providers[]` binding includes that provider
4. Provider's category → skills whose `categories[]` binding includes that category
5. Any loaded skill's `depends_on[]` → transitively load those dependencies

Skills are methodology documents (`SKILL.md`) that teach agents *how* to use tools, complementing the tools that provide *data access*.

### Proxy Server

The proxy (`ati proxy`) is an axum HTTP server that holds all secrets and serves sandboxed agents:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Status — tool/provider/skill counts, version |
| `/call` | POST | Execute tool — `{tool_name, args}` → `{result, error}` |
| `/mcp` | POST | MCP JSON-RPC pass-through — routes `tools/call` to correct backend by tool name |
| `/help` | POST | LLM-powered discovery — `{query}` → `{content, error}` |
| `/skills` | GET | List skills — `?category=X&provider=Y&tool=Z&search=Q` |
| `/skills/:name` | GET | Skill detail — `?meta=true&refs=true` |
| `/skills/resolve` | POST | Resolve skills for given scopes |

Proxy auth: JWT Bearer token via `ATI_SESSION_TOKEN` env var on all client requests.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ATI_OUTPUT` | Default output format: `json`, `table`, or `text` (default: `text`) |
| `ATI_PROXY_URL` | If set, enables proxy mode (e.g., `http://proxy-host:8090`) |
| `ATI_SESSION_TOKEN` | JWT Bearer token for proxy client auth (carries scopes) |
| `ATI_DIR` | Override ATI directory (default: `~/.ati`) |
| `ATI_KEY_FILE` | Override session key path (default: `/run/ati/.key`) |
| `ATI_JWT_PUBLIC_KEY` | Path to ES256 public key PEM (proxy validation) |
| `ATI_JWT_PRIVATE_KEY` | Path to ES256 private key PEM (token issuance) |
| `ATI_JWT_SECRET` | Hex-encoded HS256 shared secret (simpler alternative) |
| `ATI_JWT_ISSUER` | Expected `iss` claim in JWTs (optional) |
| `ATI_JWT_AUDIENCE` | Expected `aud` claim (default: `ati-proxy`) |
| `ATI_SSRF_PROTECTION` | SSRF protection mode: `1`/`true` to block, `warn` to log |
| `RUST_LOG` | Tracing log level (e.g., `debug`) |

## Manifests

Each `.toml` file in `manifests/` defines one provider with its tools.

**HTTP provider** — hand-written tools:
```toml
[provider]
name = "my_api"
base_url = "https://api.example.com/v1"
auth_type = "bearer"          # bearer | header | query | basic | oauth2 | none
auth_key_name = "my_api_key"  # key name in keyring.enc

[[tools]]
name = "my_search"
endpoint = "/search"
method = "POST"
[tools.input_schema]
type = "object"
required = ["query"]
[tools.input_schema.properties.query]
type = "string"
```

**MCP provider** — tools auto-discovered, no `[[tools]]` needed:
```toml
[provider]
name = "github"
handler = "mcp"
mcp_transport = "stdio"            # stdio | http
mcp_command = "npx"
mcp_args = ["-y", "@modelcontextprotocol/server-github"]
auth_type = "none"
[provider.mcp_env]
GITHUB_PERSONAL_ACCESS_TOKEN = "${github_token}"   # resolved from keyring
```

**OpenAPI provider** — tools auto-discovered from spec, no `[[tools]]` needed:
```toml
[provider]
name = "finnhub"
handler = "openapi"
base_url = "https://finnhub.io/api/v1"
openapi_spec = "finnhub.json"      # file in specs/ directory
auth_type = "query"
auth_query_name = "token"
auth_key_name = "finnhub_api_key"
openapi_max_operations = 50        # cap tools from large specs
```

OpenAPI providers support filtering (`openapi_include_tags`, `openapi_exclude_tags`, `openapi_include_operations`, `openapi_exclude_operations`) and per-operation overrides (`[provider.openapi_overrides.<operationId>]`).

Internal providers (`internal = true`) are hidden from `ati tool list` — used for the LLM backing `ati assist`.

## Specs Directory

`specs/` contains pre-downloaded OpenAPI 3.0 JSON files referenced by `openapi_spec` fields in manifests. The `ati provider import-openapi` command downloads and normalizes specs into this directory.

## Testing Patterns

- **Unit tests**: `#[cfg(test)] mod tests` inside core modules (keyring, mcp_client, scope)
- **Integration tests**: `tests/*.rs` — each mirrors a source module. Uses `wiremock` for HTTP mocking and `tempfile::TempDir` for isolated fixture directories
- **Subprocess tests**: `assert_cmd` + `env!("CARGO_BIN_EXE_ati")` for testing the compiled binary with env var overrides
- **Proxy endpoint tests**: axum Router tested in-process via `tower::ServiceExt::oneshot` — no TCP binding needed
- **Live MCP tests**: `tests/mcp_live_test.rs` — calls real MCP servers (GitHub, Linear, DeepWiki). Requires real API keys, runs with `--ignored`
- **E2E shell scripts**: `scripts/` — spin up Python mock servers or `ati proxy`, exercise full round-trips with `curl`

## Conventions

- `thiserror` for custom error types per module; `main.rs` prints full error chain in `--verbose` mode
- `parse_tool_args()` converts `--key value` CLI pairs to `HashMap<String, serde_json::Value>`. Tries JSON parse first, falls back to string. `--flag` alone becomes `true`
- OAuth2 tokens cached in a static `LazyLock<Mutex<HashMap>>` with expiry tracking
- MCP JSON-RPC uses incrementing `id` counters; SSE responses parsed for `data:` lines with JSON extraction
- OpenAPI PATCH operations mapped to PUT (ATI's `HttpMethod` enum has no PATCH variant)
- Multipart/form-data operations skipped during OpenAPI import
- Skills without `skill.toml` are supported for backward compatibility (metadata inferred from SKILL.md)
