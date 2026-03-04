# ATI Tool Manifests

This directory contains example tool manifest files for ATI (Agent Tools Interface).

## Quick Start

1. Copy `example.toml` and rename it to `<your_provider>.toml`
2. Edit the provider section with your API details
3. Define one or more `[[tools]]` sections
4. Place the file in `~/.ati/manifests/`
5. Run `ati tool list` to verify it loaded

## File Format

Each manifest is a TOML file with:
- **One** `[provider]` section defining the API provider
- **One or more** `[[tools]]` sections defining individual tools

See `example.toml` for a fully annotated reference.

## Included Manifests

| File | Provider | Tools | Auth |
|------|----------|-------|------|
| `parallel.toml` | Parallel.ai | web_search, web_fetch | Bearer token |
| `pubmed.toml` | PubMed/NCBI | medical_search_pubmed | None (free) |
| `epo.toml` | European Patent Office | patent_search_epo | Bearer token |
| `middesk.toml` | Middesk | middesk_us_business_lookup | Bearer token |
| `_llm.toml` | Cerebras | _chat_completion | Bearer (internal) |

## Authentication Types

- `bearer` — `Authorization: Bearer <key>` header (most APIs)
- `header` — `X-Api-Key: <key>` header
- `query` — `?api_key=<key>` query parameter
- `basic` — HTTP Basic authentication
- `none` — No authentication needed
