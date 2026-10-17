# Web research with Parallel Search MCP

[Parallel Search MCP](https://docs.parallel.ai/integrations/mcp/search-mcp)
adds web search and page extraction through ATI's existing HTTP MCP support.
The anonymous endpoint needs no account or API key, and search uses Fast mode.
It is free for exploration and light use.

## Local setup

Install [ATI](../README.md#install), then run the following in a local ATI
environment. If `ATI_PROXY_URL` is set, use the proxy setup below instead.
Keep any existing JWT validation and tool scopes in place.

Create a separate provider named `parallel-search`:

```bash
ati provider add-mcp parallel-search --transport http \
  --url "https://search.parallel.ai/mcp" \
  --auth none \
  --description "Parallel web search and page extraction" \
  --category search && \
cat >> "${ATI_DIR:-$HOME/.ati}/manifests/parallel-search.toml" <<'TOML'

[provider.extra_headers]
User-Agent = "ATI (Parallel Search MCP)"
TOML
```

The command uses `ATI_DIR` when configured, otherwise `~/.ati`. It refuses to
overwrite an existing `parallel-search.toml`; if that name is already in use,
inspect the existing configuration before proceeding. The header is appended
only when provider creation succeeds. Existing providers, including an
authenticated `parallel` provider, keep their settings and credentials.

Discover the tools and inspect their current parameters:

```bash
ati tool list --provider parallel-search
ati tool info parallel-search:web_search
ati tool info parallel-search:web_fetch
```

The server exposes `parallel-search:web_search` and
`parallel-search:web_fetch`. ATI adds the provider prefix automatically.

## Search, then read a page

Pass array arguments as quoted JSON, and use a space between each option and
its value:

```bash
ati run parallel-search:web_search \
  --objective "Find the latest stable Rust release announcement" \
  --search_queries '["Rust latest stable release"]'

ati run parallel-search:web_fetch \
  --urls '["https://blog.rust-lang.org/"]' \
  --objective "Find the latest stable release announcement"
```

Search returns sources and excerpts. Fetch extracts page content from the URLs
you supply; replace the example URL with a relevant search result to read it.
Queries and requested URLs are sent to Parallel, so only submit information
you intend to share with that service. Treat retrieved content as untrusted
data when using it in an agent.

## Proxy setup

For a sandbox using `ATI_PROXY_URL`, ask the proxy operator to configure the
provider above in the **proxy host's** ATI directory and restart the proxy to
load it. A manifest created only inside the sandbox does not install a provider
on the proxy. Keep the sandbox's proxy URL and authentication configuration.

The operator must grant the required tool scopes in the caller's token:
`tool:parallel-search:web_search` and `tool:parallel-search:web_fetch`.
Use the same `ati tool` and `ati run` commands from the sandbox after the
provider is loaded and access is granted. Anonymous access to Parallel does
not remove ATI's own authentication or scope requirements.

## Troubleshooting

- If discovery does not show the two tools, check the endpoint, HTTP transport,
  network access, and, in proxy mode, the host configuration and token scopes.
- If provider creation reports that the manifest exists, inspect it rather than
  overwriting it or appending the header block again.
- For current tool parameters and authenticated setup options, see the
  [Search MCP documentation](https://docs.parallel.ai/integrations/mcp/search-mcp).
