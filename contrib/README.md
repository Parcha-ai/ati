# contrib/ — Community & Extended Manifests

This directory holds additional provider manifests and OpenAPI specs beyond the curated set in `manifests/` and `specs/`.

The files in `contrib/manifests/` and `contrib/specs/` are **gitignored** — they exist on disk for local development but are not distributed with the repo.

## Using a contrib manifest

Copy (or symlink) it into your ATI manifests directory:

```bash
# Copy to your local ATI config
cp contrib/manifests/complyadvantage.toml ~/.ati/manifests/

# Or copy to the repo's manifests/ for local dev
cp contrib/manifests/complyadvantage.toml manifests/
```

If the manifest references an OpenAPI spec, copy the spec too:

```bash
cp contrib/specs/sec_edgar.json specs/
```

## What's here

These manifests cover finance, compliance, legal, medical, real estate, shipping, and more. Each `.toml` file is a complete provider definition — just copy it and set any required API keys with `ati key set`.

## Contributing

To add a new provider manifest:

1. Create it with `ati provider import-openapi` or `ati provider add-mcp`
2. Place the `.toml` in `contrib/manifests/`
3. Place any OpenAPI spec `.json` in `contrib/specs/`
