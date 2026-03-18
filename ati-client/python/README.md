# ati-client

Python SDK for [ATI](https://github.com/Parcha-ai/ati) (Agent Tools Interface) — orchestrator provisioning and JWT token utilities.

## Install

```bash
pip install ati-client
```

## Quick Start

### Orchestrator Provisioning

```python
from ati import AtiOrchestrator

orch = AtiOrchestrator(
    proxy_url="https://ati-proxy.example.com",
    secret="17332cf135d362f79a2ed700b13e1215978be1d6ae6e133d25b6b3f21fa10299",
)

# Generate env vars to inject into a sandboxed agent
env_vars = orch.provision_sandbox(
    agent_id=f"sandbox:{sandbox_id}",
    tools=["finnhub_quote", "web_search", "github:*"],
    skills=["financial-analysis"],
    ttl_seconds=7200,
    rate={"tool:github:*": "10/hour"},
)

# env_vars = {
#     "ATI_PROXY_URL": "https://ati-proxy.example.com",
#     "ATI_SESSION_TOKEN": "eyJ...",
# }
```

### Token Utilities

```python
from ati import issue_token, validate_token, inspect_token

# Issue a token
token = issue_token(
    secret="17332cf135d362f79a...",
    sub="agent-7",
    scope="tool:web_search tool:finnhub_quote",
    ttl_seconds=3600,
)

# Validate (checks signature, expiry, audience)
claims = validate_token(token, secret="17332cf135d362f79a...")
print(claims.sub)      # "agent-7"
print(claims.scopes()) # ["tool:web_search", "tool:finnhub_quote"]

# Inspect without validation (debugging)
claims = inspect_token(token)
```

### Scope Utilities

```python
from ati import build_scope_string, check_scope, matches_wildcard

# Build scope strings
scope = build_scope_string(
    tools=["web_search", "github:*"],
    skills=["research-*"],
    extra=["help"],
)
# "tool:web_search tool:github:* skill:research-* help"

# Check if a tool is allowed
check_scope("tool:github:search_repos", ["tool:github:*"])  # True
check_scope("tool:secret_api", ["tool:web_search"])            # False

# Wildcard matching
matches_wildcard("tool:github:search", "tool:github:*")  # True
matches_wildcard("anything", "*")                           # True
```

## JWT Format

Tokens are HS256-signed JWTs compatible with the ATI Rust proxy. The secret must be a hex-encoded 32-byte key (64 hex characters).

Claims payload:

```json
{
  "sub": "agent-7",
  "aud": "ati-proxy",
  "iat": 1700000000,
  "exp": 1700003600,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "ati-orchestrator",
  "scope": "tool:web_search tool:github:*",
  "ati": {
    "v": 1,
    "rate": {
      "tool:github:*": "10/hour"
    }
  }
}
```

## Development

```bash
cd ati-client
pip install -e ".[dev]"
pytest
```
