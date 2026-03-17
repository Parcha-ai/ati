"""ATI Python SDK — orchestrator provisioning and token utilities."""

from __future__ import annotations

from .errors import AtiError, ProvisionError, ScopeError, TokenError
from .scope import build_scope_string, check_scope, matches_wildcard, parse_scopes
from .token import (
    AtiNamespace,
    TokenClaims,
    inspect_token,
    issue_token,
    validate_token,
)

__all__ = [
    "AtiOrchestrator",
    # Token
    "issue_token",
    "validate_token",
    "inspect_token",
    "TokenClaims",
    "AtiNamespace",
    # Scopes
    "build_scope_string",
    "check_scope",
    "matches_wildcard",
    "parse_scopes",
    # Errors
    "AtiError",
    "TokenError",
    "ScopeError",
    "ProvisionError",
]

__version__ = "0.1.0"


class AtiOrchestrator:
    """One-call provisioning for Python orchestrators.

    Usage::

        orch = AtiOrchestrator(
            proxy_url="https://ati-proxy.example.com",
            secret="17332cf135d362f79a2ed700b13e1215...",
        )
        env_vars = orch.provision_sandbox(
            agent_id="sandbox:abc123",
            tools=["finnhub_quote", "web_search"],
            skills=["financial-analysis"],
            ttl_seconds=7200,
        )
        # env_vars = {"ATI_PROXY_URL": "...", "ATI_SESSION_TOKEN": "eyJ..."}
    """

    def __init__(
        self,
        *,
        proxy_url: str,
        secret: str,
        default_aud: str = "ati-proxy",
        default_iss: str = "ati-orchestrator",
    ) -> None:
        self.proxy_url = proxy_url.rstrip("/")
        self.secret = secret
        self.default_aud = default_aud
        self.default_iss = default_iss

    def provision_sandbox(
        self,
        *,
        agent_id: str,
        tools: list[str] | None = None,
        skills: list[str] | None = None,
        extra_scopes: list[str] | None = None,
        ttl_seconds: int = 3600,
        rate: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Generate env vars to inject into a sandboxed agent.

        Args:
            agent_id: Unique identifier for this sandbox/agent (becomes JWT ``sub``).
            tools: Tool names to grant access to (e.g. ``["web_search", "github__*"]``).
            skills: Skill names to grant (e.g. ``["financial-analysis"]``).
            extra_scopes: Additional raw scope strings (e.g. ``["help"]``).
            ttl_seconds: Token lifetime (default 3600).
            rate: Per-tool rate limits (e.g. ``{"tool:github__*": "10/hour"}``).

        Returns:
            Dict with ``ATI_PROXY_URL`` and ``ATI_SESSION_TOKEN``.
        """
        scope = build_scope_string(
            tools=tools,
            skills=skills,
            extra=extra_scopes,
        )

        token = issue_token(
            secret=self.secret,
            sub=agent_id,
            scope=scope,
            ttl_seconds=ttl_seconds,
            aud=self.default_aud,
            iss=self.default_iss,
            rate=rate,
        )

        return {
            "ATI_PROXY_URL": self.proxy_url,
            "ATI_SESSION_TOKEN": token,
        }

    def validate_token(
        self,
        token: str,
        *,
        issuer: str | None = None,
        leeway: int = 60,
    ) -> TokenClaims:
        """Validate a token issued by this orchestrator."""
        return validate_token(
            token,
            secret=self.secret,
            audience=self.default_aud,
            issuer=issuer,
            leeway=leeway,
        )
