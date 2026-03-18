"""JWT token utilities — issue, validate, and inspect ATI tokens.

Produces tokens that are binary-compatible with the ATI Rust proxy
(``proxy/server.rs`` validation, ``core/jwt.rs`` claims).
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import jwt as pyjwt

from .errors import TokenError


# ---------------------------------------------------------------------------
# Claims
# ---------------------------------------------------------------------------

@dataclass
class AtiNamespace:
    """The ``ati`` namespace in the JWT payload."""

    v: int = 1
    rate: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"v": self.v}
        if self.rate:
            d["rate"] = self.rate
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AtiNamespace:
        return cls(v=d.get("v", 1), rate=d.get("rate", {}))


@dataclass
class TokenClaims:
    """Decoded JWT claims — mirrors ``core::jwt::TokenClaims`` in Rust."""

    sub: str
    aud: str
    iat: int
    exp: int
    scope: str
    iss: str | None = None
    jti: str | None = None
    ati: AtiNamespace | None = None

    def scopes(self) -> list[str]:
        """Return individual scope entries."""
        return self.scope.split() if self.scope else []

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "sub": self.sub,
            "aud": self.aud,
            "iat": self.iat,
            "exp": self.exp,
            "scope": self.scope,
        }
        if self.iss is not None:
            d["iss"] = self.iss
        if self.jti is not None:
            d["jti"] = self.jti
        if self.ati is not None:
            d["ati"] = self.ati.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TokenClaims:
        ati_raw = d.get("ati")
        return cls(
            sub=d["sub"],
            aud=d.get("aud", "ati-proxy"),
            iat=d.get("iat", 0),
            exp=d.get("exp", 0),
            scope=d.get("scope", ""),
            iss=d.get("iss"),
            jti=d.get("jti"),
            ati=AtiNamespace.from_dict(ati_raw) if ati_raw else None,
        )


# ---------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------

def _decode_hs256_secret(secret: str) -> bytes:
    """Decode a hex-encoded HS256 secret to raw bytes.

    The ATI Rust proxy always hex-decodes ``ATI_JWT_SECRET`` before use.
    """
    try:
        return bytes.fromhex(secret)
    except ValueError as exc:
        raise TokenError(f"HS256 secret must be valid hex: {exc}") from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def issue_token(
    *,
    secret: str,
    sub: str,
    scope: str,
    ttl_seconds: int = 3600,
    aud: str = "ati-proxy",
    iss: str | None = "ati-orchestrator",
    jti: str | None = None,
    rate: dict[str, str] | None = None,
) -> str:
    """Issue a signed HS256 JWT compatible with the ATI Rust proxy.

    Args:
        secret: Hex-encoded 32-byte HS256 secret (64 hex chars).
        sub: Subject — agent or sandbox identifier.
        scope: Space-delimited scope string (e.g. ``"tool:web_search tool:github:*"``).
        ttl_seconds: Token lifetime in seconds (default 3600).
        aud: Audience claim (default ``"ati-proxy"``).
        iss: Issuer claim (default ``"ati-orchestrator"``).
        jti: Token ID (auto-generated UUID4 if None).
        rate: Optional per-tool rate limits (e.g. ``{"tool:github:*": "10/hour"}``).

    Returns:
        Signed JWT string.
    """
    key = _decode_hs256_secret(secret)
    now = int(time.time())

    claims = TokenClaims(
        sub=sub,
        aud=aud,
        iat=now,
        exp=now + ttl_seconds,
        scope=scope,
        iss=iss,
        jti=jti or str(uuid.uuid4()),
        ati=AtiNamespace(v=1, rate=rate or {}),
    )

    try:
        return pyjwt.encode(claims.to_dict(), key, algorithm="HS256")
    except Exception as exc:
        raise TokenError(f"Failed to sign token: {exc}") from exc


def validate_token(
    token: str,
    *,
    secret: str,
    audience: str = "ati-proxy",
    issuer: str | None = None,
    leeway: int = 60,
) -> TokenClaims:
    """Validate a JWT and return its claims.

    Args:
        token: The JWT string.
        secret: Hex-encoded HS256 secret.
        audience: Expected ``aud`` claim (default ``"ati-proxy"``).
        issuer: Expected ``iss`` claim (None = don't check).
        leeway: Clock skew tolerance in seconds (default 60, matching Rust proxy).

    Returns:
        Decoded :class:`TokenClaims`.

    Raises:
        TokenError: If validation fails.
    """
    key = _decode_hs256_secret(secret)

    options: dict[str, Any] = {}
    kwargs: dict[str, Any] = {
        "algorithms": ["HS256"],
        "audience": audience,
        "leeway": leeway,
        "options": options,
    }
    if issuer is not None:
        kwargs["issuer"] = issuer

    try:
        payload = pyjwt.decode(token, key, **kwargs)
    except pyjwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except pyjwt.InvalidAudienceError as exc:
        raise TokenError(f"Invalid audience: {exc}") from exc
    except pyjwt.InvalidIssuerError as exc:
        raise TokenError(f"Invalid issuer: {exc}") from exc
    except pyjwt.PyJWTError as exc:
        raise TokenError(f"Token validation failed: {exc}") from exc

    return TokenClaims.from_dict(payload)


def inspect_token(token: str) -> TokenClaims:
    """Decode a JWT *without* validation — for debugging only.

    Returns:
        Decoded :class:`TokenClaims` (signature not verified).
    """
    try:
        payload = pyjwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["HS256", "ES256"],
        )
    except pyjwt.PyJWTError as exc:
        raise TokenError(f"Failed to decode token: {exc}") from exc

    return TokenClaims.from_dict(payload)
