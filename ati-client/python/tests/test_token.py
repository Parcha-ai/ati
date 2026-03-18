"""Tests for ati.token — JWT issuance, validation, and inspection."""

import time

import pytest

from ati import (
    AtiNamespace,
    TokenClaims,
    TokenError,
    inspect_token,
    issue_token,
    validate_token,
)

# 32-byte hex secret (64 hex chars) — matches Rust's `ati token keygen HS256` output format
TEST_SECRET = "17332cf135d362f79a2ed700b13e1215978be1d6ae6e133d25b6b3f21fa10299"


class TestIssueToken:
    def test_basic_issuance(self):
        token = issue_token(
            secret=TEST_SECRET,
            sub="agent-7",
            scope="tool:web_search tool:github:*",
        )
        assert isinstance(token, str)
        assert token.count(".") == 2  # header.payload.signature

    def test_claims_roundtrip(self):
        token = issue_token(
            secret=TEST_SECRET,
            sub="sandbox:abc123",
            scope="tool:finnhub_quote skill:research-*",
            ttl_seconds=1800,
            aud="ati-proxy",
            iss="ati-orchestrator",
            rate={"tool:finnhub_quote": "10/min"},
        )
        claims = validate_token(token, secret=TEST_SECRET)
        assert claims.sub == "sandbox:abc123"
        assert claims.aud == "ati-proxy"
        assert claims.iss == "ati-orchestrator"
        assert claims.scope == "tool:finnhub_quote skill:research-*"
        assert claims.jti is not None
        assert claims.ati is not None
        assert claims.ati.v == 1
        assert claims.ati.rate == {"tool:finnhub_quote": "10/min"}

    def test_scopes_method(self):
        token = issue_token(
            secret=TEST_SECRET,
            sub="test",
            scope="tool:a tool:b skill:c",
        )
        claims = validate_token(token, secret=TEST_SECRET)
        assert claims.scopes() == ["tool:a", "tool:b", "skill:c"]

    def test_custom_jti(self):
        token = issue_token(
            secret=TEST_SECRET,
            sub="test",
            scope="tool:x",
            jti="custom-id-123",
        )
        claims = validate_token(token, secret=TEST_SECRET)
        assert claims.jti == "custom-id-123"

    def test_default_iss(self):
        token = issue_token(secret=TEST_SECRET, sub="test", scope="tool:x")
        claims = validate_token(token, secret=TEST_SECRET)
        assert claims.iss == "ati-orchestrator"

    def test_no_iss(self):
        token = issue_token(
            secret=TEST_SECRET, sub="test", scope="tool:x", iss=None
        )
        claims = inspect_token(token)
        assert claims.iss is None

    def test_invalid_hex_secret(self):
        with pytest.raises(TokenError, match="valid hex"):
            issue_token(secret="not-hex!", sub="test", scope="tool:x")

    def test_empty_scope(self):
        token = issue_token(secret=TEST_SECRET, sub="test", scope="")
        claims = validate_token(token, secret=TEST_SECRET)
        assert claims.scope == ""
        assert claims.scopes() == []

    def test_exp_in_future(self):
        token = issue_token(
            secret=TEST_SECRET, sub="test", scope="tool:x", ttl_seconds=600
        )
        claims = validate_token(token, secret=TEST_SECRET)
        assert claims.exp > time.time()
        assert claims.exp - claims.iat == 600


class TestValidateToken:
    def test_wrong_secret(self):
        other_secret = "aa" * 32
        token = issue_token(secret=TEST_SECRET, sub="test", scope="tool:x")
        with pytest.raises(TokenError, match="validation failed"):
            validate_token(token, secret=other_secret)

    def test_wrong_audience(self):
        token = issue_token(secret=TEST_SECRET, sub="test", scope="tool:x")
        with pytest.raises(TokenError, match="audience"):
            validate_token(token, secret=TEST_SECRET, audience="wrong-aud")

    def test_wrong_issuer(self):
        token = issue_token(
            secret=TEST_SECRET, sub="test", scope="tool:x", iss="real-issuer"
        )
        with pytest.raises(TokenError, match="issuer"):
            validate_token(
                token, secret=TEST_SECRET, issuer="expected-issuer"
            )

    def test_expired_token(self):
        token = issue_token(
            secret=TEST_SECRET, sub="test", scope="tool:x", ttl_seconds=-100
        )
        with pytest.raises(TokenError, match="expired"):
            validate_token(token, secret=TEST_SECRET, leeway=0)

    def test_leeway_allows_slight_expiry(self):
        # Token expired 30 seconds ago, but 60s leeway should accept it
        token = issue_token(
            secret=TEST_SECRET, sub="test", scope="tool:x", ttl_seconds=-30
        )
        claims = validate_token(token, secret=TEST_SECRET, leeway=60)
        assert claims.sub == "test"

    def test_issuer_not_checked_when_none(self):
        token = issue_token(
            secret=TEST_SECRET, sub="test", scope="tool:x", iss="anything"
        )
        # issuer=None means don't check
        claims = validate_token(token, secret=TEST_SECRET, issuer=None)
        assert claims.iss == "anything"


class TestInspectToken:
    def test_inspect_without_secret(self):
        token = issue_token(
            secret=TEST_SECRET,
            sub="agent-99",
            scope="tool:web_search",
        )
        claims = inspect_token(token)
        assert claims.sub == "agent-99"
        assert claims.scope == "tool:web_search"

    def test_inspect_expired_token(self):
        token = issue_token(
            secret=TEST_SECRET,
            sub="old-agent",
            scope="tool:x",
            ttl_seconds=-9999,
        )
        # Should still decode without error
        claims = inspect_token(token)
        assert claims.sub == "old-agent"

    def test_inspect_garbage_token(self):
        with pytest.raises(TokenError, match="decode"):
            inspect_token("not.a.jwt")


class TestTokenClaims:
    def test_to_dict_minimal(self):
        c = TokenClaims(sub="s", aud="a", iat=0, exp=1, scope="tool:x")
        d = c.to_dict()
        assert "iss" not in d
        assert "jti" not in d
        assert "ati" not in d
        assert d["sub"] == "s"

    def test_to_dict_full(self):
        c = TokenClaims(
            sub="s",
            aud="a",
            iat=0,
            exp=1,
            scope="tool:x",
            iss="i",
            jti="j",
            ati=AtiNamespace(v=1, rate={"tool:x": "5/min"}),
        )
        d = c.to_dict()
        assert d["iss"] == "i"
        assert d["jti"] == "j"
        assert d["ati"]["v"] == 1
        assert d["ati"]["rate"] == {"tool:x": "5/min"}

    def test_from_dict_roundtrip(self):
        original = TokenClaims(
            sub="s",
            aud="a",
            iat=100,
            exp=200,
            scope="tool:a tool:b",
            iss="i",
            jti="j",
            ati=AtiNamespace(v=1, rate={"tool:a": "1/sec"}),
        )
        rebuilt = TokenClaims.from_dict(original.to_dict())
        assert rebuilt.sub == original.sub
        assert rebuilt.scope == original.scope
        assert rebuilt.ati.rate == original.ati.rate


class TestAtiNamespace:
    def test_defaults(self):
        ns = AtiNamespace()
        assert ns.v == 1
        assert ns.rate == {}

    def test_to_dict_no_rate(self):
        d = AtiNamespace(v=1).to_dict()
        assert d == {"v": 1}
        assert "rate" not in d

    def test_to_dict_with_rate(self):
        d = AtiNamespace(v=1, rate={"*": "100/day"}).to_dict()
        assert d["rate"] == {"*": "100/day"}

    def test_from_dict(self):
        ns = AtiNamespace.from_dict({"v": 1, "rate": {"tool:x": "5/min"}})
        assert ns.v == 1
        assert ns.rate == {"tool:x": "5/min"}
