"""Tests for AtiOrchestrator — end-to-end provisioning."""

import io
import json
import warnings
from unittest.mock import patch

from ati import AtiOrchestrator, build_skill_instructions, inspect_token, validate_token

TEST_SECRET = "17332cf135d362f79a2ed700b13e1215978be1d6ae6e133d25b6b3f21fa10299"


class TestAtiOrchestrator:
    def setup_method(self):
        self.orch = AtiOrchestrator(
            proxy_url="https://ati-proxy.example.com",
            secret=TEST_SECRET,
        )

    def test_provision_returns_env_vars(self):
        env = self.orch.provision_sandbox(
            agent_id="sandbox:abc123",
            tools=["web_search", "finnhub_quote"],
        )
        assert "ATI_PROXY_URL" in env
        assert "ATI_SESSION_TOKEN" in env
        assert env["ATI_PROXY_URL"] == "https://ati-proxy.example.com"

    def test_provision_token_is_valid(self):
        env = self.orch.provision_sandbox(
            agent_id="sandbox:xyz",
            tools=["web_search"],
            skills=["research-*"],
            ttl_seconds=1800,
        )
        claims = validate_token(env["ATI_SESSION_TOKEN"], secret=TEST_SECRET)
        assert claims.sub == "sandbox:xyz"
        assert claims.aud == "ati-proxy"
        assert claims.iss == "ati-orchestrator"
        assert "tool:web_search" in claims.scope
        assert "skill:research-*" in claims.scope
        assert claims.exp - claims.iat == 1800

    def test_provision_with_rate_limits(self):
        env = self.orch.provision_sandbox(
            agent_id="agent-1",
            tools=["github:*"],
            rate={"tool:github:*": "10/hour"},
        )
        claims = inspect_token(env["ATI_SESSION_TOKEN"])
        assert claims.ati is not None
        assert claims.ati.rate == {"tool:github:*": "10/hour"}

    def test_provision_with_extra_scopes(self):
        env = self.orch.provision_sandbox(
            agent_id="agent-2",
            tools=["web_search"],
            extra_scopes=["help"],
        )
        claims = inspect_token(env["ATI_SESSION_TOKEN"])
        assert "help" in claims.scopes()
        assert "tool:web_search" in claims.scopes()

    def test_provision_strips_trailing_slash(self):
        orch = AtiOrchestrator(
            proxy_url="https://ati-proxy.example.com/",
            secret=TEST_SECRET,
        )
        env = orch.provision_sandbox(agent_id="test", tools=["x"])
        assert env["ATI_PROXY_URL"] == "https://ati-proxy.example.com"

    def test_custom_aud_and_iss(self):
        orch = AtiOrchestrator(
            proxy_url="https://proxy.test",
            secret=TEST_SECRET,
            default_aud="custom-aud",
            default_iss="custom-iss",
        )
        env = orch.provision_sandbox(agent_id="test", tools=["x"])
        claims = validate_token(
            env["ATI_SESSION_TOKEN"],
            secret=TEST_SECRET,
            audience="custom-aud",
        )
        assert claims.aud == "custom-aud"
        assert claims.iss == "custom-iss"

    def test_validate_own_token(self):
        env = self.orch.provision_sandbox(
            agent_id="validate-me", tools=["web_search"]
        )
        claims = self.orch.validate_token(env["ATI_SESSION_TOKEN"])
        assert claims.sub == "validate-me"

    def test_provision_empty_tools(self):
        env = self.orch.provision_sandbox(agent_id="empty")
        claims = inspect_token(env["ATI_SESSION_TOKEN"])
        assert claims.scope == ""


# --- build_skill_listing / listing formatter regression tests (0.7.5+) ---


def _fake_urlopen(payload_bytes: bytes):
    """Return a mock context-manager that `urllib.request.urlopen` can
    accept. Captures the Request passed in via a side-effect list so
    tests can assert URL + headers."""
    captured: list = []

    class _FakeResp:
        def __init__(self, data):
            self._data = data

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def read(self):
            return self._data

    def _urlopen(req, timeout=None):
        captured.append((req, timeout))
        return _FakeResp(payload_bytes)

    return captured, _urlopen


class TestBuildSkillListing:
    def setup_method(self):
        self.orch = AtiOrchestrator(
            proxy_url="https://ati-proxy.example.com",
            secret=TEST_SECRET,
        )

    def test_fetches_from_proxy_with_bearer_token(self):
        payload = json.dumps(
            {
                "skills": [
                    {
                        "name": "slidedeck-production",
                        "description": "Create animation-rich HTML slides",
                    },
                    {
                        "name": "html-app-architecture",
                        "description": "Build self-contained HTML apps",
                        "when_to_use": "use when asked for an HTML artifact",
                    },
                ]
            }
        ).encode()

        captured, urlopen = _fake_urlopen(payload)
        with patch("urllib.request.urlopen", urlopen):
            listing = self.orch.build_skill_listing(token="tok-abc")

        assert "<system-reminder>" in listing
        assert "</system-reminder>" in listing
        assert "slidedeck-production: Create animation-rich HTML slides" in listing
        assert (
            "html-app-architecture: Build self-contained HTML apps - "
            "use when asked for an HTML artifact"
        ) in listing

        assert len(captured) == 1
        req, _timeout = captured[0]
        assert req.full_url == "https://ati-proxy.example.com/skillati/catalog"
        assert req.get_header("Authorization") == "Bearer tok-abc"

    def test_forwards_search_query_param(self):
        captured, urlopen = _fake_urlopen(b'{"skills": []}')
        with patch("urllib.request.urlopen", urlopen):
            self.orch.build_skill_listing(token="tok", search="html")

        req, _ = captured[0]
        assert req.full_url == (
            "https://ati-proxy.example.com/skillati/catalog?search=html"
        )

    def test_respects_total_budget_across_many_skills(self):
        # 400 skills * ~80 chars each > 8000 char budget, forces pass-2
        # (names only) or pass-3 (truncated) fallback.
        many = [
            {
                "name": f"skill-{i:03}",
                "description": "A description that pushes us past the per-entry cap " * 3,
            }
            for i in range(400)
        ]
        payload = json.dumps({"skills": many}).encode()
        captured, urlopen = _fake_urlopen(payload)
        with patch("urllib.request.urlopen", urlopen):
            listing = self.orch.build_skill_listing(token="tok")
        assert len(listing) <= 8000, f"listing {len(listing)} chars exceeds 8000 budget"
        assert "<system-reminder>" in listing

    def test_truncates_per_entry_over_250_chars(self):
        long_desc = "x" * 2000
        payload = json.dumps(
            {
                "skills": [
                    {
                        "name": "bloated-skill",
                        "description": long_desc,
                    }
                ]
            }
        ).encode()
        _, urlopen = _fake_urlopen(payload)
        with patch("urllib.request.urlopen", urlopen):
            listing = self.orch.build_skill_listing(token="tok")
        # Find the skill's bullet line. The per-entry budget is 250 chars
        # including the leading "- " and the trailing ellipsis.
        for line in listing.splitlines():
            if line.startswith("- bloated-skill"):
                assert len(line) <= 250, f"entry line is {len(line)} chars: {line}"
                assert line.endswith("\u2026"), "truncated line should end with ellipsis"
                return
        raise AssertionError(f"bloated-skill line not found in listing:\n{listing}")

    def test_empty_catalog_returns_empty_string(self):
        _, urlopen = _fake_urlopen(b'{"skills": []}')
        with patch("urllib.request.urlopen", urlopen):
            listing = self.orch.build_skill_listing(token="tok")
        assert listing == ""

    def test_legacy_build_skill_instructions_still_works_with_warning(self):
        with warnings.catch_warnings(record=True) as captured_warnings:
            warnings.simplefilter("always")
            out = build_skill_instructions(["foo", "bar"])

        assert any(
            issubclass(w.category, DeprecationWarning) for w in captured_warnings
        ), "build_skill_instructions should emit a DeprecationWarning"
        # Legacy format preserved.
        assert "# Available Skills" in out
        assert "- **foo**: `ati skill fetch read foo`" in out
        assert "- **bar**: `ati skill fetch read bar`" in out
