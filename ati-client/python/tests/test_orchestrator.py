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

    def test_respects_body_budget_across_many_skills(self):
        """CC's 8000-char budget applies to the bullet-content body, not
        the wrapped output. The `<system-reminder>` envelope adds
        header/footer overhead on top. 400 skills * ~80 chars forces
        the pass-2/pass-3 cascade; the body (excluding the wrap) must
        stay under 8000 chars — matching CC's
        ``formatCommandsWithinBudget`` which returns just the body
        string and lets ``wrapInSystemReminder`` add its own overhead
        later (``~/cc/src/utils/messages.ts:3098``)."""
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
        assert "<system-reminder>" in listing
        # Extract the body (everything between the preamble blank line
        # and the closing tag).
        preamble_end = listing.find("\n\n")
        closing = listing.find("\n</system-reminder>")
        assert preamble_end >= 0 and closing >= 0, f"malformed listing: {listing[:200]}"
        body = listing[preamble_end + 2 : closing]
        assert len(body) <= 8000, (
            f"body {len(body)} chars exceeds 8000 budget (total listing: "
            f"{len(listing)} chars)"
        )

    def test_truncates_description_at_250_chars_not_full_line(self):
        """CC's 250-char cap applies to the description portion only,
        not the whole bullet line. A skill with a 2000-char description
        should have its description clipped to 249 chars + `\\u2026`,
        then the `- name: ` prefix is added on top. Matches
        ``~/cc/src/tools/SkillTool/prompt.ts:43-50``
        (`getCommandDescription`)."""
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
        for line in listing.splitlines():
            if line.startswith("- bloated-skill"):
                # Description portion = the "x...x\u2026" after "- name: ".
                prefix = "- bloated-skill: "
                assert line.startswith(prefix)
                description_part = line[len(prefix):]
                assert len(description_part) == 250, (
                    f"description portion is {len(description_part)} chars, "
                    f"expected 250 (249 x's + 1 ellipsis): {description_part[:50]}..."
                )
                assert description_part.endswith("\u2026")
                # Make sure CC's rule applies: 249 content chars + 1 ellipsis.
                assert description_part[:-1] == "x" * 249
                return
        raise AssertionError(f"bloated-skill line not found in listing:\n{listing}")

    def test_long_skill_name_does_not_force_description_truncation(self):
        """A skill with a moderate description and a very long name
        should NOT have its description truncated — the 250-char cap
        applies to the description, not `- name: description` as a
        whole. This is the regression the previous test was hiding."""
        payload = json.dumps(
            {
                "skills": [
                    {
                        "name": "a" * 200,  # 200-char skill name
                        "description": "b" * 100,  # 100-char description
                    }
                ]
            }
        ).encode()
        _, urlopen = _fake_urlopen(payload)
        with patch("urllib.request.urlopen", urlopen):
            listing = self.orch.build_skill_listing(token="tok")
        # Description should be intact — no ellipsis anywhere in the body.
        for line in listing.splitlines():
            if line.startswith("- " + "a" * 10):
                assert "\u2026" not in line, (
                    f"description must not be truncated when the bullet's "
                    f"total length exceeds 250 chars due to a long name: {line}"
                )
                assert line.endswith("b" * 100)
                return
        raise AssertionError(f"skill line not found in listing:\n{listing}")

    def test_ellipsis_uses_single_codepoint_not_three_dots(self):
        """CC uses the U+2026 ellipsis codepoint (`\\u2026`), not three
        ASCII periods. Assert our truncation matches byte-for-byte."""
        long_desc = "z" * 500
        payload = json.dumps(
            {"skills": [{"name": "ellipsis-check", "description": long_desc}]}
        ).encode()
        _, urlopen = _fake_urlopen(payload)
        with patch("urllib.request.urlopen", urlopen):
            listing = self.orch.build_skill_listing(token="tok")
        for line in listing.splitlines():
            if line.startswith("- ellipsis-check:"):
                assert "..." not in line, (
                    f"three-dot ellipsis leaked into output: {line[:80]}"
                )
                assert line.endswith("\u2026")
                return
        raise AssertionError("ellipsis-check skill not found in listing")

    def test_middle_pass_truncates_descriptions_before_dropping_to_names(self):
        """When full descriptions don't fit but there's still room for
        moderately-sized per-description budgets (>=20 chars per entry),
        CC trims descriptions via the middle pass rather than dropping
        straight to names-only. Matches
        ``~/cc/src/tools/SkillTool/prompt.ts:117-170``."""
        # 100 skills * 150-char descriptions = 15000+ chars in full mode
        # (overflows 8000). Per-description budget after overhead should
        # still be well above MIN_DESC_LENGTH (20), so we expect Pass 2.
        skills = [
            {
                "name": f"skill-{i:03}",
                "description": "Detailed methodology for handling scenario " + ("x" * 100),
            }
            for i in range(100)
        ]
        payload = json.dumps({"skills": skills}).encode()
        _, urlopen = _fake_urlopen(payload)
        with patch("urllib.request.urlopen", urlopen):
            listing = self.orch.build_skill_listing(token="tok")

        # Pass 2 signature: every bullet still has a description (colon +
        # space + text), and at least one of them ends with the ellipsis
        # marker because it got trimmed.
        lines = [
            ln for ln in listing.splitlines() if ln.startswith("- skill-")
        ]
        assert len(lines) == 100, f"all 100 skills should be listed, got {len(lines)}"
        with_desc = [ln for ln in lines if ": " in ln]
        assert len(with_desc) == 100, (
            f"middle pass must preserve descriptions, got "
            f"{len(with_desc)} / 100 with descriptions"
        )
        truncated = [ln for ln in lines if ln.endswith("\u2026")]
        assert truncated, (
            "at least one description should be trimmed in the middle pass"
        )
        assert len(listing) <= 8000 + 500  # header+footer overhead

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
