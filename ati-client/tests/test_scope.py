"""Tests for ati.scope — scope parsing and wildcard matching."""

from ati import build_scope_string, check_scope, matches_wildcard, parse_scopes


class TestParseScopes:
    def test_basic(self):
        assert parse_scopes("tool:a tool:b") == ["tool:a", "tool:b"]

    def test_empty(self):
        assert parse_scopes("") == []

    def test_single(self):
        assert parse_scopes("tool:web_search") == ["tool:web_search"]

    def test_mixed(self):
        assert parse_scopes("tool:a skill:b help") == ["tool:a", "skill:b", "help"]


class TestMatchesWildcard:
    def test_exact_match(self):
        assert matches_wildcard("tool:web_search", "tool:web_search")

    def test_no_match(self):
        assert not matches_wildcard("tool:web_search", "tool:github__search")

    def test_global_wildcard(self):
        assert matches_wildcard("tool:anything", "*")

    def test_prefix_wildcard(self):
        assert matches_wildcard("tool:github__search_repos", "tool:github__*")
        assert matches_wildcard("tool:github__create_issue", "tool:github__*")

    def test_prefix_wildcard_no_match(self):
        assert not matches_wildcard("tool:linear__list", "tool:github__*")

    def test_wildcard_not_at_end(self):
        # Only trailing * is supported
        assert not matches_wildcard("tool:abc", "tool:*bc")

    def test_empty_pattern(self):
        assert not matches_wildcard("tool:x", "")

    def test_empty_name(self):
        assert not matches_wildcard("", "tool:x")
        assert matches_wildcard("", "*")


class TestBuildScopeString:
    def test_tools_only(self):
        result = build_scope_string(tools=["web_search", "github__*"])
        assert result == "tool:web_search tool:github__*"

    def test_skills_only(self):
        result = build_scope_string(skills=["research-*"])
        assert result == "skill:research-*"

    def test_mixed(self):
        result = build_scope_string(
            tools=["web_search"], skills=["analysis"], extra=["help"]
        )
        assert result == "tool:web_search skill:analysis help"

    def test_empty(self):
        assert build_scope_string() == ""

    def test_no_double_prefix(self):
        # If already prefixed, don't double-prefix
        result = build_scope_string(tools=["tool:web_search"])
        assert result == "tool:web_search"

    def test_skill_no_double_prefix(self):
        result = build_scope_string(skills=["skill:my-skill"])
        assert result == "skill:my-skill"


class TestCheckScope:
    def test_exact_grant(self):
        assert check_scope("tool:web_search", ["tool:web_search", "tool:other"])

    def test_wildcard_grant(self):
        assert check_scope("tool:github__search", ["tool:github__*"])

    def test_global_grant(self):
        assert check_scope("tool:anything", ["*"])

    def test_no_grant(self):
        assert not check_scope("tool:secret", ["tool:web_search"])

    def test_empty_granted(self):
        assert not check_scope("tool:x", [])
