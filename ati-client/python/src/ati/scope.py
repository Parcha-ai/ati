"""Scope parsing and matching — compatible with ATI Rust proxy."""

from __future__ import annotations


def parse_scopes(scope_str: str) -> list[str]:
    """Parse a space-delimited scope string into individual scopes."""
    return scope_str.split() if scope_str else []


def matches_wildcard(name: str, pattern: str) -> bool:
    """Check if *name* matches *pattern* using ATI wildcard rules.

    Rules (from core/scope.rs):
      - ``"*"`` matches everything
      - exact string match
      - pattern ending with ``*`` is a prefix match
    """
    if pattern == "*":
        return True
    if pattern == name:
        return True
    if pattern.endswith("*") and name.startswith(pattern[:-1]):
        return True
    return False


def build_scope_string(
    *,
    tools: list[str] | None = None,
    skills: list[str] | None = None,
    extra: list[str] | None = None,
) -> str:
    """Build a space-delimited scope string from typed lists.

    >>> build_scope_string(tools=["web_search", "github:*"], skills=["research-*"])
    'tool:web_search tool:github:* skill:research-*'
    """
    parts: list[str] = []
    for t in tools or []:
        parts.append(f"tool:{t}" if not t.startswith("tool:") else t)
    for s in skills or []:
        parts.append(f"skill:{s}" if not s.startswith("skill:") else s)
    parts.extend(extra or [])
    return " ".join(parts)


def check_scope(required: str, granted: list[str]) -> bool:
    """Return True if *required* scope is covered by any pattern in *granted*."""
    return any(matches_wildcard(required, g) for g in granted)
