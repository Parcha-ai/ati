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
    "build_skill_instructions",
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


def build_skill_instructions(skills: list[str]) -> str:
    """Deprecated: use ``AtiOrchestrator.build_skill_listing`` instead.

    Emits a DeprecationWarning and delegates to the legacy generator.
    The new canonical path fetches a scope-filtered catalog from the
    proxy and formats it as a Claude-Code-shaped ``<system-reminder>``
    block with per-entry and total-budget truncation, matching
    ``~/cc/src/utils/attachments.ts::getSkillListingAttachments``.

    Args:
        skills: List of skill names.

    Returns:
        Legacy instruction string for the agent.
    """
    import warnings

    warnings.warn(
        "ati.build_skill_instructions is deprecated and will be removed in a "
        "future release; use AtiOrchestrator.build_skill_listing(token=...) "
        "to get a Claude-Code-shaped <system-reminder> block populated from "
        "the proxy's scope-filtered catalog.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _build_skill_instructions_legacy(skills)


def _build_skill_instructions_legacy(skills: list[str]) -> str:
    """Pre-0.7.5 listing format — kept so existing callsites don't break."""
    if not skills:
        return ""

    lines = [
        "# Available Skills",
        "",
        "The following skills contain methodology and detailed guidance for this task.",
        "Read the relevant skill(s) before using the associated tools.",
        "",
    ]
    for skill in skills:
        lines.append(f"- **{skill}**: `ati skill fetch read {skill}`")
    lines.append("")
    lines.append(
        "Use `ati skill fetch read <name>` to fetch and read a skill's full methodology. "
        "Skills contain tool-specific workflows, parameter guidance, and best practices."
    )
    return "\n".join(lines)


# --- Claude-Code-shaped skill listing (0.7.5+) -----------------------------

# Per-entry character budget for a single skill line in the listing.
# Matches `MAX_LISTING_DESC_CHARS` in
# `~/cc/src/tools/SkillTool/prompt.ts:29`.
_MAX_LISTING_DESC_CHARS = 250

# Total budget for the whole <system-reminder> block. Matches Claude
# Code's default at `~/cc/src/tools/SkillTool/prompt.ts:31-41`.
_MAX_LISTING_BLOCK_CHARS = 8000


def _truncate_with_ellipsis(text: str, max_chars: int) -> str:
    """Clip `text` to at most `max_chars` characters, adding a trailing
    ellipsis glyph when we actually removed content. Matches the
    single-character ellipsis (`\u2026`) Claude Code uses in its listing
    truncation path so downstream byte comparisons match."""
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    if max_chars <= 1:
        return "\u2026"
    return text[: max_chars - 1].rstrip() + "\u2026"


def _format_skill_listing(entries: list[dict]) -> str:
    """Render a list of remote skill metadata dicts as a
    ``<system-reminder>`` block mirroring Claude Code's
    ``getSkillListingAttachments`` output
    (``~/cc/src/utils/attachments.ts:2661``).

    Each entry is a dict with at least ``name`` and ``description``;
    ``when_to_use`` is optional. Non-dict entries (plain strings) are
    coerced to ``{"name": <string>, "description": ""}`` for
    backwards compatibility with the legacy call shape.

    Layout:

    ```
    <system-reminder>
    The following skills are available. To load one, run
    `ati skill fetch read <name>` via the Bash tool — the skill's body will
    be returned. Follow the skill's instructions literally. Files referenced
    inside a skill body live at `skillati://<name>/<path>` — fetch them via
    `ati skill fetch cat <name> <path>`.

    - skill-name: description - when_to_use
    - other-skill: description
    </system-reminder>
    ```

    Under extreme budget pressure the function falls back to
    name-only entries (``- skill-name``), matching
    ``~/cc/src/tools/SkillTool/prompt.ts:125-142``.
    """
    if not entries:
        return ""

    header = (
        "<system-reminder>\n"
        "The following skills are available. To load one, run "
        "`ati skill fetch read <name>` via the Bash tool — the skill's body "
        "will be returned. Follow the skill's instructions literally. Files "
        "referenced inside a skill body live at `skillati://<name>/<path>` — "
        "fetch them via `ati skill fetch cat <name> <path>`.\n\n"
    )
    footer = "\n</system-reminder>"
    overhead = len(header) + len(footer)
    budget = max(0, _MAX_LISTING_BLOCK_CHARS - overhead)

    def _normalize(entry) -> tuple[str, str, str | None]:
        if isinstance(entry, dict):
            name = str(entry.get("name", "")).strip()
            description = str(entry.get("description", "")).strip()
            when_to_use_raw = entry.get("when_to_use")
            when_to_use = (
                str(when_to_use_raw).strip()
                if when_to_use_raw is not None
                else None
            )
            return name, description, when_to_use
        # Legacy list[str] path — coerce to a bare name.
        return str(entry).strip(), "", None

    # Pass 1 — render with descriptions, truncate per-entry.
    rich_lines: list[str] = []
    for entry in entries:
        name, description, when_to_use = _normalize(entry)
        if not name:
            continue
        suffix = description
        if when_to_use:
            suffix = f"{description} - {when_to_use}" if description else when_to_use
        line = f"- {name}: {suffix}" if suffix else f"- {name}"
        rich_lines.append(_truncate_with_ellipsis(line, _MAX_LISTING_DESC_CHARS))

    if not rich_lines:
        return ""

    body = "\n".join(rich_lines)
    if len(body) <= budget:
        return header + body + footer

    # Pass 2 — names only, same budget check.
    name_lines: list[str] = []
    for entry in entries:
        name, _, _ = _normalize(entry)
        if name:
            name_lines.append(f"- {name}")
    body = "\n".join(name_lines)
    if len(body) <= budget:
        return header + body + footer

    # Pass 3 — hard cap: take as many names as fit, append a "+N more"
    # footer so the agent knows something was dropped.
    truncated: list[str] = []
    running = 0
    more_note_template = "\n- ... (+{count} more — run `ati skill fetch catalog` to list all)"
    more_note_reserve = len(more_note_template.format(count=99999))
    for line in name_lines:
        needed = running + len(line) + (1 if truncated else 0)
        if needed > budget - more_note_reserve:
            break
        if truncated:
            running += 1
        running += len(line)
        truncated.append(line)

    remaining = len(name_lines) - len(truncated)
    body = "\n".join(truncated)
    if remaining > 0:
        body += more_note_template.format(count=remaining)
    return header + body + footer


__version__ = "0.7.5"


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
        fetch_skill_content: bool = False,
    ) -> dict[str, str | dict[str, str]]:
        """Generate env vars to inject into a sandboxed agent.

        Args:
            agent_id: Unique identifier for this sandbox/agent (becomes JWT ``sub``).
            tools: Tool names to grant access to (e.g. ``["web_search", "github:*"]``).
            skills: Skill names to grant (e.g. ``["financial-analysis"]``).
            extra_scopes: Additional raw scope strings (e.g. ``["help"]``).
            ttl_seconds: Token lifetime (default 3600).
            rate: Per-tool rate limits (e.g. ``{"tool:github:*": "10/hour"}``).
            fetch_skill_content: If True, resolve skills from proxy and include
                SKILL.md content in the returned dict under a ``"skills"`` key.

        Returns:
            Dict with ``ATI_PROXY_URL`` and ``ATI_SESSION_TOKEN``.
            If ``fetch_skill_content=True``, also includes ``"skills"``
            mapping skill names to their SKILL.md content.
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

        result: dict[str, str | dict[str, str]] = {
            "ATI_PROXY_URL": self.proxy_url,
            "ATI_SESSION_TOKEN": token,
        }

        if fetch_skill_content:
            skill_scopes: list[str] = []
            for t in tools or []:
                skill_scopes.append(f"tool:{t}" if not t.startswith("tool:") else t)
            for s in skills or []:
                skill_scopes.append(f"skill:{s}" if not s.startswith("skill:") else s)
            try:
                result["skills"] = self.fetch_skills(
                    scopes=skill_scopes or ["*"],
                    token=token,
                )
            except Exception:
                result["skills"] = {}

        return result

    def fetch_skills(
        self,
        *,
        scopes: list[str] | None = None,
        token: str | None = None,
    ) -> dict[str, str]:
        """Fetch resolved skill content from the proxy.

        Calls ``POST /skills/resolve`` with ``include_content=true`` and
        returns a dict mapping skill name to SKILL.md content.

        Args:
            scopes: Scope strings to resolve (default ``["*"]``).
            token: JWT Bearer token for authentication.

        Returns:
            Dict mapping skill name to SKILL.md content string.
        """
        import json
        import urllib.request

        url = f"{self.proxy_url}/skills/resolve"
        body = json.dumps({
            "scopes": scopes or ["*"],
            "include_content": True,
        }).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        return {s["name"]: s.get("content", "") for s in data if "name" in s}

    def download_skill(
        self,
        name: str,
        dest_dir: str,
        *,
        token: str | None = None,
    ) -> str:
        """Download a full skill directory from the proxy and write it to disk.

        Fetches ``GET /skills/{name}/bundle`` and writes all files
        (SKILL.md, skill.toml, scripts/\\*, references/\\*, etc.) to
        ``{dest_dir}/{name}/``.

        Args:
            name: Skill name.
            dest_dir: Parent directory (e.g. ``.claude/skills``).
            token: JWT Bearer token for authentication.

        Returns:
            Path to the created skill directory.
        """
        import base64
        import json
        import os
        import urllib.request

        url = f"{self.proxy_url}/skills/{name}/bundle"
        req = urllib.request.Request(url)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())

        skill_dir = os.path.realpath(os.path.join(dest_dir, name))
        for rel_path, content in data.get("files", {}).items():
            # Path traversal protection
            if ".." in rel_path or rel_path.startswith("/"):
                continue
            file_path = os.path.realpath(os.path.join(skill_dir, rel_path))
            if not file_path.startswith(skill_dir + os.sep) and file_path != skill_dir:
                continue
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            if isinstance(content, dict) and "base64" in content:
                # Binary file
                with open(file_path, "wb") as f:
                    f.write(base64.b64decode(content["base64"]))
            else:
                # Text file
                with open(file_path, "w") as f:
                    f.write(content)
        return skill_dir

    def download_skills(
        self,
        names: list[str],
        dest_dir: str,
        *,
        token: str | None = None,
    ) -> dict[str, str]:
        """Download multiple skill directories from the proxy in one request.

        Uses ``POST /skills/bundle`` to fetch all skills in a single
        HTTP call, then writes each skill's directory tree to disk.

        Args:
            names: List of skill names.
            dest_dir: Parent directory (e.g. ``.claude/skills``).
            token: JWT Bearer token for authentication.

        Returns:
            Dict mapping skill name to the created directory path.
        """
        import base64
        import json
        import os
        import urllib.request

        url = f"{self.proxy_url}/skills/bundle"
        body = json.dumps({"names": names}).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())

        result = {}
        for name, skill_data in data.get("skills", {}).items():
            skill_dir = os.path.realpath(os.path.join(dest_dir, name))
            for rel_path, content in skill_data.get("files", {}).items():
                if ".." in rel_path or rel_path.startswith("/"):
                    continue
                file_path = os.path.realpath(os.path.join(skill_dir, rel_path))
                if not file_path.startswith(skill_dir + os.sep) and file_path != skill_dir:
                    continue
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                if isinstance(content, dict) and "base64" in content:
                    with open(file_path, "wb") as f:
                        f.write(base64.b64decode(content["base64"]))
                else:
                    with open(file_path, "w") as f:
                        f.write(content)
            result[name] = skill_dir

        missing = data.get("missing", [])
        if missing:
            import warnings
            warnings.warn(f"Skills not found on server: {missing}", stacklevel=2)

        return result

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

    def build_tool_instructions(
        self,
        *,
        tools: list[str],
        token: str | None = None,
    ) -> str:
        """Build agent instructions for reading skills before using tools.

        Queries the proxy for each tool's skill declarations and generates
        instructions telling the agent which skills to read before using
        the tools.

        Args:
            tools: List of tool names (e.g. ``["finnhub:quote", "web_search"]``).
            token: JWT Bearer token for authentication.

        Returns:
            Instruction string for the agent, or empty string if no skills found.
        """
        import json
        import urllib.parse
        import urllib.request

        skills_by_provider: dict[str, list[str]] = {}
        seen_skills: set[str] = set()

        for tool_name in tools:
            url = f"{self.proxy_url}/tools/{urllib.parse.quote(tool_name, safe='')}"
            req = urllib.request.Request(url)
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                tool_skills = data.get("skills", [])
                if tool_skills:
                    provider = data.get("provider", tool_name)
                    for skill in tool_skills:
                        if skill not in seen_skills:
                            seen_skills.add(skill)
                            skills_by_provider.setdefault(provider, []).append(skill)
            except Exception:
                continue

        if not skills_by_provider:
            return ""

        lines = []
        for provider, skill_names in skills_by_provider.items():
            if len(skill_names) == 1:
                lines.append(
                    f"Before using {provider} tools, read the methodology:\n"
                    f"  ati skill fetch read {skill_names[0]}"
                )
            else:
                lines.append(f"Before using {provider} tools, read the relevant skill:")
                for skill in skill_names:
                    lines.append(f"  ati skill fetch read {skill}")

        return "\n".join(lines)

    @staticmethod
    def build_skill_instructions(
        skills: list[str],
    ) -> str:
        """Deprecated: use :meth:`build_skill_listing` instead.

        Emits a ``DeprecationWarning`` and delegates to the legacy
        generator. The new path fetches a scope-filtered catalog from
        the proxy and emits a Claude-Code-shaped ``<system-reminder>``
        listing block, matching
        ``~/cc/src/utils/attachments.ts::getSkillListingAttachments``.
        """
        import warnings

        warnings.warn(
            "AtiOrchestrator.build_skill_instructions is deprecated and "
            "will be removed in a future release; use "
            "AtiOrchestrator.build_skill_listing(token=...) to get a "
            "Claude-Code-shaped <system-reminder> block populated from "
            "the proxy's scope-filtered catalog.",
            DeprecationWarning,
            stacklevel=2,
        )
        return _build_skill_instructions_legacy(skills)

    def build_skill_listing(
        self,
        *,
        token: str,
        search: str | None = None,
    ) -> str:
        """Fetch the scope-filtered skill catalog from the proxy and
        render it as a Claude-Code-shaped ``<system-reminder>`` block
        suitable for direct injection into an agent's system prompt.

        Mirrors Claude Code's
        ``getSkillListingAttachments`` +
        ``formatCommandsWithinBudget`` pipeline
        (``~/cc/src/utils/attachments.ts:2661`` +
        ``~/cc/src/tools/SkillTool/prompt.ts:70``), pointed at the
        ``ati skill fetch read`` CLI entry point instead of Claude Code's
        ``Skill`` tool. Scope filtering happens server-side — the
        listing you get back contains exactly the skills the token's
        JWT scopes grant.

        Args:
            token: JWT Bearer token (e.g. the ``ATI_SESSION_TOKEN`` from
                :meth:`provision_sandbox`). The proxy's
                ``visible_skill_names_with_remote`` gate uses this to
                filter the catalog before returning it.
            search: Optional keyword query forwarded to
                ``GET /skillati/catalog?search=…``. When unset, the
                full scope-visible catalog is returned.

        Returns:
            A ``<system-reminder>``-wrapped listing string, or an empty
            string if no skills are visible.
        """
        import json
        import urllib.parse
        import urllib.request

        url = f"{self.proxy_url}/skillati/catalog"
        if search:
            url = f"{url}?{urllib.parse.urlencode({'search': search})}"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read())
        entries = payload.get("skills", []) if isinstance(payload, dict) else []
        return _format_skill_listing(entries)
