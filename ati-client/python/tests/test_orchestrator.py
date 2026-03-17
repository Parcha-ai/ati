"""Tests for AtiOrchestrator — end-to-end provisioning."""

from ati import AtiOrchestrator, inspect_token, validate_token

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
            tools=["github__*"],
            rate={"tool:github__*": "10/hour"},
        )
        claims = inspect_token(env["ATI_SESSION_TOKEN"])
        assert claims.ati is not None
        assert claims.ati.rate == {"tool:github__*": "10/hour"}

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
