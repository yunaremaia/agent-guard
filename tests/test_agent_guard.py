"""Tests for agent-guard."""

from __future__ import annotations

import pytest
import asyncio

from agent_guard import Action, Guard, GuardStats, Policy, RiskLevel, Rule, ToolCall


SAMPLE_POLICY = """
name: test-agent
description: Test policy
default_action: deny
max_tool_calls: 50
blocked_tools:
  - destructive_*
rules:
  - action: allow
    tool: fs.read
    resource: "./**/*"
    description: Allow reading project files

  - action: allow
    tool: shell
    resource: "ls *"
    description: Allow listing

  - action: deny
    tool: fs.write
    resource: "/etc/*"
    description: Never write to system

  - action: allow
    tool: http
    resource: "https://api.github.com/*"
    description: Allow GitHub API
"""


@pytest.fixture
def policy() -> Policy:
    return Policy.from_yaml(SAMPLE_POLICY)


@pytest.fixture
def guard(policy: Policy) -> Guard:
    return Guard(policy)


class TestPolicyParsing:
    def test_parse_basic(self):
        p = Policy.from_yaml(SAMPLE_POLICY)
        assert p.name == "test-agent"
        assert p.default_action == Action.DENY
        assert len(p.rules) == 4

    def test_parse_max_tool_calls(self):
        p = Policy.from_yaml(SAMPLE_POLICY)
        assert p.max_tool_calls == 50

    def test_parse_blocked_tools(self):
        p = Policy.from_yaml(SAMPLE_POLICY)
        assert "destructive_*" in p.blocked_tools


class TestAllowRules:
    def test_allow_fs_read(self, guard: Guard):
        call = ToolCall(tool="fs.read", resource="./src/main.py")
        v = guard.check(call)
        assert v.allowed is True
        assert v.risk.value == "low"

    def test_allow_shell_ls(self, guard: Guard):
        call = ToolCall(tool="shell", resource="ls -la")
        v = guard.check(call)
        assert v.allowed is True

    def test_allow_github_api(self, guard: Guard):
        call = ToolCall(tool="http", resource="https://api.github.com/repos/foo")
        v = guard.check(call)
        assert v.allowed is True


class TestDenyRules:
    def test_deny_write_etc(self, guard: Guard):
        call = ToolCall(tool="fs.write", resource="/etc/passwd")
        v = guard.check(call)
        assert v.allowed is False
        assert "system" in v.reason.lower() or "denied" in v.reason.lower()

    def test_deny_unknown_default(self, guard: Guard):
        call = ToolCall(tool="shell", resource="cat secret.txt")
        v = guard.check(call)
        assert v.allowed is False
        assert "default deny" in v.reason


class TestBlockedTools:
    def test_blocked_tool(self, guard: Guard):
        call = ToolCall(tool="destructive_delete", resource="foo")
        v = guard.check(call)
        assert v.allowed is False
        assert "blocked" in v.reason

    def test_blocked_tool_wildcard(self, guard: Guard):
        call = ToolCall(tool="admin_root", resource="bar")
        v = guard.check(call)
        assert v.allowed is False


class TestLimits:
    def test_max_tool_calls(self):
        p = Policy.from_yaml("""
name: limited
default_action: allow
max_tool_calls: 3
rules: []
""")
        g = Guard(p)
        assert g.check(ToolCall(tool="x", resource="a")).allowed is True
        assert g.check(ToolCall(tool="x", resource="b")).allowed is True
        assert g.check(ToolCall(tool="x", resource="c")).allowed is True
        v = g.check(ToolCall(tool="x", resource="d"))
        assert v.allowed is False
        assert "max_tool_calls" in v.reason


class TestDomains:
    def test_blocked_domain(self):
        p = Policy.from_yaml("""
name: net
default_action: allow
blocked_domains:
  - "*.evil.com"
rules: []
""")
        g = Guard(p)
        v = g.check(ToolCall(tool="browser", resource="https://api.evil.com/steal"))
        assert v.allowed is False
        assert "blocked" in v.reason

    def test_allowed_domain_only(self):
        p = Policy.from_yaml("""
name: net
default_action: allow
allowed_domains:
  - "*.github.com"
  - "*.stackoverflow.com"
rules: []
""")
        g = Guard(p)
        v = g.check(ToolCall(tool="browser", resource="https://evil.com"))
        assert v.allowed is False
        assert "not in allowlist" in v.reason

    def test_allowed_domain_permitted(self):
        p = Policy.from_yaml("""
name: net
default_action: allow
allowed_domains:
  - "*.github.com"
rules: []
""")
        g = Guard(p)
        v = g.check(ToolCall(tool="browser", resource="https://api.github.com/repos"))
        assert v.allowed is True


class TestRuleMatching:
    def test_wildcard_tool(self):
        p = Policy.from_yaml("""
name: wild
default_action: deny
rules:
  - action: allow
    tool: "fs.*"
    resource: "*"
""")
        g = Guard(p)
        assert g.check(ToolCall(tool="fs.read", resource="x")).allowed is True
        assert g.check(ToolCall(tool="fs.write", resource="y")).allowed is True
        assert g.check(ToolCall(tool="shell", resource="z")).allowed is False

    def test_wildcard_resource(self):
        p = Policy.from_yaml("""
name: wild
default_action: deny
rules:
  - action: allow
    tool: "shell"
    resource: "*"
""")
        g = Guard(p)
        assert g.check(ToolCall(tool="shell", resource="anything goes")).allowed is True


class TestVerdictRisk:
    def test_default_allow_risk(self):
        p = Policy.from_yaml("""
name: perm
default_action: allow
rules: []
""")
        g = Guard(p)
        v = g.check(ToolCall(tool="x", resource="y"))
        assert v.allowed is True
        assert v.risk == RiskLevel.MEDIUM  # medium because no rule matched

    def test_rule_match_risk(self, guard: Guard):
        call = ToolCall(tool="fs.read", resource="./src/main.py")
        v = guard.check(call)
        assert v.risk == RiskLevel.LOW


class TestResourceNoneHandling:
    def test_resource_none_matches_rule(self):
        p = Policy.from_yaml("""
name: test-none
default_action: deny
rules:
  - action: allow
    tool: "get_status"
    resource: "*"
""")
        g = Guard(p)
        call = ToolCall(tool="get_status", resource=None)
        v = g.check(call)
        assert v.allowed is True
        assert v.rule is not None

    def test_resource_none_denied_when_no_tool_rule(self):
        p = Policy.from_yaml("""
name: test-none-deny
default_action: deny
rules:
  - action: allow
    tool: "fs.read"
    resource: "*"
""")
        g = Guard(p)
        call = ToolCall(tool="other_tool", resource=None)
        v = g.check(call)
        assert v.allowed is False
        assert "default deny" in v.reason

    def test_resource_empty_string(self):
        p = Policy.from_yaml("""
name: test-empty
default_action: deny
rules:
  - action: allow
    tool: "ping"
    resource: "*"
""")
        g = Guard(p)
        call = ToolCall(tool="ping", resource="")
        v = g.check(call)
        assert v.allowed is True

    def test_network_check_with_none_resource(self):
        p = Policy.from_yaml("""
name: test-net-none
default_action: allow
rules: []
""")
        g = Guard(p)
        call = ToolCall(tool="http", resource=None)
        v = g.check(call)
        assert v.allowed is True

class TestAsyncGuard:
    @pytest.mark.asyncio
    async def test_check_async(self, guard: Guard):
        call = ToolCall(tool="fs.read", resource="./src/main.py")
        v = await guard.check_async(call)
        assert v.allowed is True

    @pytest.mark.asyncio
    async def test_check_batch_async(self, guard: Guard):
        calls = [
            ToolCall(tool="fs.read", resource="./src/main.py"),
            ToolCall(tool="shell", resource="ls -la"),
            ToolCall(tool="fs.write", resource="/etc/passwd"),
        ]
        verdicts = await guard.check_batch_async(calls)
        assert verdicts[0].allowed is True
        assert verdicts[1].allowed is True
        assert verdicts[2].allowed is False
    @pytest.mark.asyncio
    async def test_guard_concurrent_checks(self):
        policy = Policy.from_yaml("""
name: concurrent-agent
default_action: deny
rules:
  - action: allow
    tool: fs.read
    resource: "./**/*"
""")
        guard = Guard(policy)
        calls = [
            ToolCall(tool="fs.read", resource="./src/main.py")
            for _ in range(100)
        ]

        verdicts = await asyncio.gather(
            *(guard.check_async(call) for call in calls)
        )

        assert len(verdicts) == 100
        assert all(v.allowed is True for v in verdicts)

    @pytest.mark.asyncio
    async def test_from_file_async(self, tmp_path: Path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(SAMPLE_POLICY)

        policy = await Policy.from_file_async(policy_file)

        assert policy.name == "test-agent"
        assert policy.default_action == Action.DENY


class TestGuardLifecycleAndStats:
    """Tests for Guard.reset() and Guard.stats()."""

    def test_reset_zeroes_counters(self, guard: Guard):
        # Manually alter counters
        guard.execution_count = 5
        guard.tool_call_count = 10

        returned = guard.reset()
        assert returned is guard  # Returns self for chaining
        assert guard.execution_count == 0
        assert guard.tool_call_count == 0

    def test_stats_reflects_current_state(self):
        policy = Policy.from_yaml("""
name: stats-agent
default_action: allow
max_tool_calls: 15
max_executions: 3
rules: []
""")
        guard = Guard(policy)
        guard.execution_count = 2
        guard.check(ToolCall(tool="fs.read", resource="./file.txt"))
        guard.check(ToolCall(tool="fs.read", resource="./file2.txt"))

        stats = guard.stats()
        assert isinstance(stats, GuardStats)
        assert stats.execution_count == 2
        assert stats.tool_call_count == 2
        assert stats.max_tool_calls == 15
        assert stats.max_executions == 3

        # Test dictionary-like access
        assert stats["execution_count"] == 2
        assert stats["tool_call_count"] == 2
        assert stats.get("max_tool_calls") == 15
        assert stats.to_dict() == {
            "execution_count": 2,
            "tool_call_count": 2,
            "max_tool_calls": 15,
            "max_executions": 3,
        }

    def test_reset_restores_initial_behavior_after_check(self):
        policy = Policy.from_yaml("""
name: limit-test
default_action: allow
max_tool_calls: 2
rules: []
""")
        guard = Guard(policy)
        assert guard.check(ToolCall(tool="cmd", resource="1")).allowed is True
        assert guard.check(ToolCall(tool="cmd", resource="2")).allowed is True

        # Third call exceeds max_tool_calls
        exceeded = guard.check(ToolCall(tool="cmd", resource="3"))
        assert exceeded.allowed is False
        assert "max_tool_calls exceeded" in exceeded.reason
        assert guard.stats().tool_call_count == 3

        # Reset zeroes tool_call_count and restores initial behavior
        guard.reset()
        assert guard.stats().tool_call_count == 0
        v1 = guard.check(ToolCall(tool="cmd", resource="1"))
        assert v1.allowed is True
        assert guard.stats().tool_call_count == 1

    def test_reset_chaining(self):
        policy = Policy(name="chain", description="chain test", default_action=Action.ALLOW)
        guard = Guard(policy)
        guard.tool_call_count = 99
        v = guard.reset().check(ToolCall(tool="ping", resource="localhost"))
        assert v.allowed is True
        assert guard.tool_call_count == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
