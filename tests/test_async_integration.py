"""Integration tests for async policy enforcement (check_async / check_batch_async).

Requires pytest-asyncio.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_guard import (
    Action,
    Guard,
    Policy,
    PolicyDecision,
    PolicyViolation,
    RiskLevel,
    ToolCall,
    check_async,
    check_batch_async,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

ALLOW_READ_POLICY = """
name: async-test-agent
description: Policy for async integration tests
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
    return Policy.from_yaml(ALLOW_READ_POLICY)


# ---------------------------------------------------------------------------
# Module-level check_async
# ---------------------------------------------------------------------------


class TestCheckAsync:
    """Tests for the module-level check_async() function."""

    @pytest.mark.asyncio
    async def test_check_async_allowed(self, policy: Policy):
        decision = await check_async(policy, ToolCall(tool="fs.read", resource="./src/main.py"))
        assert isinstance(decision, PolicyDecision)
        assert decision.allowed is True
        assert decision.denied is False
        assert decision.risk == RiskLevel.LOW

    @pytest.mark.asyncio
    async def test_check_async_denied(self, policy: Policy):
        decision = await check_async(policy, ToolCall(tool="fs.write", resource="/etc/passwd"))
        assert decision.allowed is False
        assert decision.denied is True
        assert "denied" in decision.reason.lower() or "system" in decision.reason.lower()

    @pytest.mark.asyncio
    async def test_check_async_default_deny(self, policy: Policy):
        decision = await check_async(policy, ToolCall(tool="shell", resource="cat secret.txt"))
        assert decision.allowed is False
        assert "default deny" in decision.reason

    @pytest.mark.asyncio
    async def test_check_async_raises_on_deny(self, policy: Policy):
        with pytest.raises(PolicyViolation) as exc_info:
            await check_async(
                policy,
                ToolCall(tool="fs.write", resource="/etc/shadow"),
                raise_on_deny=True,
            )
        assert exc_info.value.decision.denied is True
        assert isinstance(exc_info.value.decision, PolicyDecision)

    @pytest.mark.asyncio
    async def test_check_async_no_raise_when_allowed(self, policy: Policy):
        # Should NOT raise even with raise_on_deny=True when the call is allowed
        decision = await check_async(
            policy,
            ToolCall(tool="fs.read", resource="./README.md"),
            raise_on_deny=True,
        )
        assert decision.allowed is True

    @pytest.mark.asyncio
    async def test_check_async_with_context(self, policy: Policy):
        """context is accepted but currently unused — must not break."""
        decision = await check_async(
            policy,
            ToolCall(tool="fs.read", resource="./file.py"),
            context={"user": "agent-1"},
        )
        assert decision.allowed is True

    @pytest.mark.asyncio
    async def test_check_async_blocked_tool(self, policy: Policy):
        decision = await check_async(
            policy,
            ToolCall(tool="destructive_delete", resource="anything"),
        )
        assert decision.allowed is False
        assert "blocked" in decision.reason


# ---------------------------------------------------------------------------
# Module-level check_batch_async
# ---------------------------------------------------------------------------


class TestCheckBatchAsync:
    """Tests for the module-level check_batch_async() function."""

    @pytest.mark.asyncio
    async def test_check_batch_async_mixed(self, policy: Policy):
        calls = [
            ToolCall(tool="fs.read", resource="./src/main.py"),
            ToolCall(tool="shell", resource="ls -la"),
            ToolCall(tool="fs.write", resource="/etc/passwd"),
        ]
        decisions = await check_batch_async(policy, calls)
        assert len(decisions) == 3
        assert decisions[0].allowed is True
        assert decisions[1].allowed is True
        assert decisions[2].allowed is False

    @pytest.mark.asyncio
    async def test_check_batch_async_all_allowed(self, policy: Policy):
        calls = [
            ToolCall(tool="fs.read", resource="./a.py"),
            ToolCall(tool="fs.read", resource="./b.py"),
        ]
        decisions = await check_batch_async(policy, calls)
        assert all(d.allowed for d in decisions)

    @pytest.mark.asyncio
    async def test_check_batch_async_raises_on_deny(self, policy: Policy):
        calls = [
            ToolCall(tool="fs.read", resource="./ok.py"),
            ToolCall(tool="fs.write", resource="/etc/shadow"),
        ]
        with pytest.raises(PolicyViolation):
            await check_batch_async(policy, calls, raise_on_deny=True)

    @pytest.mark.asyncio
    async def test_check_batch_async_empty_list(self, policy: Policy):
        decisions = await check_batch_async(policy, [])
        assert decisions == []


# ---------------------------------------------------------------------------
# Guard method async tests (existing methods, new integration coverage)
# ---------------------------------------------------------------------------


class TestGuardAsyncMethods:
    """Verify the Guard.check_async and Guard.check_batch_async methods."""

    @pytest.mark.asyncio
    async def test_guard_check_async_allowed(self, policy: Policy):
        guard = Guard(policy)
        verdict = await guard.check_async(ToolCall(tool="fs.read", resource="./x.py"))
        assert verdict.allowed is True

    @pytest.mark.asyncio
    async def test_guard_check_async_denied(self, policy: Policy):
        guard = Guard(policy)
        verdict = await guard.check_async(ToolCall(tool="fs.write", resource="/etc/passwd"))
        assert verdict.allowed is False

    @pytest.mark.asyncio
    async def test_guard_check_batch_async(self, policy: Policy):
        guard = Guard(policy)
        calls = [
            ToolCall(tool="fs.read", resource="./a.py"),
            ToolCall(tool="fs.write", resource="/etc/shadow"),
        ]
        verdicts = await guard.check_batch_async(calls)
        assert verdicts[0].allowed is True
        assert verdicts[1].allowed is False

    @pytest.mark.asyncio
    async def test_guard_concurrent_async_checks(self):
        policy = Policy.from_yaml("""
name: concurrent-test
default_action: deny
rules:
  - action: allow
    tool: fs.read
    resource: "./**/*"
""")
        guard = Guard(policy)
        calls = [ToolCall(tool="fs.read", resource="./src/main.py") for _ in range(100)]

        verdicts = await asyncio.gather(*(guard.check_async(c) for c in calls))
        assert len(verdicts) == 100
        assert all(v.allowed is True for v in verdicts)


# ---------------------------------------------------------------------------
# Domain enforcement (async)
# ---------------------------------------------------------------------------


class TestAsyncDomainEnforcement:
    @pytest.mark.asyncio
    async def test_blocked_domain_async(self):
        policy = Policy.from_yaml("""
name: net-async
default_action: allow
blocked_domains:
  - "*.evil.com"
rules: []
""")
        decision = await check_async(
            policy,
            ToolCall(tool="browser", resource="https://api.evil.com/steal"),
        )
        assert decision.allowed is False
        assert "blocked" in decision.reason

    @pytest.mark.asyncio
    async def test_allowed_domain_async(self):
        policy = Policy.from_yaml("""
name: net-async
default_action: allow
allowed_domains:
  - "*.github.com"
rules: []
""")
        decision = await check_async(
            policy,
            ToolCall(tool="browser", resource="https://api.github.com/repos"),
        )
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# Execution limits (async)
# ---------------------------------------------------------------------------


class TestAsyncExecutionLimits:
    @pytest.mark.asyncio
    async def test_max_tool_calls_async(self):
        policy = Policy.from_yaml("""
name: limited-async
default_action: allow
max_tool_calls: 3
rules: []
""")
        guard = Guard(policy)
        for _ in range(3):
            v = await guard.check_async(ToolCall(tool="x", resource="r"))
            assert v.allowed is True

        v = await guard.check_async(ToolCall(tool="x", resource="r"))
        assert v.allowed is False
        assert "max_tool_calls" in v.reason


# ---------------------------------------------------------------------------
# PolicyDecision properties
# ---------------------------------------------------------------------------


class TestPolicyDecisionProperties:
    def test_allowed_decision(self):
        d = PolicyDecision(allowed=True, reason="ok", risk=RiskLevel.LOW)
        assert d.allowed is True
        assert d.denied is False
        assert d.rule is None

    def test_denied_decision(self):
        d = PolicyDecision(allowed=False, reason="nope", risk=RiskLevel.HIGH)
        assert d.denied is True
        assert d.allowed is False

    def test_from_verdict(self, policy: Policy):
        guard = Guard(policy)
        verdict = guard.check(ToolCall(tool="fs.read", resource="./x.py"))
        decision = PolicyDecision.from_verdict(verdict)
        assert decision.allowed == verdict.allowed
        assert decision.reason == verdict.reason
        assert decision.risk == verdict.risk
        assert decision.rule == verdict.rule


# ---------------------------------------------------------------------------
# PolicyViolation exception
# ---------------------------------------------------------------------------


class TestPolicyViolationException:
    def test_exception_message(self):
        d = PolicyDecision(allowed=False, reason="tool blocked", risk=RiskLevel.CRITICAL)
        exc = PolicyViolation(d)
        assert "tool blocked" in str(exc)
        assert "critical" in str(exc)
        assert exc.decision is d

    def test_exception_is_catchable(self):
        d = PolicyDecision(allowed=False, reason="denied", risk=RiskLevel.MEDIUM)
        with pytest.raises(PolicyViolation):
            raise PolicyViolation(d)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
