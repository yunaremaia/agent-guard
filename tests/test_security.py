"""Tests for agent-guard security fixes."""
import sys
sys.path.insert(0, 'src')

import pytest
from agent_guard import Guard, Policy, ToolCall, Action, RiskLevel


def test_redos_protection_long_pattern():
    policy = Policy(name="test", description="t", default_action=Action.DENY, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="fs.read", resource="a" * 150)
    verdict = guard.check(call)
    assert not verdict.allowed


def test_redos_protection_nested_quantifiers():
    policy = Policy(name="test", description="t", default_action=Action.DENY, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="fs.read", resource="(a+)+")
    verdict = guard.check(call)
    assert not verdict.allowed


def test_shell_injection_semicolon():
    policy = Policy(name="test", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="shell", resource="ls; rm -rf /")
    verdict = guard.check(call)
    assert not verdict.allowed
    assert verdict.risk == RiskLevel.CRITICAL


def test_shell_injection_pipe():
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="shell", resource="ls | cat")
    verdict = guard.check(call)
    assert not verdict.allowed


def test_shell_injection_backtick():
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="shell", resource="`whoami`")
    verdict = guard.check(call)
    assert not verdict.allowed


def test_shell_injection_dollar():
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="shell", resource="$HOME")
    verdict = guard.check(call)
    assert not verdict.allowed


def test_shell_safe_command():
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="shell", resource="ls -la")
    verdict = guard.check(call)
    assert verdict.allowed


def test_shell_wildcard_allowed():
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="shell", resource="ls *.py")
    verdict = guard.check(call)
    assert verdict.allowed
