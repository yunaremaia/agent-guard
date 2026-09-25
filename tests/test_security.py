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


def test_shell_wildcard_allowed() -> None:
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="shell", resource="ls *.py")
    verdict = guard.check(call)
    assert verdict.allowed


def test_invalid_tool_none() -> None:
    """ToolCall with tool=None should be rejected (issue #137)."""
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool=None, resource="foo")
    verdict = guard.check(call)
    assert not verdict.allowed
    assert "invalid tool" in verdict.reason
    assert verdict.risk == RiskLevel.HIGH


def test_invalid_tool_empty() -> None:
    """ToolCall with empty tool string should be rejected (issue #137)."""
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="", resource="foo")
    verdict = guard.check(call)
    assert not verdict.allowed
    assert "invalid tool" in verdict.reason


def test_invalid_arguments_not_dict() -> None:
    """ToolCall with non-dict arguments should be rejected (issue #137)."""
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="fs.read", arguments="not a dict")  # type: ignore[arg-type]
    verdict = guard.check(call)
    assert not verdict.allowed
    assert "invalid arguments" in verdict.reason


def test_policy_from_yaml_unknown_fields() -> None:
    """Policy.from_yaml should warn on unknown fields (issue #140)."""
    import warnings
    yaml_text = """
name: test
description: test policy
default_action: deny
rules: []
unknown_field: should_warn
another_unknown: 123
"""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        policy = Policy.from_yaml(yaml_text)
        assert policy.name == "test"
        assert len(w) == 1
        assert "unknown_field" in str(w[0].message)
        assert "another_unknown" in str(w[0].message)


def test_policy_from_yaml_invalid_name() -> None:
    """Policy.from_yaml should reject missing or invalid name (issue #140)."""
    with pytest.raises(ValueError, match="name"):
        Policy.from_yaml("description: test\nrules: []")
    with pytest.raises(ValueError, match="name"):
        Policy.from_yaml("name: !\ndescription: test\nrules: []")


def test_policy_from_yaml_invalid_type_max_tool_calls() -> None:
    """Policy.from_yaml should reject non-integer max_tool_calls (issue #140)."""
    with pytest.raises(ValueError, match="max_tool_calls"):
        Policy.from_yaml("""
name: test
default_action: deny
rules: []
max_tool_calls: "not_a_number"
""")


def test_policy_from_yaml_invalid_action() -> None:
    """Policy.from_yaml should reject invalid action values (issue #140)."""
    with pytest.raises(ValueError, match="default_action"):
        Policy.from_yaml("""
name: test
default_action: maybe
rules: []
""")


def test_policy_from_yaml_invalid_rule_action() -> None:
    """Policy.from_yaml should reject invalid rule actions (issue #140)."""
    with pytest.raises(ValueError, match="Rule 0"):
        Policy.from_yaml("""
name: test
default_action: deny
rules:
  - action: maybe
    tool: "fs.read"
    resource: "*"
""")


def test_policy_from_yaml_not_a_mapping() -> None:
    """Policy.from_yaml should reject non-mapping YAML (issue #140)."""
    with pytest.raises(ValueError, match="mapping"):
        Policy.from_yaml("- item1\n- item2")
