"""Tests for agent-guard security fixes."""
import sys
sys.path.insert(0, 'src')

import pytest
from agent_guard import Guard, Policy, ToolCall, Action, RiskLevel, Rule


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


def test_redos_protection_execution_timeout():
    """Tier 2: A pathological regex that triggers catastrophic backtracking
    must be killed by the execution timeout, not hang the process."""
    import time
    # Policy with a rule that uses a regex pattern — the pathological input
    # will be evaluated against this regex
    policy = Policy(
        name="test",
        description="t",
        default_action=Action.DENY,
        rules=[
            Rule(
                action=Action.ALLOW,
                tool="test",
                resource=r"(a+)+b",  # pathological regex
                description="allow if matches",
            )
        ],
    )
    guard = Guard(policy)
    # (a+)+b on a string of 50 'a's then 'c' — will backtrack exponentially
    call = ToolCall(tool="test", resource="a" * 50 + "c")
    start = time.time()
    verdict = guard.check(call)
    elapsed = time.time() - start
    # Should complete in < 2s (timeout is 1s, plus overhead)
    assert elapsed < 2.0, f"ReDoS timeout not effective: took {elapsed:.2f}s"
    assert not verdict.allowed, "Pathological regex should be rejected"


def test_redos_protection_normal_regex_still_works():
    """Normal regex patterns should still match correctly after timeout guard."""
    policy = Policy(
        name="test",
        description="t",
        default_action=Action.DENY,
        rules=[
            Rule(
                action=Action.ALLOW,
                tool="fs.read",
                # Pattern with + quantifier and anchors — triggers regex path,
                # but uses only literal chars that survive normalization
                resource=r"^/home/user/[a-z]+\.txt$",
                description="allow txt files in user dir",
            )
        ],
    )
    guard = Guard(policy)
    # Path with only lowercase letters → matches [a-z]+
    call = ToolCall(tool="fs.read", resource="/home/user/zzz.txt")
    verdict = guard.check(call)
    assert verdict.allowed


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
    """ToolCall with tool=None should raise ValueError (issue #137)."""
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool=None, resource="foo")
    with pytest.raises(ValueError, match="tool must be a non-empty string"):
        guard.check(call)


def test_invalid_tool_empty() -> None:
    """ToolCall with empty tool string should raise ValueError (issue #137)."""
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="", resource="foo")
    with pytest.raises(ValueError, match="tool must be a non-empty string"):
        guard.check(call)


def test_invalid_arguments_not_dict() -> None:
    """ToolCall with non-dict arguments should raise ValueError (issue #137)."""
    policy = Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
    guard = Guard(policy)
    call = ToolCall(tool="fs.read", arguments="not a dict")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="arguments must be a dict"):
        guard.check(call)


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
