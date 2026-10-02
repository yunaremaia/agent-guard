"""Tests for ReDoS protection in user-supplied policy regex patterns.

These pin *behavior* (which patterns are refused and why), not the internals
of the analyzer. The false-positive side matters as much as the true-positive
side: a detector that refuses ordinary patterns like an anchored URL is worse
than no detector at all in a policy engine.
"""
import sys
import time

sys.path.insert(0, 'src')

import pytest

from agent_guard import Action, Guard, Policy, Rule, ToolCall
from agent_guard.redos import MAX_PATTERN_LENGTH, is_safe_pattern

# Patterns that MUST be refused: each is a real catastrophic-backtracking shape.
UNSAFE_PATTERNS = [
    r"(a+)+",
    r"(a+)*",
    r"(a*)*",
    r"(a*)+",
    r"(a?)+",
    r"(a?)*",
    r"(.*)*",
    r"(.*)+",
    r"((a|b)+)+",
    r"(\w+)+",
    r"([a-z]+)*",
    r"(a{1,2})+",
    r"(a+){2,}",
    r"(\d+)+",
    r"(.*?)*",
    r"^(a+)+$",
]

# Alternation whose branches are ambiguous under repetition.
AMBIGUOUS_ALTERNATION = [
    r"(a|a)*",
    r"(a|a)+",
    r"(a|ab)*",
    r"(foo|foobar)*",
    r"(\d|\d)*",
]

# Patterns that MUST keep working. A false positive here is a broken policy engine.
SAFE_PATTERNS = [
    r"a+",
    r"a*",
    r"a?",
    r"\d{2,4}",
    r"[a-z]+",
    r"(a+)",
    r"(a{2,3})",
    r"(.*?)",
    r"(?:abc)+",
    r"^/srv/.*\.log$",
    r"^/home/user/[a-z]+\.txt$",
    r"^src/[a-z_]+\.py$",
    r"^foo/bar{1,3}$",
    r"(cat|dog)",
    r"(cat|dog)+",
    r"^(get|set)_\w+$",
    r"file_\d+\.txt",
    r"tool_\w+",
    r"^https://[a-z0-9.-]+(:[0-9]+)?/.*$",
    r"^https://api\.github\.com/repos/[^/]+/.*$",
    r"a\+b",
    r"^literal\.\*$",
    r"[^/]+",
    r"^(?!.*(secret|token)).*$",
    # Patterns that look structurally like a nested quantifier but are pinned
    # by a mandatory separator the inner class cannot absorb. Rejecting these
    # would break ordinary policy documents, so they are pinned as regressions.
    r"^https://[a-z0-9.-]+(?:\.[a-z]{2,})+(?:/[a-zA-Z0-9._~%/-]*)?$",
    r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::[0-9]{1,5})?"
    r"(?:/[^\s?#]*)?(?:\?[^\s#]*)?$",
    r"^/usr/local/bin/[a-z0-9_-]+( [a-zA-Z0-9_./-]+)*$",
    r"^/home/[a-z]+/projects/[a-z_]+/\.env$",
    r"^(GET|POST|PUT|DELETE|PATCH) /api/v[0-9]+/.*$",
    r"^/var/log/(nginx|apache2|journal)/.*\.log$",
]


@pytest.mark.parametrize("pattern", UNSAFE_PATTERNS + AMBIGUOUS_ALTERNATION)
def test_dangerous_patterns_are_rejected(pattern):
    safe, reason = is_safe_pattern(pattern)
    assert safe is False, f"expected {pattern!r} to be rejected"
    assert reason, "a rejection must carry a reason"


@pytest.mark.parametrize("pattern", SAFE_PATTERNS)
def test_safe_patterns_are_accepted(pattern):
    safe, reason = is_safe_pattern(pattern)
    assert safe is True, f"false positive: {pattern!r} rejected with reason {reason!r}"
    assert reason is None


def test_rejection_reason_names_the_dangerous_construct():
    """The reason must tell the user which construct is dangerous."""
    safe, reason = is_safe_pattern(r"(a+)+")
    assert safe is False
    assert isinstance(reason, str)
    lowered = reason.lower()
    assert "quantifier" in lowered, reason
    # The offending fragment itself is quoted back to the user.
    assert "(a+)" in reason, reason


def test_ambiguous_alternation_reason_mentions_branches():
    safe, reason = is_safe_pattern(r"(a|a)*")
    assert safe is False
    lowered = reason.lower()
    assert "alternation" in lowered or "ambiguous" in lowered, reason
    assert "a" in reason


def test_length_limit_is_preserved():
    """The pre-existing length check must keep working."""
    assert MAX_PATTERN_LENGTH == 100
    safe, reason = is_safe_pattern("a" * (MAX_PATTERN_LENGTH + 1))
    assert safe is False
    assert "length" in reason.lower(), reason
    # Exactly at the limit is fine.
    assert is_safe_pattern("a" * MAX_PATTERN_LENGTH)[0] is True


def test_default_max_length_is_configurable():
    assert is_safe_pattern("a" * 20, max_length=10)[0] is False
    assert is_safe_pattern("a" * 20, max_length=100)[0] is True


def test_unbounded_large_repetition_is_rejected():
    """An unbounded repetition with a large floor is a resource-exhaustion vector."""
    safe, reason = is_safe_pattern(r"[a-z]{100,}")
    assert safe is False
    assert "repetition" in reason.lower() or "length" in reason.lower(), reason


def test_bounded_repetition_is_accepted():
    assert is_safe_pattern(r"[a-z]{2,10}")[0] is True
    assert is_safe_pattern(r"\d{1,3}")[0] is True


def test_incomplete_pattern_does_not_raise():
    """A truncated pattern must be reported, not blow up the analyzer."""
    for bad in [r"(unclosed", r"[a-", r"(", r"*", r"(a+", r"{2,", r"a)b"]:
        safe, reason = is_safe_pattern(bad)
        assert isinstance(safe, bool)
        assert isinstance(reason, (str, type(None)))


def test_analyzer_is_bounded_on_hostile_input():
    """The guard must not itself hang on a hostile pattern (step/depth budget)."""
    hostile = [
        "(" * 5000 + "a" + ")" * 5000 + "+",
        "(((((a+)+)+)+)+)+",
        "(a|" * 3000 + "a" + ")" * 3000,
        "(a+)+" * 2000,
        "[" * 2000 + "]" * 2000,
        "\\" * 5000,
    ]
    start = time.time()
    for pattern in hostile:
        safe, _ = is_safe_pattern(pattern, max_length=10**6)
        assert isinstance(safe, bool)
    elapsed = time.time() - start
    assert elapsed < 2.0, f"analyzer took {elapsed:.2f}s on hostile input"


def test_deeply_nested_hostile_pattern_is_still_reported_unsafe():
    """Budget exhaustion must fail closed (unsafe), never open."""
    deep = "(" * 300 + "a" + ")" * 300 + "+"
    safe, _ = is_safe_pattern(deep, max_length=10**6)
    assert safe is False


class TestWiredIntoEvaluation:
    """The analyzer must be reachable from real policy evaluation."""

    def _guard(self, resource, action=Action.ALLOW):
        policy = Policy(
            name="test",
            description="t",
            default_action=Action.DENY,
            rules=[Rule(action=action, tool="fs.read", resource=resource)],
        )
        return Guard(policy)

    def test_rule_matches_resource_refuses_nested_quantifier(self):
        rule = Rule(action=Action.ALLOW, tool="fs.read", resource=r"(a+)+")
        assert rule.matches_resource("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX") is False

    def test_rule_matches_resource_allows_ordinary_pattern(self):
        rule = Rule(action=Action.ALLOW, tool="fs.read", resource=r"^/srv/.*\.log$")
        assert rule.matches_resource("/srv/app.log") is True
        assert rule.matches_resource("/srv/app.txt") is False

    def test_guard_check_denies_unsafe_pattern(self):
        verdict = self._guard(r"(a+)+").check(ToolCall(tool="fs.read", resource="aaaa"))
        assert verdict.allowed is False

    def test_guard_check_allows_safe_pattern(self):
        guard = self._guard(r"^/tmp/[a-z0-9_]+\.txt$")
        assert guard.check(ToolCall(tool="fs.read", resource="/tmp/report.txt")).allowed
        assert not guard.check(ToolCall(tool="fs.read", resource="/tmp/a.exe")).allowed

    def test_policy_from_yaml_rejects_unsafe_pattern(self):
        yaml_text = (
            "name: bad\n"
            "description: d\n"
            "default_action: deny\n"
            "rules:\n"
            "  - action: allow\n"
            '    tool: "fs.read"\n'
            '    resource: "(a+)+"\n'
        )
        with pytest.raises(ValueError, match=r"(?i)regex"):
            Policy.from_yaml(yaml_text)

    def test_policy_from_yaml_accepts_safe_regex(self):
        yaml_text = (
            "name: good\n"
            "description: d\n"
            "default_action: deny\n"
            "rules:\n"
            "  - action: allow\n"
            '    tool: "fs.read"\n'
            '    resource: "^/srv/.*\\\\.log$"\n'
        )
        policy = Policy.from_yaml(yaml_text)
        assert policy.rules[0].resource == r"^/srv/.*\.log$"
        assert policy.rules[0].matches_resource("/srv/a.log") is True

    def test_policy_from_yaml_ignores_glob_patterns(self):
        """Plain globs never reach the regex analyzer and must keep working."""
        yaml_text = (
            "name: globs\n"
            "description: d\n"
            "default_action: deny\n"
            "rules:\n"
            "  - action: allow\n"
            '    tool: "fs.read"\n'
            '    resource: "**/*.py"\n'
            "  - action: allow\n"
            '    tool: "shell"\n'
            '    resource: "ls *"\n'
        )
        policy = Policy.from_yaml(yaml_text)
        assert len(policy.rules) == 2
