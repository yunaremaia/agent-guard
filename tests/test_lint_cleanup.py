"""Regression tests for the ruff lint-gate cleanup.

Each test here proves that a mechanical lint fix does not change observable
runtime behaviour. They were written BEFORE the fixes (RED), against the
current public contract:

* ``Policy.from_yaml`` / ``Guard.check`` raise ``ValueError`` today (issues
  #137 and #140) and callers depend on that. To satisfy TRY004 without
  breaking the contract, the type-check failures are raised as
  ``PolicyValidationError``, which subclasses *both* ValueError and TypeError.
* Annotations are unquoted (UP037). The module has
  ``from __future__ import annotations``, so annotations are lazy strings at
  runtime -- these tests prove ``typing.get_type_hints()`` still resolves them.
"""

from __future__ import annotations

import re
import typing

import pytest

from agent_guard import (
    Action,
    Guard,
    Policy,
    PolicyValidationError,
    Rule,
    ToolCall,
    _normalize_path,
)


class TestPolicyValidationErrorContract:
    """PolicyValidationError must stay catchable as ValueError (back-compat)."""

    def test_is_both_value_error_and_type_error(self) -> None:
        err = PolicyValidationError("boom")
        assert isinstance(err, ValueError)
        assert isinstance(err, TypeError)

    def test_public_api_exports_it(self) -> None:
        import agent_guard

        assert "PolicyValidationError" in agent_guard.__all__
        assert agent_guard.PolicyValidationError is PolicyValidationError

    def test_from_yaml_type_failure_raises_policy_validation_error(self) -> None:
        with pytest.raises(PolicyValidationError):
            Policy.from_yaml("- item1\n- item2")

    def test_from_yaml_type_failure_still_caught_as_value_error(self) -> None:
        """The pre-existing contract: bare ``except ValueError`` keeps working."""
        with pytest.raises(ValueError, match="mapping"):
            Policy.from_yaml("- item1\n- item2")

    @pytest.mark.parametrize(
        ("yaml_text", "match"),
        [
            ("- item1\n- item2", "mapping"),
            ("name: t\ndescription: 5\nrules: []", "description"),
            ("name: t\ndefault_action: 7\nrules: []", "default_action"),
            ("name: t\nrules:\n  - notadict", "mapping"),
            ("name: t\nrules:\n  - tool: a\n    resource: 1", "'resource'"),
            ("name: t\nrules:\n  - tool: 1\n    resource: b", "'tool'"),
            ("name: t\nrules:\n  - tool: a\n    resource: b\n    action: 1", "'action'"),
        ],
    )
    def test_every_try004_site_uses_the_new_error(self, yaml_text: str, match: str) -> None:
        with pytest.raises(PolicyValidationError, match=match):
            Policy.from_yaml(yaml_text)

    @pytest.mark.parametrize(
        ("yaml_text", "match"),
        [
            # Missing/empty 'name' and bad enum values are *semantic* errors,
            # not type errors: they stay plain ValueError, unchanged.
            ("description: x\nrules: []", "name"),
            ("name: 5\nrules: []", "name"),
            ("name: t\ndefault_action: maybe\nrules: []", "default_action"),
            ("name: t\nrules:\n  - action: maybe\n    tool: a\n    resource: b", "Rule 0"),
            ("name: t\nrules: []\nmax_tool_calls: 'nope'", "max_tool_calls"),
            ("name: t\nrules: []\nblocked_tools: 'nope'", "blocked_tools"),
        ],
    )
    def test_semantic_errors_remain_plain_value_error(
        self, yaml_text: str, match: str
    ) -> None:
        with pytest.raises(ValueError, match=match) as exc_info:
            Policy.from_yaml(yaml_text)
        assert not isinstance(exc_info.value, PolicyValidationError)

    def test_guard_check_type_failure_raises_policy_validation_error(self) -> None:
        """The former ``# noqa: TRY004`` site in Guard.check."""
        guard = Guard(
            Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
        )
        with pytest.raises(PolicyValidationError, match="arguments must be a dict"):
            guard.check(ToolCall(tool="fs.read", resource="x", arguments="not a dict"))

    def test_guard_check_type_failure_still_caught_as_value_error(self) -> None:
        guard = Guard(
            Policy(name="t", description="t", default_action=Action.ALLOW, rules=[])
        )
        with pytest.raises(ValueError, match="tool must be a non-empty string"):
            guard.check(ToolCall(tool="", resource="x"))


class TestAnnotationsRemainResolvable:
    """UP037 unquoted the forward refs; ``get_type_hints`` must still resolve them."""

    @pytest.mark.parametrize(
        "func",
        [
            Policy.from_yaml,
            Policy.from_file,
            Policy.from_file_async,
            Guard.reset,
            Guard.check,
            Guard.check_async,
            Guard.stats,
            typing.get_type_hints(Policy.from_yaml),  # sanity: itself resolvable
        ][:-1],
    )
    def test_get_type_hints_resolves(self, func) -> None:
        hints = typing.get_type_hints(func)
        assert hints, f"{func.__qualname__} produced no type hints"

    def test_policy_return_annotation_resolves_to_policy_class(self) -> None:
        assert typing.get_type_hints(Policy.from_yaml)["return"] is Policy
        assert typing.get_type_hints(Policy.from_file)["return"] is Policy
        assert typing.get_type_hints(Policy.from_file_async)["return"] is Policy

    def test_self_referential_guard_reset_resolves_to_guard_class(self) -> None:
        assert typing.get_type_hints(Guard.reset)["return"] is Guard

    def test_forward_declared_policy_decision_resolves(self) -> None:
        """PolicyDecision.from_verdict is defined before PolicyDecision exists."""
        from agent_guard import PolicyDecision, Verdict

        assert typing.get_type_hints(PolicyDecision.from_verdict)["return"] is PolicyDecision
        assert typing.get_type_hints(PolicyDecision.from_verdict)["verdict"] is Verdict


class TestNormalizePathBehaviourUnchanged:
    """FURB188 replaced ``if p.startswith('./'): p = p[2:]`` with removeprefix."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("./src/main.py", "src/main.py"),
            ("./", ""),
            # "//" is collapsed *before* the leading "./" is stripped, so
            # ".//double" becomes "./double" -> "double" (not "/double").
            (".//double", "double"),
            ("./a//b", "a/b"),
            # Only a LEADING "./" is stripped; interior "./" is left alone.
            ("src/./main.py", "src/./main.py"),
            ("plain.py", "plain.py"),
            ("src\\main.py", "src/main.py"),
            ("dir/", "dir"),
            ("a//b///c", "a/b/c"),
        ],
    )
    def test_normalize_path(self, raw: str, expected: str) -> None:
        assert _normalize_path(raw) == expected

    def test_traversal_still_raises(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            _normalize_path("../etc/passwd")
        # Patterns may opt out of the security check.
        assert _normalize_path("../etc", security_check=False) == "../etc"


class TestCollapsedDirectoryMatchUnchanged:
    """SIM102 collapsed the nested ``if`` in Rule.matches_resource."""

    def test_directory_resource_matches_dir_glob(self) -> None:
        rule = Rule(action=Action.ALLOW, resource="/srv/data", tool="fs.read")
        assert rule.matches_resource("/srv/data/") is True

    def test_directory_resource_does_not_match_unrelated_glob(self) -> None:
        rule = Rule(action=Action.ALLOW, resource="/etc/*", tool="fs.read")
        assert rule.matches_resource("/srv/data/") is False

    def test_non_directory_resource_unaffected_by_collapse(self) -> None:
        rule = Rule(action=Action.ALLOW, resource="*.py", tool="fs.read")
        assert rule.matches_resource("main.py") is True
        assert rule.matches_resource("main.txt") is False


class TestRedosGuardUnchanged:
    """BLE001 narrowed the blind ``except BaseException`` inside the regex thread.

    The worker must still marshal its exception out; unhandled cases now fail
    closed (deny) instead of propagating a stray BaseException.
    """

    def test_redos_pattern_fails_closed(self) -> None:
        rule = Rule(action=Action.ALLOW, resource="(a+)+$", tool="fs.read")
        assert rule.matches_resource("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX") is False

    def test_invalid_regex_pattern_fails_closed(self) -> None:
        rule = Rule(action=Action.ALLOW, resource="[unclosed", tool="fs.read")
        assert rule.matches_resource("whatever") is False

    def test_valid_regex_pattern_still_matches(self) -> None:
        rule = Rule(action=Action.ALLOW, resource=r"^/srv/.*\.log$", tool="fs.read")
        assert rule.matches_resource("/srv/app.log") is True
        assert rule.matches_resource("/srv/app.txt") is False

    def test_recursive_glob_still_works(self) -> None:
        rule = Rule(action=Action.ALLOW, resource="/**/*.py", tool="fs.read")
        assert rule.matches_resource("/root/deep/file.py") is True

    def test_regex_error_from_worker_is_swallowed_by_outer_handler(self) -> None:
        """A re.error raised inside the thread is caught by the outer guard."""
        assert re.match(r"a", "a") is not None
        rule = Rule(action=Action.ALLOW, resource="[a-", tool="fs.read")
        assert rule.matches_resource("x") is False
