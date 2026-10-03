"""Tests for globstar (``**``) semantics in :meth:`Rule.matches_resource`.

Issue #175: ``**`` must match ZERO or more path segments, matching standard
globstar / .gitignore behaviour. The matcher used a hand-rolled
``pattern.partition("**/")`` split which has no case for a *trailing* ``**``
(``"/home/"`` never appears, so the whole pattern landed in ``prefix`` and the
check degenerated to ``res.startswith("/home/**")``). Every ``**`` pattern that
does not end in ``*/`` therefore matched nothing, so ``deny`` rules such as
``resource: "/home/**"`` silently failed open and the README's own templates
(``./research/**``, ``./deploy/**``, ``./.github/**``) were dead as written.

The tests are grouped in three classes:

* **Discriminating** -- these fail on the pre-fix matcher and pass after the
  fix. They are the RED baseline.
* **Positive controls** -- these already pass before the fix and must keep
  passing. They guard against "fixing" the bug by turning the matcher into an
  over-broad deny-all, and they pin the sibling single-star behaviour that the
  fix must not disturb.
"""

import sys

sys.path.insert(0, "src")

import pytest

from agent_guard import Action, Guard, Policy, Rule, ToolCall


def deny(pattern: str) -> Rule:
    return Rule(action=Action.DENY, resource=pattern, tool="fs_read")


# --------------------------------------------------------------------------
# Discriminating: trailing ``**`` matches ZERO or more segments
# --------------------------------------------------------------------------


class TestTrailingGlobstarMatchesZeroSegments:
    """``/home/**`` must match ``/home`` itself, not just its descendants."""

    @pytest.mark.parametrize(
        "resource",
        ["/home", "/home/a", "/home/agent/.ssh/id_rsa", "/home/a/b/c/d/e.txt"],
    )
    def test_trailing_globstar_matches_zero_or_more_segments(self, resource: str) -> None:
        assert deny("/home/**").matches_resource(resource) is True

    def test_bare_globstar_matches_everything(self) -> None:
        rule = deny("**")
        for resource in ["/", "/a", "/a/b/c", "relative/path", "file.txt"]:
            assert rule.matches_resource(resource) is True, resource

    def test_globstar_infix_matches_zero_segments_before_suffix(self) -> None:
        """/a/**/b matches /a/b: the middle ``**`` may consume no segment."""
        rule = deny("/a/**/b")
        assert rule.matches_resource("/a/b") is True
        assert rule.matches_resource("/a/x/b") is True
        assert rule.matches_resource("/a/x/y/z/b") is True

    def test_leading_globstar_matches_zero_segments(self) -> None:
        """``**/secrets/**`` matches a top-level ``/secrets`` too."""
        rule = deny("**/secrets/**")
        assert rule.matches_resource("/secrets") is True
        assert rule.matches_resource("/secrets/db.env") is True
        assert rule.matches_resource("/a/secrets/db.env") is True
        assert rule.matches_resource("/a/secrets/x/y/z") is True

    def test_trailing_slash_resource_still_matches(self) -> None:
        assert deny("/home/**").matches_resource("/home/") is True


# --------------------------------------------------------------------------
# Discriminating: end-to-end policy behaviour (fail-open vs fail-closed)
# --------------------------------------------------------------------------


def test_deny_rule_with_trailing_globstar_does_not_fail_open() -> None:
    """A ``deny`` on ``/home/**`` under ``default_action: allow`` must deny.

    Regression for the exact false negative in #175: the rule matched nothing,
    so every read under ``/home`` fell through to the default allow.
    """
    policy = Policy.from_yaml(
        """
name: recursive-glob
description: Deny reads under /home
default_action: allow
rules:
  - action: deny
    tool: "fs_read"
    resource: "/home/**"
"""
    )
    guard = Guard(policy)
    for resource in ["/home", "/home/agent/.ssh/id_rsa", "/home/a/b/c"]:
        verdict = guard.check(ToolCall(tool="fs_read", resource=resource))
        assert verdict.allowed is False, f"{resource} was allowed: {verdict.reason}"


def test_readme_template_2_research_glob_allows_recursive_writes() -> None:
    """README Template 2 verbatim: ``allow`` on ``./research/**``.

    With ``default_action: deny`` every legitimate write was denied because the
    allow rule never matched.
    """
    policy = Policy.from_yaml(
        """
name: research-agent
description: README Template 2
default_action: deny
rules:
  - action: allow
    tool: "fs.write"
    resource: "./research/**"
"""
    )
    guard = Guard(policy)
    for resource in ["./research/notes.md", "./research/sub/dir/notes.md", "research/notes.md"]:
        verdict = guard.check(ToolCall(tool="fs.write", resource=resource))
        assert verdict.allowed is True, f"{resource} was denied: {verdict.reason}"


# --------------------------------------------------------------------------
# Positive controls: these pass BEFORE the fix too. They are here to prove the
# fix is not an over-broad "match everything" change.
# --------------------------------------------------------------------------


class TestPositiveControls:
    """Deliberately over-broad probes -- must be rejected before AND after."""

    @pytest.mark.parametrize("resource", ["/etc/shadow", "/var/run/secrets/aws", "home2/x"])
    def test_trailing_globstar_is_scoped_to_its_prefix(self, resource: str) -> None:
        assert deny("/home/**").matches_resource(resource) is False

    def test_globstar_does_not_match_a_sibling_directory_with_a_shared_prefix(
        self,
    ) -> None:
        """``/home`` must not swallow ``/homeagent``: segment boundary."""
        assert deny("/home/**").matches_resource("/homeagent/x") is False

    def test_prefix_globstar_still_requires_the_suffix_segment(self) -> None:
        assert deny("**/secrets/**").matches_resource("/a/public") is False

    def test_deny_rule_does_not_become_deny_all(self) -> None:
        """The default action must still govern everything outside ``/home``."""
        policy = Policy.from_yaml(
            """
name: scoped-deny
description: t
default_action: allow
rules:
  - action: deny
    tool: "fs_read"
    resource: "/home/**"
"""
        )
        guard = Guard(policy)
        verdict = guard.check(ToolCall(tool="fs_read", resource="/etc/hosts"))
        assert verdict.allowed is True

    def test_single_star_semantics_are_unchanged(self) -> None:
        """The ``*`` path is untouched: ``**`` handling is a separate branch.

        ``/home/*`` reaches the ``PurePath.match`` fallback, which matches a
        single-star pattern at any depth. That is pre-existing behaviour and is
        deliberately left alone -- this fix is scoped to the ``**`` branch.
        """
        rule = deny("/home/*")
        assert rule.matches_resource("/home/a") is True
        assert rule.matches_resource("/home/a/b") is True
        assert rule.matches_resource("/etc/shadow") is False

    def test_absolute_single_star_pattern_still_anchors(self) -> None:
        assert deny("/home/*").matches_resource("home/a") is False

    def test_regex_patterns_are_unaffected(self) -> None:
        rule = Rule(action=Action.DENY, resource=r"^/srv/.*\.log$", tool="fs_read")
        assert rule.matches_resource("/srv/app.log") is True
        assert rule.matches_resource("/srv/app.txt") is False

    def test_path_traversal_in_resource_still_fails_closed(self) -> None:
        assert deny("/home/**").matches_resource("/home/../../etc/shadow") is False


# --------------------------------------------------------------------------
# Positive controls for the sibling forms that already worked before the fix.
# --------------------------------------------------------------------------


class TestExistingGlobstarFormsStillWork:
    @pytest.mark.parametrize(
        ("resource", "expected"),
        [
            ("/app/main.py", True),
            ("/app/pkg/util.py", True),
            ("/app/main.txt", False),
        ],
    )
    def test_extension_globstar(self, resource: str, expected: bool) -> None:
        assert deny("**/*.py").matches_resource(resource) is expected

    def test_absolute_extension_globstar(self) -> None:
        assert deny("/**/*.py").matches_resource("/root/deep/file.py") is True

    def test_readme_faq_glob_all_files_recursively(self) -> None:
        """README FAQ: ``./**/*`` matches all files recursively."""
        rule = deny("./**/*")
        for resource in ["./a.txt", "./src/main.py", "./a/b/c/d.txt"]:
            assert rule.matches_resource(resource) is True, resource
