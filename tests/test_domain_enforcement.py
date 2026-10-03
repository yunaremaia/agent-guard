"""Regression tests for issue #176: domain policies are bypassed without a scheme.

Before the fix, :meth:`Guard._check_network` only extracted a host when the
resource contained ``://`` or began with ``www.``. Every other spelling of the
same host (``internal.corp``, ``//internal.corp``, ``HTTPS://INTERNAL.CORP``,
``https://user@internal.corp/``) left ``domain == ""``, which skipped the whole
``if domain:`` block holding *both* the blocklist and the allowlist checks and
fell through to the generic rule list. A policy author writing the documented
allowlist form got a silently unenforced policy, and the verdict reason claimed
``domain ok, allow by rule`` when no domain had been checked at all.

These tests exercise the public ``Guard.check`` surface only, so they pin the
security behaviour rather than the parsing helper's shape.
"""

from __future__ import annotations

import pytest

from agent_guard import Guard, Policy, ToolCall

# One host per spelling, all of which resolve to the same authority. The
# baseline entry is what a policy author reads as "this host is off limits".
BLOCKED_SPELLINGS = [
    "https://metadata.internal.corp/latest",
    "http://metadata.internal.corp",
    "metadata.internal.corp",
    "metadata.internal.corp/latest",
    "//metadata.internal.corp",
    "//metadata.internal.corp/latest",
    "metadata.internal.corp:8443/latest",
    "HTTPS://METADATA.INTERNAL.CORP",
    "https://metadata.INTERNAL.CORP/latest",
    "https://user:secret@metadata.internal.corp/latest",
]

ALLOWED_HOST = "https://api.example.com/ok"


def _guard(policy_yaml: str) -> Guard:
    return Guard(Policy.from_yaml(policy_yaml))


BLOCKLIST_POLICY = """
name: blocklist
description: Metadata endpoints are off limits
default_action: allow
blocked_domains:
  - "*.internal.corp"
rules: []
"""

ALLOWLIST_POLICY = """
name: allowlist
description: Only approved hosts may be browsed
default_action: deny
allowed_domains:
  - "*.example.com"
rules:
  - action: allow
    tool: "browser"
    resource: "*"
    description: "Generic browser access"
"""


class TestBlocklistIsNotBypassable:
    """A blocked host must stay blocked however the URL is spelled.

    The blocklist is the hard-deny control, so a spelling that skips the
    ``if domain:`` block is the worst possible failure: the policy explicitly
    named the host and the call still went through.
    """

    @pytest.mark.parametrize("resource", BLOCKED_SPELLINGS)
    def test_blocked_host_denied_in_every_spelling(self, resource: str):
        verdict = _guard(BLOCKLIST_POLICY).check(
            ToolCall(tool="browser", resource=resource)
        )
        assert verdict.allowed is False, (
            f"{resource!r} bypassed blocked_domains: {verdict.reason}"
        )
        assert "blocked" in verdict.reason

    def test_unlisted_host_still_allowed(self):
        """Positive control: the fix must not deny hosts outside the blocklist."""
        verdict = _guard(BLOCKLIST_POLICY).check(
            ToolCall(tool="browser", resource=ALLOWED_HOST)
        )
        assert verdict.allowed is True


class TestAllowlistIsNotBypassable:
    """An allowlist is a containment control; dropping the scheme must not escape it."""

    @pytest.mark.parametrize(
        "resource",
        [
            "https://evil.example.org/steal",
            "evil.example.org",
            "evil.example.org/steal",
            "//evil.example.org",
            "//evil.example.org/steal",
            "evil.example.org:8443/steal",
            "HTTPS://EVIL.EXAMPLE.ORG/steal",
            "https://user:secret@evil.example.org/steal",
        ],
    )
    def test_unlisted_host_denied_in_every_spelling(self, resource: str):
        verdict = _guard(ALLOWLIST_POLICY).check(
            ToolCall(tool="browser", resource=resource)
        )
        assert verdict.allowed is False, (
            f"{resource!r} bypassed allowed_domains: {verdict.reason}"
        )
        assert "not in allowlist" in verdict.reason

    def test_listed_host_still_allowed(self):
        """Positive control: an allowlisted host keeps working with and without a scheme."""
        guard = _guard(ALLOWLIST_POLICY)
        for resource in (ALLOWED_HOST, "api.example.com", "//api.example.com/ok"):
            verdict = guard.check(ToolCall(tool="browser", resource=resource))
            assert verdict.allowed is True, f"{resource!r} was wrongly denied: {verdict.reason}"


class TestDomainPolicyFailsClosed:
    """A resource that cannot be reduced to a host must not skip the domain checks."""

    @pytest.mark.parametrize("resource", [None, "", "   ", "/etc/passwd", "://"])
    def test_allowlist_denies_undeterminable_host(self, resource):
        verdict = _guard(ALLOWLIST_POLICY).check(
            ToolCall(tool="browser", resource=resource)
        )
        assert verdict.allowed is False, (
            f"{resource!r} skipped the allowlist entirely: {verdict.reason}"
        )
        assert "could not determine target domain" in verdict.reason

    @pytest.mark.parametrize("resource", [None, "", "/etc/passwd", "https://[::1"])
    def test_blocklist_denies_undeterminable_host(self, resource):
        verdict = _guard(BLOCKLIST_POLICY).check(
            ToolCall(tool="browser", resource=resource)
        )
        assert verdict.allowed is False, (
            f"{resource!r} skipped the blocklist entirely: {verdict.reason}"
        )
        assert "could not determine target domain" in verdict.reason


class TestPoliciesWithoutDomainRulesAreUnchanged:
    """No domain policy configured means no domain check to fail closed on."""

    def test_none_resource_still_allowed(self):
        policy = """
name: no-domains
default_action: allow
rules: []
"""
        assert _guard(policy).check(ToolCall(tool="http", resource=None)).allowed is True

    def test_url_still_allowed_without_domain_policy(self):
        policy = """
name: no-domains
default_action: allow
rules: []
"""
        verdict = _guard(policy).check(ToolCall(tool="http", resource=ALLOWED_HOST))
        assert verdict.allowed is True

    def test_rules_still_decide_when_no_domain_policy(self):
        """A domain-less policy keeps matching rules, and says so honestly."""
        policy = """
name: no-domains
default_action: deny
rules:
  - action: allow
    tool: browser
    resource: "*"
"""
        verdict = _guard(policy).check(ToolCall(tool="browser", resource="anything"))
        assert verdict.allowed is True
        assert "domain ok" not in verdict.reason, (
            "verdict claims a domain check that never ran"
        )

    def test_non_network_tool_is_unaffected(self):
        """Domain extraction must not leak into the filesystem/rule path."""
        policy = """
name: fs
default_action: deny
allowed_domains:
  - "*.example.com"
rules:
  - action: allow
    tool: fs.read
    resource: "*"
"""
        verdict = _guard(policy).check(ToolCall(tool="fs.read", resource="/etc/hosts"))
        assert verdict.allowed is True
