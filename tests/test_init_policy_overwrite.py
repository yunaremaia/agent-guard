"""Regression tests for `agent-guard init` writing a policy file."""

from pathlib import Path

from click.testing import CliRunner

from agent_guard import Policy
from agent_guard.main import cli

EXISTING_POLICY = """\
name: production
description: Hand-tuned production policy
default_action: deny
max_tool_calls: 5
blocked_domains:
  - "*.prod.internal"
rules:
  - action: allow
    tool: fs.read
    resource: "./**/*"
    description: Only pre-approved prod read
"""


def test_init_refuses_to_overwrite_an_existing_policy(tmp_path: Path) -> None:
    """`init` builds a whole file, so writing it over a live policy destroys
    every key the user added. It must refuse instead."""
    policy = tmp_path / ".agent-guard.yaml"
    policy.write_text(EXISTING_POLICY, encoding="utf-8")

    result = CliRunner().invoke(
        cli, ["init", "scratch", "--output", str(policy)], catch_exceptions=False
    )

    assert result.exit_code == 1
    assert policy.read_text(encoding="utf-8") == EXISTING_POLICY


def test_init_preserves_sibling_keys_of_an_existing_policy(tmp_path: Path) -> None:
    """The keys the user added survive a refused/forced init unchanged."""
    policy = tmp_path / ".agent-guard.yaml"
    policy.write_text(EXISTING_POLICY, encoding="utf-8")

    refused = CliRunner().invoke(
        cli, ["init", "scratch", "--output", str(policy)], catch_exceptions=False
    )
    assert refused.exit_code == 1

    loaded = Policy.from_file(policy)
    assert loaded.name == "production"
    assert loaded.description == "Hand-tuned production policy"
    assert loaded.max_tool_calls == 5
    assert loaded.blocked_domains == ["*.prod.internal"]
    assert [r.description for r in loaded.rules] == ["Only pre-approved prod read"]


def test_init_force_still_writes_a_fresh_policy(tmp_path: Path) -> None:
    """--force is the deliberate opt-in that replaces the file."""
    policy = tmp_path / ".agent-guard.yaml"
    policy.write_text(EXISTING_POLICY, encoding="utf-8")

    result = CliRunner().invoke(
        cli, ["init", "scratch", "--output", str(policy), "--force"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    loaded = Policy.from_file(policy)
    assert loaded.name == "scratch"
    assert loaded.rules


def test_init_creates_a_policy_when_none_exists(tmp_path: Path) -> None:
    """The normal first-run path is unchanged."""
    policy = tmp_path / ".agent-guard.yaml"

    result = CliRunner().invoke(
        cli, ["init", "fresh", "--output", str(policy)], catch_exceptions=False
    )

    assert result.exit_code == 0
    loaded = Policy.from_file(policy)
    assert loaded.name == "fresh"
    assert loaded.default_action.value == "deny"
    assert loaded.rules
