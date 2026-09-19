"""Tests for agent-guard CLI."""

from __future__ import annotations

import importlib.metadata

from click.testing import CliRunner

import agent_guard
from agent_guard.main import cli


def test_package_version_from_metadata():
    """Verify __version__ is defined and sourced from package metadata."""
    assert hasattr(agent_guard, "__version__")
    expected_version = importlib.metadata.version("agent-guard")
    assert agent_guard.__version__ == expected_version


def test_cli_version_flag():
    """Verify --version prints the program name and version."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert f"Agent Guard, version {agent_guard.__version__}" in result.output.strip()


def test_cli_version_short_flag():
    """Verify -v shorthand prints the program name and version."""
    runner = CliRunner()
    result = runner.invoke(cli, ["-v"])
    assert result.exit_code == 0
    assert f"Agent Guard, version {agent_guard.__version__}" in result.output.strip()


def test_cli_version_flags_match():
    """Verify --version and -v outputs are identical."""
    runner = CliRunner()
    long_res = runner.invoke(cli, ["--version"])
    short_res = runner.invoke(cli, ["-v"])
    assert long_res.output == short_res.output
