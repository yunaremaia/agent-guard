"""Executable verification of the packaged console-script entry point.

Two bugs motivated this file, and neither is catchable by reading text.

**1. The entry-point target pointed outside the wheel.** The console script
``agent-guard`` was declared as ``src.main:cli`` while the wheel ships the
package as ``agent_guard``. The package installed cleanly and every other test
passed, but the only command the README documents failed on first use::

    $ agent-guard --help
    ModuleNotFoundError: No module named 'src'

A string assertion over ``pyproject.toml`` does not catch this -- it still passes
if the module behind the target is moved, renamed, or dropped from the wheel. So
these tests resolve the target the same way the installed wrapper does, via
``importlib.metadata`` + ``EntryPoint.load()``, and then execute the object that
came back. ``EntryPoint.load()`` performs the same import the generated wrapper
performs at startup, so a wrong target raises here instead of at a user's shell.

**2. The distribution was renamed underneath a hardcoded lookup.** Renaming the
distribution from ``agent-guard`` to ``agentperm-py`` broke every test here that
looked the metadata up by literal name, with a bare
``PackageNotFoundError: No package metadata was found for agent-guard`` -- while
the entry point itself was perfectly fine. So ``DIST_NAME`` is read from
``[project] name`` in ``pyproject.toml`` and never hardcoded, matching the
convention ``tests/test_install_name.py`` already documents. The next rename
cannot break this file; if the declared name and the installed metadata ever
disagree, the lookup fails loudly instead of silently passing.

The names differ by design and only the distribution moved: the repository is
``agent-guard``, the console script a user types is ``agent-guard``, and the
distribution is ``agentperm-py``.

These tests require the package to be installed in the environment running them
-- the metadata and the generated wrapper both come from the install. CI does
that with ``pip install -e ".[dev]"``. When it is missing, the helpers below fail
with an explicit message rather than skipping, so an install regression is a
failure instead of a silent reduction in coverage.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from importlib.metadata import distribution
from pathlib import Path

import pytest

# ruff sorts tomllib as third-party here because [tool.ruff] target-version is
# py310, where tomllib was not yet stdlib. tests/test_install_name.py imports it
# the same way; matching that keeps this file ruff-clean.
import tomllib
from click.testing import CliRunner

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"

# The distribution name, read from the single source of truth so that a rename in
# pyproject.toml cannot leave this file looking up a name nothing ships under.
DIST_NAME: str = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["name"]

# The console script -- the command a user types. Only the distribution name
# carries the `-py` suffix; this is the repository name and must not change.
CONSOLE_SCRIPT_NAME = "agent-guard"


def _console_script_entry_point():
    """Return the installed ``agent-guard`` console_scripts entry point."""
    entry_points = distribution(DIST_NAME).entry_points
    matches = [ep for ep in entry_points if ep.name == CONSOLE_SCRIPT_NAME]
    assert matches, (
        f"no [project.scripts] entry named {CONSOLE_SCRIPT_NAME!r} was found in the "
        f"installed {DIST_NAME!r} distribution; got {[ep.name for ep in entry_points]}"
    )
    return matches[0]


def _console_script_path() -> Path:
    """Locate the wrapper script pip generated for the entry point."""
    # The wrapper is installed next to the interpreter that installed it, so it
    # is found next to sys.executable first; PATH is the fallback for the case
    # where the tests run under a different interpreter than the one installed.
    on_path = shutil.which(CONSOLE_SCRIPT_NAME)
    directories = [Path(sys.executable).parent]
    if on_path:
        directories.append(Path(on_path).parent)

    searched = []
    for directory in directories:
        for name in (CONSOLE_SCRIPT_NAME, f"{CONSOLE_SCRIPT_NAME}.exe"):
            path = directory / name
            searched.append(str(path))
            if path.is_file():
                return path
    pytest.fail(
        f"the {CONSOLE_SCRIPT_NAME} console script was not installed; searched {searched}. "
        f"The {DIST_NAME!r} distribution is not installed in the environment running "
        "the tests -- install it with `pip install -e \".[dev]\"`."
    )


def test_console_script_entry_point_resolves():
    """The declared target must import and yield a callable.

    This is the assertion that catches a target naming a module the wheel does
    not ship: ``EntryPoint.load()`` performs the same import the generated
    wrapper performs at startup, so it raises here instead of at the user's
    shell.
    """
    entry_point = _console_script_entry_point()
    loaded = entry_point.load()
    assert callable(loaded), f"{entry_point.value} resolved to a non-callable {loaded!r}"


def test_console_script_target_is_the_packaged_cli():
    """The target must be the ``cli`` group defined inside the shipped package.

    Guards against pointing the entry point at a module that exists but is not
    part of the distributed package (a test helper, a stray top-level module, or
    the ``src`` directory itself, which is not importable once installed).
    """
    entry_point = _console_script_entry_point()
    loaded = entry_point.load()

    import agent_guard.main

    assert loaded is agent_guard.main.cli
    assert agent_guard.main.__file__ is not None
    package_dir = Path(agent_guard.main.__file__).parent
    assert package_dir.name == "agent_guard", (
        f"entry point target resolves to {agent_guard.main.__file__}, which is outside "
        f"the shipped package directory {package_dir}"
    )


def test_console_script_runs_from_the_shell():
    """The generated wrapper must actually execute: --help and --version."""
    script = _console_script_path()
    for args in (["--help"], ["--version"]):
        result = subprocess.run(
            [str(script), *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, (
            f"`{CONSOLE_SCRIPT_NAME} {' '.join(args)}` exited {result.returncode}:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert result.stdout.strip(), f"`{CONSOLE_SCRIPT_NAME} {' '.join(args)}` printed nothing"


def test_module_entry_point_runs():
    """``python -m agent_guard`` is the second entry point; it must work too.

    ``__main__.py`` imports ``from .main import cli``, so it is unaffected by the
    ``src.main`` mixup — but it is the same class of surface and is exercised
    here so neither path can regress unnoticed.
    """
    result = subprocess.run(
        [sys.executable, "-m", CONSOLE_SCRIPT_NAME.replace("-", "_"), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, (
        f"`python -m agent_guard --help` exited {result.returncode}:\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "check" in result.stdout


def test_both_entry_points_expose_the_same_group():
    """``python -m agent_guard`` and the console script must agree on the object."""
    import agent_guard.__main__ as module_entry_point
    import agent_guard.main

    assert module_entry_point.cli is agent_guard.main.cli
    assert _console_script_entry_point().load() is agent_guard.main.cli


@pytest.mark.parametrize("command", ["check", "init", "audit"])
def test_documented_subcommands_run(command, tmp_path):
    """The subcommands the README documents must work through the resolved target.

    Driving the object returned by ``EntryPoint.load()`` (not a direct import)
    keeps this end-to-end: a wrong target fails before any command runs.
    """
    entry_point = _console_script_entry_point()
    runner = CliRunner()

    if command == "init":
        policy_file = tmp_path / "policy.yaml"
        result = runner.invoke(entry_point.load(), ["init", "demo", "-o", str(policy_file)])
        assert result.exit_code == 0, result.output
        assert policy_file.is_file(), f"init did not create {policy_file}"
        assert "name: demo" in policy_file.read_text()
    else:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "name: demo\n"
            "default_action: deny\n"
            "rules:\n"
            '  - action: allow\n'
            '    tool: fs.read\n'
            '    resource: "./**/*"\n'
        )
        # `check`/`explain` take the tool call to evaluate; `audit` reports on the
        # policy itself and only accepts the file plus a --format choice.
        if command == "audit":
            argv = ["audit", str(policy_file), "--format", "json"]
        else:
            argv = [command, str(policy_file), "--tool", "fs.read", "--resource", "./a.txt"]
            if command == "check":
                argv.append("--json")
        result = runner.invoke(entry_point.load(), argv)
        # `check` exits 1 when the verdict is DENY, which is the correct
        # behaviour for this policy/tool pair; only a crash is a failure.
        assert result.exit_code in (0, 1), result.output
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"`agent-guard {command}` raised {result.exception!r}"
        )
        assert result.output.strip(), f"`agent-guard {command}` printed nothing"
        if command == "audit":
            assert json.loads(result.output)["name"] == "demo"
        else:
            # `check --json` emits the verdict, `explain` echoes the policy name.
            assert "allowed" in json.loads(result.output) or "demo" in result.output
