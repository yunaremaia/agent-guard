"""Regression guard: the documented install target must be the distribution name.

The short name `agent-guard` on PyPI belongs to an unrelated project (an
operational monitoring library for Crew AI applications by a different author),
so a README saying `pip install agent-guard` installs someone else's code. The
distribution is published as `agentperm-py`; the importable module and the
`agent-guard` console script are unchanged.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"

SHORT_NAME = "agent-guard"

# Matches the short name as a whole pip target, so `agent-guard-py` / a `git+`
# URL do not trigger it. Guarding the *name* only: `pip install -e .` and
# `pip install git+...` are legitimate from-source installs.
SHORT_NAME_INSTALL = re.compile(
    r"pip(?:3)?\s+install\s+(?:.*\s)?" + re.escape(SHORT_NAME) + r"(?![\w-])"
)


def _read(name: Path) -> str:
    return name.read_text(encoding="utf-8")


def _distribution_name() -> str:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["name"]


def test_distribution_name_is_not_the_pypi_short_name():
    assert _distribution_name() == "agentperm-py"


def test_readme_installs_the_distribution_name():
    readme = _read(README)
    assert "pip install agentperm-py" in readme


def test_readme_never_installs_the_pypi_short_name():
    offenders = [
        line
        for line in _read(README).splitlines()
        if SHORT_NAME_INSTALL.search(line)
    ]
    assert not offenders, (
        "README tells users to `pip install agent-guard`, which on PyPI is an "
        "unrelated project by a different author. Install the distribution "
        f"name `{_distribution_name()}` instead. Offending lines: {offenders}"
    )


def test_readme_notes_the_name_conflict():
    """The README must say *why* the short name is not the install target."""
    readme = _read(README).lower()
    assert "agentperm-py" in readme
    assert "unrelated" in readme or "different author" in readme or "taken" in readme
    assert "pypi" in readme


def test_import_module_and_console_script_are_unchanged():
    """Only the distribution name moves: the import surface must not."""
    with PYPROJECT.open("rb") as fh:
        pyproject = tomllib.load(fh)

    packages = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    assert any(p.endswith("agent_guard") for p in packages), packages
    assert "agent-guard" in pyproject["project"]["scripts"]


def test_console_script_target_is_importable():
    """The entry point must resolve against the built wheel, not the source tree.

    It once pointed at `src.main:cli`, a path that does not exist in the wheel
    (only the `agent_guard` package is packaged, with `src/` as its import root),
    so every install shipped a console script that raised ModuleNotFoundError.
    """
    pyproject = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    target = pyproject["project"]["scripts"]["agent-guard"]
    module_path, _, attr = target.partition(":")

    # hatchling `packages = ["src/agent_guard"]` installs `agent_guard/` into the
    # wheel root, so `src/` is the directory that goes on sys.path.
    packaged = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    assert packaged, "wheel packages entry missing"
    import_root = REPO_ROOT / Path(packaged[0]).parent

    top_level = module_path.split(".")[0]
    assert top_level == Path(packaged[0]).name, (
        f"console script imports {top_level!r} but the wheel packages "
        f"{Path(packaged[0]).name!r}"
    )

    resolved = import_root / Path(*module_path.split(".")).with_suffix(".py")
    assert resolved.exists(), f"console script module not in wheel: {module_path} ({resolved})"

    source = resolved.read_text(encoding="utf-8")
    assert re.search(rf"^def {re.escape(attr)}\b", source, re.M), (
        f"{target} does not define {attr}() in {resolved.name}"
    )


def test_no_pypi_badge_while_unpublished():
    """A PyPI badge renders "not found" for a package that is not on PyPI yet."""
    badges = [
        line for line in _read(README).splitlines() if "img.shields.io/pypi" in line
    ]
    assert not badges, f"PyPI badge would render broken: {badges}"


@pytest.mark.parametrize(
    "doc",
    ["README.md", "CONTRIBUTING.md", "action.yml", "Dockerfile"],
)
def test_no_other_public_file_installs_the_short_name(doc):
    path = REPO_ROOT / doc
    if not path.exists():
        pytest.skip(f"{doc} not present")
    assert not SHORT_NAME_INSTALL.search(_read(path)), f"{doc} installs the short name"
