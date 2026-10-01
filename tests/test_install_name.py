"""Regression guards for the documented install instructions.

The distribution name is read from ``[project] name`` in pyproject.toml, never
hardcoded, so a future rename cannot leave the docs pointing at a package that
does not exist. Two facts are pinned here:

1. Nothing is published on PyPI yet, so the docs must install from git. A bare
   ``pip install <name>`` line in the docs is a 404 for the reader.
2. The name ``agent-guard`` on PyPI belongs to an unrelated third-party project,
   so it must never be offered as an install target either.

Note the repo name and the distribution name differ: the repo is ``agent-guard``
(also the console script), the distribution is ``agentperm-py``.

Rule 1 is deliberately the one that flips on publication. Publishing is gated on
creating the project on PyPI and registering a trusted publisher; once
``pip install agentperm-py`` resolves, the git line becomes unnecessary and the
bare install becomes correct. Flip ``PUBLISHED`` in that same commit -- do not
leave a guard that forces one of two wrong states.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest
import tomllib

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"

# Flip to True in the same commit that restores the PyPI install line, once
# https://pypi.org/pypi/<the [project] name>/json answers 200.
PUBLISHED = False

# Every tracked surface a reader can copy an install line out of.
DOC_SURFACES = (
    "README.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "action.yml",
    ".pre-commit-hooks.yaml",
    "Dockerfile",
    "SECURITY.md",
)

_PYPROJECT = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
DIST_NAME: str = _PYPROJECT["project"]["name"]

# The repository name -- which is also the console script name and the name of
# the third-party PyPI project.
REPO_NAME = "agent-guard"

EXPECTED_INSTALL = (
    f"pip install {DIST_NAME}"
    if PUBLISHED
    else f"pip install git+https://github.com/yunaremaia/{REPO_NAME}.git"
)

# Install targets that must never appear. While unpublished, a bare
# `pip install agentperm-py` 404s just like the short name does; the short name
# fails worse, by silently installing another author's project.
FORBIDDEN_TARGETS = {REPO_NAME} | (set() if PUBLISHED else {DIST_NAME})

# `pip install`, `pip3 install`, `uv tool install`, `uv pip install` and
# `python -m pip install`, plus everything after them on the line.
INSTALL_COMMAND = re.compile(
    r"(?:uv\s+(?:tool|pip)|pip3?|python3?\s+-m\s+pip)\s+install(?P<args>[^\n]*)",
    re.MULTILINE,
)

# A PEP 508 requirement: a bare name, optional extras, optional version spec.
#
# The negative lookahead `(?![\w.-])` is load-bearing. A plain substring check
# for "pip install agent-guard" is True for "pip install agent-guard-py", so the
# naive grep would flag the very line it is meant to protect. Anchoring the name
# and refusing to stop mid-token keeps the two apart.
#
# This also rejects, for free, every target that is not a bare name: a `git+`
# URL fails the spec part at the `+`, and `.` / `.[dev]` never start with an
# alphanumeric.
REQUIREMENT = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?![\w.-])"
    r"(?P<spec>\[[^\]]*\])?(?:[<>=!~].*)?$"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _requirement_name(token: str) -> str | None:
    """Return the distribution name a pip target token names, if it names one."""
    match = REQUIREMENT.match(token)
    return match.group("name") if match else None


def install_targets(line: str) -> list[str]:
    """Return the distribution names pip would be handed by an install command."""
    names = []
    for command in INSTALL_COMMAND.finditer(line):
        try:
            tokens = shlex.split(command.group("args"))
        except ValueError:
            tokens = command.group("args").split()
        for token in tokens:
            if token.startswith("-"):  # -e, --upgrade, -r, --no-cache-dir ...
                continue
            name = _requirement_name(token)
            if name is not None:
                names.append(name)
    return names


def bare_install_lines(text: str) -> list[str]:
    """Return every line in *text* that installs a forbidden bare target.

    Only the tokens pip would actually receive are considered, so options and
    their values never register: a legitimate `git clone` + `pip install -e .`
    from-source block cannot show up as an offender.
    """
    return [
        line.strip()
        for line in text.splitlines()
        if FORBIDDEN_TARGETS.intersection(install_targets(line))
    ]


def doc_surfaces() -> list[tuple[str, Path]]:
    """The DOC_SURFACES that exist in this checkout."""
    return [(name, REPO_ROOT / name) for name in DOC_SURFACES if (REPO_ROOT / name).exists()]


class TestDocsInstallFromGitWhileUnpublished:
    """The expected install line is asserted first, so a failure names the fix."""

    def test_readme_carries_the_expected_install_line(self):
        assert EXPECTED_INSTALL in _read(README), f"README must carry `{EXPECTED_INSTALL}`"


class TestNoBarePyPIInstallAnywhere:
    def test_surfaces_were_found(self):
        """Guard the guard: an empty surface list would assert nothing."""
        found = doc_surfaces()
        assert found, f"none of {DOC_SURFACES} exists -- the surface list is stale"
        assert "README.md" in [name for name, _ in found]
        assert "CONTRIBUTING.md" in [name for name, _ in found], (
            "CONTRIBUTING.md carries the from-source block, so a stale surface "
            "list would be a false GREEN"
        )

    def test_no_surface_installs_a_forbidden_bare_name(self):
        offenders = {
            name: lines[:5] for name, path in doc_surfaces() if (lines := bare_install_lines(_read(path)))
        }
        offenders = {name: lines for name, lines in offenders.items() if lines}
        assert not offenders, (
            f"these files tell readers to `pip install` {sorted(FORBIDDEN_TARGETS)}, which on "
            f"PyPI is not this project. Use `{EXPECTED_INSTALL}`. "
            f"Offending files and lines: {offenders}"
        )

    def test_no_pypi_badge_while_unpublished(self):
        """A PyPI badge renders "not found" for a package that is not on PyPI."""
        badges = [line for line in _read(README).splitlines() if "img.shields.io/pypi" in line]
        assert not badges, f"PyPI badge would render broken: {badges}"


class TestTargetParsing:
    """Literal inputs, so editing a constant above cannot make these pass."""

    def test_git_install_is_not_a_bare_name(self):
        line = "pip install git+https://github.com/yunaremaia/agent-guard.git"
        assert install_targets(line) == []
        assert bare_install_lines(line) == []

    def test_short_name_is_a_bare_name(self):
        assert install_targets("pip install agent-guard") == ["agent-guard"]
        assert bare_install_lines("pip install agent-guard")

    def test_uv_and_pip3_variants_are_covered(self):
        for line in ("uv tool install agent-guard", "uv pip install agent-guard", "pip3 install agent-guard"):
            assert bare_install_lines(line), line

    def test_unrelated_packages_are_not_caught(self):
        for line in (
            "pip install pre-commit",
            "python -m pip install --upgrade pip",
            "python -m pip install build twine",
        ):
            assert install_targets(line) and not bare_install_lines(line), line

    def test_from_source_blocks_are_not_caught(self):
        """`git clone` + `pip install -e .` is a legitimate install, not a lie."""
        for line in (
            "pip install -e .",
            'pip install -e ".[dev]"',
            "pip install -r requirements.txt",
            "RUN pip install --no-cache-dir .",
        ):
            assert not bare_install_lines(line), line

    def test_bare_distribution_name_is_forbidden_while_unpublished(self):
        """`-py` is still a bare install target, and it still 404s."""
        line = "pip install agentperm-py"
        assert install_targets(line) == ["agentperm-py"]
        assert bool(bare_install_lines(line)) is not PUBLISHED


class TestTheRegexIsNotANaiveSubstringCheck:
    def test_a_substring_check_could_not_separate_the_two_names(self):
        """Documents the trap this guard exists to avoid.

        The needle is built from the repo name, so the check reads as the naive
        grep it warns about rather than as two unrelated literals.
        """
        needle = f"pip install {REPO_NAME}"
        assert needle in f"{needle}-py"

    def test_the_requirement_parser_does_separate_them(self):
        assert _requirement_name("agent-guard-py") == "agent-guard-py"
        assert _requirement_name("agent-guard") == "agent-guard"
        assert _requirement_name("git+https://github.com/yunaremaia/agent-guard.git") is None


class TestReadmeDisclosesTheNameSituation:
    """A reader who sees `agentperm-py` deserves to know what is going on."""

    def test_short_name_is_disclosed_as_foreign(self):
        text = _read(README).lower()
        assert REPO_NAME in text
        assert "pypi" in text
        assert any(
            phrase in text for phrase in ("different author", "another author", "unrelated", "taken")
        ), "README must say the agent-guard PyPI name belongs to another project"

    def test_unpublished_state_is_disclosed(self):
        """Otherwise a git URL in the install block reads as a mistake."""
        text = _read(README).lower()
        assert any(
            phrase in text for phrase in ("not published", "not yet on pypi", "not yet published")
        ), "README must state the project is not on PyPI yet, so the git URL is expected"


class TestPackaging:
    def test_console_script_name_is_the_repo_name(self):
        """Only the distribution moves; the command a user types does not."""
        assert REPO_NAME in _PYPROJECT["project"]["scripts"], (
            f"console script must stay `{REPO_NAME}`; only the distribution "
            f"carries the `-py` suffix"
        )

    def test_import_module_is_unchanged(self):
        packages = _PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
        assert any(p.endswith("agent_guard") for p in packages), packages

    def test_console_script_target_is_importable(self):
        """The entry point must resolve against the built wheel, not the source tree.

        It once pointed at `src.main:cli`, a path that does not exist in the wheel
        (only the `agent_guard` package is packaged, with `src/` as its import root),
        so every install shipped a console script that raised ModuleNotFoundError.
        """
        target = _PYPROJECT["project"]["scripts"][REPO_NAME]
        module_path, _, attr = target.partition(":")

        # hatchling `packages = ["src/agent_guard"]` installs `agent_guard/` into
        # the wheel root, so `src/` is the directory that goes on sys.path.
        packaged = _PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
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
        assert re.search(rf"^def {re.escape(attr)}\b", source, re.MULTILINE), (
            f"{target} does not define {attr}() in {resolved.name}"
        )


@pytest.mark.parametrize("line", ["pip install pre-commit", "pip install -e ."])
def test_parser_noise_is_not_reported(line):
    """Explicitly assert the two shapes that produced false positives before."""
    assert bare_install_lines(line) == []