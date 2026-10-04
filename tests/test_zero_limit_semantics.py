"""Tests for the ``0`` vs ``null`` semantics of the global limit fields.

Issue #174: ``max_tool_calls: 0`` and ``max_executions: 0`` were silently
ignored. ``Guard.check`` gated the enforcement behind a truthiness test
(``if self.policy.max_tool_calls and current_count > ...``), and ``0`` is
falsy in Python, so the whole block was skipped and a policy that asked for a
**zero budget** enforced **no limit at all**. The value survived the parser
intact, so ``stats()`` reported ``max_tool_calls: 0`` while every call was
allowed -- a fail-open defect in the enforcement path.

The owner decided the semantics, and the whole suite pins them:

* ``max_tool_calls: 0`` / ``max_executions: 0`` is **DENY ALL** -- an explicit
  zero is a limit of zero, enforced from the very first call. agent-guard is a
  deny-oriented guard, so silently *widening* permissions because someone
  wrote ``0`` is the dangerous direction; failing closed is the safe one.
* ``null`` / absent means **no limit configured** -- unlimited, as before.

The tests are grouped as:

* **Discriminating** -- these fail on the pre-fix code and pass after it. They
  are the RED baseline.
* **Positive controls** -- these pass before and after. They guard against
  "fixing" the bug by turning every limit into a deny-all, and they pin the
  ``null``-means-unlimited half of the contract, which must not move.
* **Regression guard** -- a static check that no consumer reintroduces a
  truthiness test on either field, so a ``0``/``null`` confusion cannot come
  back silently.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from click.testing import CliRunner

import agent_guard
from agent_guard import Guard, Policy, RiskLevel, ToolCall, check_async
from agent_guard.main import cli

ZERO_TOOL_CALLS_POLICY = """
name: zero-limit
description: A policy that permits zero tool calls
default_action: allow
max_tool_calls: 0
rules: []
"""

ZERO_EXECUTIONS_POLICY = """
name: zero-executions
description: A policy that permits zero executions
default_action: allow
max_executions: 0
rules: []
"""


def _policy(body: str) -> Policy:
    return Policy.from_yaml(body)


def _call(resource: str = "x") -> ToolCall:
    return ToolCall(tool="fs_read", resource=resource)


# --------------------------------------------------------------------------
# Discriminating: an explicit 0 is a limit of zero (RED before the fix)
# --------------------------------------------------------------------------


class TestZeroToolCallsDeniesAll:
    def test_zero_max_tool_calls_denies_the_first_call(self) -> None:
        """``max_tool_calls: 0`` must deny on call #1, not silently allow."""
        guard = Guard(_policy(ZERO_TOOL_CALLS_POLICY))
        verdict = guard.check(_call())
        assert verdict.allowed is False, (
            "max_tool_calls: 0 means zero tool calls are permitted; the first "
            f"call was allowed with reason {verdict.reason!r}"
        )
        assert "max_tool_calls" in verdict.reason
        assert verdict.risk is RiskLevel.HIGH

    def test_zero_max_tool_calls_denies_every_call(self) -> None:
        """No call may ever be allowed, however many are attempted."""
        guard = Guard(_policy(ZERO_TOOL_CALLS_POLICY))
        for i in range(5):
            verdict = guard.check(_call(resource=f"r{i}"))
            assert verdict.allowed is False, f"call #{i + 1} was allowed: {verdict.reason!r}"

    def test_zero_limit_is_not_bypassed_by_an_allow_rule(self) -> None:
        """An allow rule must not override the exhausted budget.

        The limit is evaluated before rule matching, so a policy that both
        allows the tool and pins the budget to zero is a deny-all. That is the
        fail-closed ordering the decision depends on.
        """
        guard = Guard(
            _policy("""
name: zero-with-rule
default_action: deny
max_tool_calls: 0
rules:
  - action: allow
    tool: fs_read
    resource: "*"
""")
        )
        verdict = guard.check(_call())
        assert verdict.allowed is False
        assert "max_tool_calls" in verdict.reason

    def test_zero_max_tool_calls_survives_the_parser(self) -> None:
        """The parser must not coerce an explicit 0 into "unset"."""
        policy = _policy(ZERO_TOOL_CALLS_POLICY)
        assert policy.max_tool_calls == 0
        assert policy.max_tool_calls is not None


class TestZeroExecutionsDeniesAll:
    def test_zero_max_executions_denies_the_first_call(self) -> None:
        guard = Guard(_policy(ZERO_EXECUTIONS_POLICY))
        verdict = guard.check(_call())
        assert verdict.allowed is False, (
            "max_executions: 0 means zero executions are permitted; the first "
            f"call was allowed with reason {verdict.reason!r}"
        )
        assert "max_executions" in verdict.reason
        assert verdict.risk is RiskLevel.HIGH

    def test_zero_max_executions_denies_every_call(self) -> None:
        guard = Guard(_policy(ZERO_EXECUTIONS_POLICY))
        for i in range(5):
            verdict = guard.check(_call(resource=f"r{i}"))
            assert verdict.allowed is False, f"call #{i + 1} was allowed: {verdict.reason!r}"

    def test_zero_max_executions_survives_the_parser(self) -> None:
        policy = _policy(ZERO_EXECUTIONS_POLICY)
        assert policy.max_executions == 0
        assert policy.max_executions is not None


class TestZeroLimitIsVisibleToCallers:
    def test_stats_report_a_zero_budget(self) -> None:
        """``stats()`` must not hide the budget, and must not invent one."""
        guard = Guard(_policy(ZERO_TOOL_CALLS_POLICY))
        guard.check(_call())
        stats = guard.stats()
        assert stats.max_tool_calls == 0
        assert stats.get("max_tool_calls") == 0

    def test_cli_check_exits_1_on_a_zero_budget(self, tmp_path: Path) -> None:
        """``agent-guard check`` must exit non-zero, not print a green tick."""
        policy_file = tmp_path / "zero-limit.yaml"
        policy_file.write_text(ZERO_TOOL_CALLS_POLICY, encoding="utf-8")
        result = CliRunner().invoke(
            cli,
            [
                "check",
                str(policy_file),
                "--tool",
                "fs_read",
                "--resource",
                "/etc/hostname",
                "--json",
            ],
        )
        assert result.exit_code == 1, f"expected exit 1, got {result.exit_code}: {result.output}"
        assert '"allowed": false' in result.output
        assert "max_tool_calls" in result.output

    def test_cli_audit_table_shows_a_zero_budget(self, tmp_path: Path) -> None:
        """``audit`` must print the zero limit instead of hiding it.

        The display used a bare truthiness check, so ``max_tool_calls: 0``
        produced an audit report with no limit line at all -- the operator had
        no way to see that a zero budget was configured.
        """
        policy_file = tmp_path / "zero-limit.yaml"
        policy_file.write_text(ZERO_TOOL_CALLS_POLICY, encoding="utf-8")
        result = CliRunner().invoke(cli, ["audit", str(policy_file), "--format", "table"])
        assert result.exit_code == 0, result.output
        assert "Max tool calls: 0" in result.output, result.output

    async def test_check_async_denies_a_zero_budget(self) -> None:
        """The async entry point delegates to ``check``; it must deny too."""
        decision = await check_async(_policy(ZERO_TOOL_CALLS_POLICY), _call())
        assert decision.allowed is False, f"async allowed the call: {decision.reason!r}"
        assert decision.denied is True


# --------------------------------------------------------------------------
# Positive controls: null/absent still means "no limit"
# --------------------------------------------------------------------------


class TestNullMeansNoLimit:
    def test_absent_max_tool_calls_means_no_limit(self) -> None:
        guard = Guard(
            _policy("""
name: unlimited
default_action: allow
rules: []
""")
        )
        for i in range(50):
            verdict = guard.check(_call(resource=f"r{i}"))
            assert verdict.allowed is True, f"call #{i + 1} denied: {verdict.reason!r}"
        assert guard.stats().max_tool_calls is None

    def test_explicit_null_max_tool_calls_means_no_limit(self) -> None:
        policy = _policy("""
name: unlimited
default_action: allow
max_tool_calls: null
rules: []
""")
        assert policy.max_tool_calls is None
        guard = Guard(policy)
        for i in range(50):
            assert guard.check(_call(resource=f"r{i}")).allowed is True

    def test_explicit_null_max_executions_means_no_limit(self) -> None:
        policy = _policy("""
name: unlimited
default_action: allow
max_executions: null
rules: []
""")
        assert policy.max_executions is None
        guard = Guard(policy)
        for i in range(50):
            assert guard.check(_call(resource=f"r{i}")).allowed is True

    def test_absent_max_executions_means_no_limit(self) -> None:
        guard = Guard(
            _policy("""
name: unlimited
default_action: allow
rules: []
""")
        )
        for i in range(50):
            assert guard.check(_call(resource=f"r{i}")).allowed is True
        assert guard.stats().max_executions is None


class TestPositiveLimitsStillLimit:
    """A positive budget must still allow exactly N calls and deny call N+1."""

    @pytest.mark.parametrize("n", [1, 2, 5, 10])
    def test_positive_max_tool_calls_allows_exactly_n_calls(self, n: int) -> None:
        guard = Guard(
            _policy(f"""
name: limited
default_action: allow
max_tool_calls: {n}
rules: []
""")
        )
        for i in range(n):
            verdict = guard.check(_call(resource=f"r{i}"))
            assert verdict.allowed is True, f"call #{i + 1} of {n} denied: {verdict.reason!r}"
        over = guard.check(_call(resource="over"))
        assert over.allowed is False
        assert "max_tool_calls" in over.reason

    @pytest.mark.parametrize("n", [1, 2, 5, 10])
    def test_positive_max_executions_allows_exactly_n_calls(self, n: int) -> None:
        guard = Guard(
            _policy(f"""
name: limited
default_action: allow
max_executions: {n}
rules: []
""")
        )
        for i in range(n):
            assert guard.check(_call(resource=f"r{i}")).allowed is True
        over = guard.check(_call(resource="over"))
        assert over.allowed is False
        assert "max_executions" in over.reason

    def test_zero_and_null_are_distinct_at_the_parser(self) -> None:
        """The 0/null distinction is made at load time and stays visible."""
        zero = _policy(ZERO_TOOL_CALLS_POLICY)
        null = _policy("""
name: unlimited
default_action: allow
max_tool_calls: null
rules: []
""")
        assert zero.max_tool_calls == 0
        assert null.max_tool_calls is None
        assert zero.max_tool_calls != null.max_tool_calls


# --------------------------------------------------------------------------
# Regression guard: no consumer may test either field for truthiness again
# --------------------------------------------------------------------------

LIMIT_FIELDS = frozenset({"max_tool_calls", "max_executions"})

SRC_DIR = Path(agent_guard.__file__).resolve().parent


def _source_files() -> list[Path]:
    return sorted(p for p in SRC_DIR.glob("*.py"))


def _is_limit_reference(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr in LIMIT_FIELDS
    if isinstance(node, ast.Name):
        return node.id in LIMIT_FIELDS
    return False


def _truthiness_positions(tree: ast.AST) -> list[ast.AST]:
    """Every node whose value is used as a boolean, in any module."""
    positions: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If | ast.While | ast.IfExp | ast.Assert):
            positions.append(node.test)
        elif isinstance(node, ast.comprehension):
            positions.extend(node.ifs)
    return positions


def _bare_limit_refs(node: ast.AST) -> list[ast.AST]:
    """Limit references inside *node* that are not part of a comparison.

    Descends from *node* but stops at ``Compare``, so ``limit is not None`` and
    ``count > limit`` -- explicit comparisons, where ``0`` cannot be conflated
    with "unset" -- are not reported. What is left is a field evaluated as a
    bare boolean, which is exactly the bug this file guards against.
    """
    found: list[ast.AST] = []
    stack: list[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Compare):
            continue
        if _is_limit_reference(current):
            found.append(current)
            continue
        stack.extend(ast.iter_child_nodes(current))
    return found


def test_source_files_are_found() -> None:
    """The guard below is vacuous if it cannot see the sources it polices."""
    files = _source_files()
    assert files, f"no python sources found under {SRC_DIR}"
    assert any(f.name == "__init__.py" for f in files)


@pytest.mark.parametrize("source", _source_files(), ids=lambda p: p.name)
def test_no_truthiness_test_on_a_limit_field(source: Path) -> None:
    """Neither limit may be tested as a bare boolean anywhere in ``src/``.

    ``if policy.max_tool_calls and ...`` is what made ``0`` mean "no limit".
    Any future consumer that reaches for the value directly -- an enforcement
    site, a display site, a coercion helper -- fails here instead of silently
    widening permissions.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    offenders = []
    for position in _truthiness_positions(tree):
        offenders.extend(_bare_limit_refs(position))
    assert not offenders, (
        f"{source.name} evaluates a limit field as a bare boolean at "
        f"{[getattr(o, 'lineno', '?') for o in offenders]}; compare it against "
        "None explicitly so an explicit 0 is not read as 'no limit configured'"
    )


@pytest.mark.parametrize("source", _source_files(), ids=lambda p: p.name)
def test_no_bool_call_on_a_limit_field(source: Path) -> None:
    """``bool(limit)`` collapses the same distinction; forbid it too."""
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    offenders = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "bool"
        ):
            continue
        if any(_is_limit_reference(arg) for arg in node.args):
            offenders.append(node)
    assert not offenders, (
        f"{source.name} wraps a limit field in bool() at "
        f"{[o.lineno for o in offenders]}; that discards the 0-vs-null distinction"
    )


@pytest.mark.parametrize("source", _source_files(), ids=lambda p: p.name)
def test_no_default_supplied_when_reading_a_limit_field(source: Path) -> None:
    """``data.get("max_tool_calls", <default>)`` cannot express "unset".

    An absent key must stay ``None``; supplying a default turns an omitted
    field into a number, and ``0`` is now a real limit rather than a stand-in
    for "not configured".
    """
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    offenders = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value in LIMIT_FIELDS
            and len(node.args) > 1
        ):
            continue
        offenders.append(node)
    assert not offenders, (
        f"{source.name} reads a limit field with a default at "
        f"{[o.lineno for o in offenders]}; omit the key and let None mean "
        "'no limit configured'"
    )
