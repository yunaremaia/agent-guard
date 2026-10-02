r"""ReDoS (Regular Expression Denial of Service) protection for policy patterns.

Users supply regex patterns through policy documents -- primarily a rule's
``resource`` pattern, and any tool or argument pattern a rule evaluates. A
pattern with catastrophic backtracking (a quantifier applied to a construct
that can itself match the same text in more than one way) can make policy
evaluation hang, which is a denial of service against the guard.

This module refuses the shapes that actually blow up, and nothing else. A
detector that also refuses ordinary patterns -- an anchored URL, a character
class, a bounded ``{2,4}`` -- would be worse than useless in a policy engine,
so every rule below is stated in terms of *ambiguity*, not merely the
presence of parentheses or a ``+``.

Refused shapes
--------------

1. **Nested quantifier** -- a repeating quantifier (``*``, ``+``, ``{n,}``,
   or any ``{m,n}`` with ``n >= 2``) applied to a group whose body already
   contains a quantifier and cannot be re-partitioned: ``(a+)+``, ``(a*)*``,
   ``(a?)+``, ``(.*)*``, ``((a|b)+)+``, ``(a{1,2})+``, ``(\d+)+``. This is the
   exponential case: the group's text can be split among its repetitions in
   many ways, and a failing match forces the engine to try all of them.

   The group is only reported when the body has no *pinned* separator. If the
   body ends with a mandatory atom whose character set is disjoint from every
   inner quantifier, each iteration consumes exactly that separator and the
   boundaries are forced, so the pattern is left alone. That is the whole
   difference between ``(a+)+`` and the ordinary hostname form
   ``(?:[a-z0-9-]+\\.)+``, where the trailing ``.`` cannot be matched by the
   inner class.

2. **Ambiguous alternation under repetition** -- a repeated group whose
   branches can begin with the same text: ``(a|a)*``, ``(a|ab)*``,
   ``(foo|foobar)*``, ``(\d|\d)*``. Disjoint branches such as ``(cat|dog)+``
   are left alone, and so is ``(get|set)_\w+``.

3. **Large unbounded repetition** -- ``{n,}`` with ``n`` at or above
   :data:`MAX_REPEAT_FLOOR`, which forces expansion of a very large minimum
   match (``[a-z]{100,}``).

4. **Excessive length** -- longer than :data:`MAX_PATTERN_LENGTH`.

Kept working
------------

``(a+)``, ``a*``, ``\d{2,4}``, ``[a-z]+``, ``(.*?)``, ``(?:abc)+``,
``(cat|dog)``, ``(cat|dog)+``, ``(a+)?`` (an *optional* group adds a constant
factor rather than an exponential), escaped literals such as ``a\+b``, and
ordinary patterns like ``^https://[a-z0-9.-]+(:[0-9]+)?/.*$``.

Limitations
-----------

* There is deliberately no ``compile_with_timeout`` helper here. CPython's
  :mod:`re` has no ``timeout`` parameter -- ``re.compile(pattern,
  timeout=1.0)`` raises ``TypeError`` on every supported version; only the
  third-party ``regex`` module offers one. Execution is instead bounded at the
  call site by the thread-with-timeout guard in
  :meth:`agent_guard.Rule.matches_resource`, which needs no new dependency.
* Analysis is one bounded pass, not a proof of polynomial backtracking
  complexity. It cannot see ambiguity that arises only through a *chain* of
  separate quantifiers, such as ``a*a*`` or ``(x+x+)+``. Those are not
  reported here; the execution-time guard remains the backstop for anything
  this pass misses.
* Constructs the scanner does not model precisely (conditional groups,
  backreferences, class subtraction) degrade the affected first character to
  "unknown". Unknown is treated as potentially overlapping, so a pattern
  such as ``(?(1)a|b)+`` may be refused conservatively. That errs toward
  refusing a rare exotic pattern, not a common one.
* The scan is iterative with a hard depth and step budget, so a hostile
  pattern of thousands of nested groups cannot exhaust the interpreter
  stack. A pattern that exhausts the budget is reported **unsafe** (fail
  closed): an unanalyzed pattern cannot be certified safe.
"""

from __future__ import annotations

import string
from collections.abc import Iterator

MAX_PATTERN_LENGTH = 100
"""Maximum accepted pattern length, in characters."""

MAX_REPEAT_FLOOR = 100
"""Smallest ``{n,}`` lower bound treated as a resource-exhaustion vector."""

MAX_SCAN_DEPTH = 100
"""Maximum group nesting depth before a pattern is abandoned as unsafe."""

MAX_SCAN_STEPS = 20_000
"""Maximum scanner steps before a pattern is abandoned as unsafe."""

REGEX_MARKERS = frozenset("^$|()+?{}")
"""Characters that make a pattern worth analysing as a regex.

A pattern containing none of these is a plain glob and never reaches the
analyzer.
"""

_ESCAPE_CLASSES: dict[str, frozenset[str]] = {
    "d": frozenset(string.digits),
    "w": frozenset(string.ascii_letters + string.digits + "_"),
    "s": frozenset(" \t\n\r\f\v"),
}

_QUANT_CHARS = frozenset("*+?{")


class _Atom:
    """One element of a pattern: a literal, a class, a group, or an anchor."""

    __slots__ = ("body_has_quant", "branches", "first", "kind", "quant", "start")

    def __init__(
        self,
        kind: str,
        *,
        quant: tuple[int, int | None] | None = None,
        branches: list[list[_Atom]] | None = None,
        first: frozenset[str] | None = None,
        start: int = 0,
        body_has_quant: bool = False,
    ) -> None:
        self.kind = kind
        # (low, high); high is None for an unbounded {n,}
        self.quant = quant
        self.branches = branches if branches is not None else []
        self.first = first
        self.start = start
        self.body_has_quant = body_has_quant

    @property
    def repeats(self) -> bool:
        """True when this atom's quantifier can apply two or more times."""
        if self.quant is None:
            return False
        _, high = self.quant
        return high is None or high >= 2

    @property
    def nullable(self) -> bool:
        """True when this atom can match the empty string."""
        if self.quant is None:
            return False
        return self.quant[0] == 0

    @property
    def quant_text(self) -> str:
        if self.quant is None:
            return ""
        low, high = self.quant
        if high is None:
            if low == 0:
                return "*"
            return "+" if low == 1 else f"{{{low},}}"
        if high == 1 and low == 0:
            return "?"
        if low == high:
            return f"{{{low}}}"
        return f"{{{low},{high}}}"

    def walk(self) -> Iterator[_Atom]:
        """Yield this atom and every atom nested inside it."""
        yield self
        for branch in self.branches:
            for atom in branch:
                yield from atom.walk()


class _Frame:
    """One open group's parse state."""

    __slots__ = ("branches", "firsts", "start")

    def __init__(self, start: int) -> None:
        self.branches: list[list[_Atom]] = [[]]
        self.firsts: list[frozenset[str] | None] = [None]
        self.start = start


def _parse_repeat(pattern: str, i: int) -> tuple[int, int | None, int] | None:
    """Parse a ``{m,n}`` quantifier at *i*; return ``(low, high, next)`` or None."""
    close = pattern.find("}", i)
    if close == -1:
        return None
    body = pattern[i + 1 : close]
    if not body:
        return None
    low_s, comma, high_s = body.partition(",")
    if low_s and not low_s.isdigit():
        return None
    if high_s and not high_s.isdigit():
        return None
    low = int(low_s) if low_s else 0
    if not comma:
        high: int | None = low
    else:
        high = int(high_s) if high_s else None
    if high is not None and high < low:
        return None
    return low, high, close + 1


def _skip_group_prefix(pattern: str, i: int) -> int:
    """Skip a ``(?...)`` prefix; *i* points at the ``?``."""
    j = i + 1
    if j >= len(pattern):
        return j
    ch = pattern[j]
    if ch in ":=!":
        return j + 1
    if ch == "<":
        return j + 2 if pattern[j + 1 : j + 2] in ("=", "!") else pattern.find(">", j) + 1
    if ch == "P":
        if pattern[j + 1 : j + 2] == "<":
            return pattern.find(">", j) + 1
        return j + 1
    if ch == "#":
        end = pattern.find(")", j)
        return len(pattern) if end == -1 else end
    return j


def _scan_class(pattern: str, i: int) -> tuple[frozenset[str] | None, int]:
    """Scan a character class starting at *i*; return ``(first_chars, next)``.

    ``first_chars`` is the set of characters the class can match (which for a
    class is also its set of possible first characters), or None when the class
    is too large, negated, or otherwise not enumerable.
    """
    j = i + 1
    negated = pattern[j : j + 1] == "^"
    if negated:
        j += 1
    chars: set[str] = set()
    enumerable = not negated
    n = len(pattern)
    while j < n and pattern[j] != "]":
        if pattern[j] == "\\":
            esc = pattern[j + 1 : j + 2]
            if esc in _ESCAPE_CLASSES:
                enumerable = False
            else:
                chars.add(esc or "\\")
            j += 2
            continue
        if pattern[j + 1 : j + 2] == "-" and pattern[j + 2 : j + 3] not in ("]", ""):
            lo = pattern[j]
            hi = pattern[j + 2]
            if lo > hi or ord(hi) - ord(lo) > 1024:
                enumerable = False
            else:
                chars.update(chr(c) for c in range(ord(lo), ord(hi) + 1))
            j += 3
            continue
        chars.add(pattern[j])
        j += 1
    if not enumerable or not chars or len(chars) > 4096:
        return None, min(j + 1, n)
    return frozenset(chars), min(j + 1, n)


def _branches_nullable(branches: list[list[_Atom]]) -> bool:
    """True when every branch of a group body can match the empty string."""
    for branch in branches:
        if not branch or branch[0].nullable:
            continue
        return False
    return True


def _branch_first(branch: list[_Atom]) -> frozenset[str] | None:
    if not branch:
        return frozenset()
    return branch[0].first


def _group_first(branches: list[list[_Atom]]) -> frozenset[str] | None:
    """First characters a group can produce, or None when unknown."""
    if _branches_nullable(branches):
        return None
    acc: set[str] = set()
    for branch in branches:
        if not branch:
            return None
        first = _first_of(branch[0])
        if first is None:
            return None
        acc |= first
    return frozenset(acc)


def _first_of(atom: _Atom) -> frozenset[str] | None:
    if atom.kind == "group":
        return _group_first(atom.branches)
    return atom.first


def _scan(pattern: str) -> list[_Atom] | None:
    """One bounded pass over *pattern*; None when a budget is exhausted."""
    stack: list[_Frame] = [_Frame(0)]
    steps = 0
    i = 0
    n = len(pattern)

    while i < n:
        steps += 1
        if steps > MAX_SCAN_STEPS or len(stack) > MAX_SCAN_DEPTH:
            return None
        ch = pattern[i]

        if ch == "\\":
            esc = pattern[i + 1 : i + 2]
            if not esc:
                i += 1
                continue
            if esc in _ESCAPE_CLASSES:
                atom = _Atom("class", first=_ESCAPE_CLASSES[esc], start=i)
            elif esc in "DWSB":
                atom = _Atom("class", first=None, start=i)
            else:
                atom = _Atom("lit", first=frozenset(esc), start=i)
            stack[-1].branches[-1].append(atom)
            if len(stack[-1].branches[-1]) == 1:
                stack[-1].firsts[-1] = atom.first
            i += 2
            continue

        if ch == "[":
            first, i = _scan_class(pattern, i)
            atom = _Atom("class", first=first, start=i)
            branch = stack[-1].branches[-1]
            branch.append(atom)
            if len(branch) == 1:
                stack[-1].firsts[-1] = first
            continue

        if ch == "(":
            j = _skip_group_prefix(pattern, i + 1) if pattern[i + 1 : i + 2] == "?" else i + 1
            stack.append(_Frame(i))
            i = j
            continue

        if ch == "|" and len(stack) > 1:
            stack[-1].branches.append([])
            stack[-1].firsts.append(None)
            i += 1
            continue

        if ch == ")" and len(stack) > 1:
            frame = stack.pop()
            branches = frame.branches
            inner = any(a.quant is not None for b in branches for a in b) or any(
                a.kind == "group" and a.body_has_quant for b in branches for a in b
            )
            group = _Atom(
                "group",
                branches=branches,
                first=_group_first(branches),
                start=frame.start,
                body_has_quant=inner,
            )
            branch = stack[-1].branches[-1]
            branch.append(group)
            if len(branch) == 1:
                stack[-1].firsts[-1] = group.first
            i += 1
            continue

        if ch in _QUANT_CHARS:
            if ch == "{":
                parsed = _parse_repeat(pattern, i)
                if parsed is None:
                    stack[-1].branches[-1].append(
                        _Atom("lit", first=frozenset("{"), start=i)
                    )
                    i += 1
                    continue
                quant = (parsed[0], parsed[1])
                nxt = parsed[2]
            elif ch == "?":
                quant, nxt = (0, 1), i + 1
            elif ch == "+":
                quant, nxt = (1, None), i + 1
            else:
                quant, nxt = (0, None), i + 1
            if pattern[nxt : nxt + 1] in ("?", "+"):
                nxt += 1
            branch = stack[-1].branches[-1]
            if branch:
                branch[-1].quant = quant
            else:
                # A quantifier with nothing to quantify: keep it as a literal
                # so an incomplete pattern is reported, not silently dropped.
                branch.append(_Atom("lit", first=frozenset(ch), start=i))
            i = nxt
            continue

        if ch in "^$":
            atom = _Atom("anchor", first=frozenset(), start=i)
        elif ch == ".":
            atom = _Atom("dot", first=None, start=i)
        else:
            atom = _Atom("lit", first=frozenset(ch), start=i)
        branch = stack[-1].branches[-1]
        branch.append(atom)
        if len(branch) == 1:
            stack[-1].firsts[-1] = atom.first
        i += 1

    # Unclosed groups: treat every remaining open frame as closed so the
    # caller still gets a usable (if partial) parse.
    while len(stack) > 1:
        _close_frame(stack)

    return stack[0].branches[0]


def _close_frame(stack: list[_Frame]) -> _Atom:
    """Pop *stack*'s top frame and return the group atom it describes."""
    frame = stack.pop()
    inner = any(a.quant is not None for b in frame.branches for a in b) or any(
        a.kind == "group" and a.body_has_quant for b in frame.branches for a in b
    )
    group = _Atom(
        "group",
        branches=frame.branches,
        first=_group_first(frame.branches),
        start=frame.start,
        body_has_quant=inner,
    )
    branch = stack[-1].branches[-1]
    branch.append(group)
    if len(branch) == 1:
        stack[-1].firsts[-1] = group.first
    return group


def _check_atoms(atoms: list[_Atom], pattern: str) -> str | None:
    """Return a rejection reason for *atoms*, or None when the pattern is safe."""
    for atom in atoms:
        # Rule 3: a large unbounded repetition floor, anywhere in the pattern.
        if atom.quant is not None:
            low, high = atom.quant
            if high is None and low >= MAX_REPEAT_FLOOR:
                ctx = pattern[max(0, atom.start - 24) : atom.start + 1]
                return (
                    f"unbounded repetition {{{low},}} in {ctx!r} requires at least "
                    f"{low} characters (limit is {MAX_REPEAT_FLOOR})"
                )
        if atom.kind != "group":
            continue
        frag = pattern[atom.start : _group_end(pattern, atom.start)]
        # Rule 1: a repeated group whose body already contains a quantifier.
        # Skipped when the body carries a mandatory separator that the inner
        # quantifier cannot absorb, which pins each iteration's boundaries --
        # that is the difference between `(a+)+` (explosive) and the ordinary
        # `(?:[a-z0-9-]+\.)+` hostname form (safe).
        if atom.repeats and atom.body_has_quant and not _is_pinned(atom):
            return (
                f"nested quantifier: group {frag!r} contains a quantifier and is "
                f"itself repeated by {atom.quant_text!r} (catastrophic backtracking)"
            )
        # Rule 2: a repeated group whose branches can start with the same text.
        if atom.repeats and len(atom.branches) > 1:
            overlap = _overlapping_branches(atom)
            if overlap == "unknown":
                return (
                    f"ambiguous alternation: group {frag!r} is repeated by "
                    f"{atom.quant_text!r} and its branches are not provably disjoint"
                )
            if overlap:
                return (
                    f"ambiguous alternation: group {frag!r} is repeated by "
                    f"{atom.quant_text!r} and its branches overlap on {overlap!r}"
                )
        nested = _check_atoms([a for b in atom.branches for a in b], pattern)
        if nested is not None:
            return nested
    return None


def _is_pinned(atom: _Atom) -> bool:
    """True when a repeated group cannot be re-partitioned across iterations.

    A nested quantifier is only explosive when the group body has more than
    one way to consume the same text. It has exactly one way when the body
    ends with a mandatory atom whose character set is disjoint from every
    inner quantifier in the body -- that atom pins where each iteration
    begins and ends.

    ``(a+)+`` ends with ``a+`` itself, which overlaps, so the engine can
    split ``aaaa`` as one run of four, two of two, or four of one. But
    ``(?:[a-z0-9-]+\\.)+`` ends with a literal ``.`` that the inner class
    cannot match, so every iteration consumes exactly one dot and the
    boundaries are forced. The same holds for ``( [a-z0-9]+)*``, where the
    leading space is a mandatory separator no inner class can match.

    Returns False (i.e. treat as explosive) whenever the trailing atom's
    character set cannot be determined, so an unfamiliar shape fails closed.
    """
    for branch in atom.branches:
        quantified = [a for a in branch if a.quant is not None]
        if not quantified:
            continue
        # The separator is the branch's last mandatory atom: whatever must be
        # consumed at the end of every iteration.
        separator = None
        for member in reversed(branch):
            if member.quant is None and member.kind != "anchor":
                separator = member
                break
        if separator is None:
            # Every atom is itself quantified, so the iteration boundary can
            # fall anywhere: `(a+)+`.
            return False
        sep_chars = _separator_chars(separator)
        if sep_chars is None or not sep_chars:
            return False
        for inner in quantified:
            absorbed = _absorbed_chars(inner)
            if absorbed is None or sep_chars & absorbed:
                return False
    return True


def _separator_chars(atom: _Atom) -> frozenset[str] | None:
    """Characters a mandatory separator atom matches, or None if undeterminable.

    The separator is unquantified, so it must consume exactly one character
    per iteration; a wildcard or negated class reports None.
    """
    if atom.quant is not None:
        return None
    if atom.kind in ("lit", "class", "anchor"):
        return atom.first
    if atom.kind == "group" and len(atom.branches) == 1 and len(atom.branches[0]) == 1:
        return _separator_chars(atom.branches[0][0])
    return None


def _absorbed_chars(atom: _Atom) -> frozenset[str] | None:
    """Characters an inner quantifier can consume, ignoring how many times.

    This is the character set the quantifier is *applied to*, so ``[a-z]+`` and
    ``[a-z]{2,}`` both report the letters. A wildcard or negated class reports
    None because it can absorb anything, which must not be treated as disjoint
    from a separator.
    """
    if atom.kind in ("lit", "class"):
        return atom.first
    if atom.kind == "group" and len(atom.branches) == 1 and len(atom.branches[0]) == 1:
        return _absorbed_chars(atom.branches[0][0])
    return None



def _overlapping_branches(atom: _Atom) -> str | list[str] | None:
    """Describe how a repeated group's branches collide.

    Returns ``"unknown"`` when any branch's first character cannot be
    determined, an empty list when the branches are provably disjoint, or the
    sorted characters two branches share.
    """
    sets: list[frozenset[str] | None] = [
        _branch_first(b) for b in atom.branches
    ]
    if any(s is None for s in sets):
        return "unknown"
    for a_idx, first in enumerate(sets):
        for second in sets[a_idx + 1 :]:
            shared = first & second  # type: ignore[operator]
            if shared:
                return sorted(shared)[:4]
    return None


def _group_end(pattern: str, start: int) -> int:
    """Index just past the ``)`` closing the group that opens at *start*."""
    depth = 0
    i = start
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            _, i = _scan_class(pattern, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def looks_like_regex(pattern: str) -> bool:
    """True when *pattern* should be analysed as a regex rather than a glob."""
    return any(c in pattern for c in REGEX_MARKERS)


def is_safe_pattern(
    pattern: str, max_length: int = MAX_PATTERN_LENGTH
) -> tuple[bool, str | None]:
    """Check a user-supplied regex for catastrophic backtracking.

    Args:
        pattern: The user-supplied regex pattern.
        max_length: Maximum accepted pattern length.

    Returns:
        ``(True, None)`` when the pattern is safe, otherwise
        ``(False, reason)`` where *reason* names the dangerous construct.
    """
    if len(pattern) > max_length:
        return False, (
            f"pattern length {len(pattern)} exceeds the maximum of {max_length}"
        )
    atoms = _scan(pattern)
    if atoms is None:
        return False, (
            "pattern could not be analyzed within the scan budget "
            f"({MAX_SCAN_STEPS} steps, depth {MAX_SCAN_DEPTH}); refused as unsafe"
        )
    reason = _check_atoms(atoms, pattern)
    if reason is not None:
        return False, reason
    return True, None
