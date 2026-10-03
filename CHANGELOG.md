# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Recursive `**` globs now match zero path segments (#175)** — `**` is
  handled by a `partition("**/")` split that has no case for a *trailing*
  `**`: `"/home/**"` contains no `"/**/"`, so the whole literal pattern landed
  in `prefix` and the check degenerated to `res.startswith("/home/**")`, which
  is true for no real path. Every `**` pattern that does not end in `*/`
  therefore matched nothing — a `deny` rule on `/home/**` silently failed open
  under `default_action: allow`, and the README's own templates
  (`./research/**`, `./deploy/**`, `./.github/**`, `../**`) were dead as
  written. Resource patterns are now matched segment-wise, so `**` matches
  zero or more path segments per standard globstar/`.gitignore` semantics:
  `/home/**` matches `/home`, `/home/a` and `/home/a/b`; a bare `**` matches
  everything including the root path. A single `*` still stays inside its own
  segment, and regex patterns are untouched.
- **Domain policies are no longer bypassed by removing the scheme (#176)** —
  `allowed_domains` and `blocked_domains` were only enforced when a network
  tool's resource contained `://` or began with `www.`. Every other spelling of
  the same host (`metadata.internal.corp`, `//metadata.internal.corp`,
  `metadata.internal.corp:8443/x`, `HTTPS://METADATA.INTERNAL.CORP`,
  `https://user:secret@metadata.internal.corp/latest`) left the extracted host
  empty, which skipped the entire block containing *both* the blocklist and the
  allowlist checks, and the verdict then reported `domain ok, allow by rule` —
  claiming a check that never ran. Hosts are now parsed with
  `urllib.parse.urlsplit` (userinfo stripped, port dropped, host lower-cased)
  and a resource that cannot be reduced to a host now fails closed whenever a
  domain policy is configured.

## [0.1.0] - 2026-10-03

First tagged release. Everything below shipped to `main` over 46 commits and
16 merged pull requests; this release marks the commit where that work is
declared stable enough to install and depend on.

### Added

- **Policy-as-code core** — YAML policy documents with `default_action`
  (deny-by-default), ordered `rules`, and first-match-wins evaluation
  semantics modelled on firewall rule sets.
- **`Rule` matching** — glob wildcards in tool names (`fs.*` matches `fs.read`,
  `fs.write`) plus glob *and* regex support for resource patterns.
- **Network domain controls** — `allowed_domains` / `blocked_domains`
  allowlist and blocklist enforcement for network tools.
- **Execution limits** — `max_tool_calls` and `max_executions` bound how much
  an agent session may do; calls past the limit are denied.
- **Risk scoring** — every `Verdict` carries a `LOW` / `MEDIUM` / `HIGH` /
  `CRITICAL` risk level derived from the tool and resource.
- **`ToolCall` / `Verdict` / `PolicyDecision` / `PolicyViolation`** — library
  types for representing calls, results, and deny-on-violation raising.
- **Async API** — `Guard.check_async()`, `Guard.check_batch_async()`,
  `Policy.from_file_async()`, and module-level `check_async()` /
  `check_batch_async()` for concurrent evaluation (#89).
- **Session lifecycle** — `Guard.reset()` and `Guard.stats()` returning
  `GuardStats`, so suites and long-lived agents can reset and inspect a guard
  between runs (#95).
- **CLI** — the `agent-guard` command with four subcommands: `check`, `explain`,
  `audit`, and `init`. Human-readable and `--json` output, plus CI-friendly exit
  codes (0 = allowed, 1 = denied).
- **Policy templates** — five ready-to-copy starting points in
  `examples/policies/`: `read-only`, `sandboxed`, `ci-agent`, `full-access`,
  and `custom-tool` (#54).
- **ReDoS analyzer** (`agent_guard.redos`) — a static analyzer for
  user-supplied regex patterns, with `is_safe_pattern()` and
  `looks_like_regex()`, enforcing a pattern-length cap, a scan-step and
  scan-depth budget, and rejection of ambiguous alternation (#70, #172).

### Security

- **ReDoS protection on policy regexes** — patterns supplied in a policy are
  analyzed before use, rejecting nested quantifiers and unbounded character
  class repetition that would cause catastrophic backtracking. Rejection
  reasons name the specific dangerous construct, and the analyzer refuses to
  guess when a pattern exceeds its scan budget (#138, #144, #172).
- **Shell command injection defense** — `shell` and `bash` resources are
  screened for injection metacharacters (`;`, `|`, backticks, `$`) before the
  tool call is evaluated (#61, #64).
- **Path traversal protection** — `_normalize_path()` rejects traversal
  sequences so a policy scoped to a directory cannot be escaped via the
  resource argument (#153).
- **TOCTOU race fix and stricter `None` resource handling** in
  `matches_resource()` (#130); cross-platform path normalization so the same
  policy behaves identically on Windows and POSIX (#139).
- **`None` resource support** in `ToolCall` and `matches_resource()` (#68, #69).
- **Input validation** — `ToolCall` fields and `Policy.from_yaml()` raise
  `PolicyValidationError` on wrong types, unknown policy fields, and invalid
  `name` / `max_tool_calls` / `action` values. The error subclasses both
  `ValueError` and `TypeError` and its message carries per-rule context
  (#137, #140).

### Packaging

- **Distribution renamed to `agentperm-py`** — `pip install agent-guard`
  resolved to an unrelated existing PyPI package (a monitoring library for
  Crew AI), silently installing the wrong software. The distribution name is
  now `agentperm-py` to remove the collision (#168).
- **Install from git** — the documented install path is
  `pip install git+https://github.com/yunaremaia/agent-guard.git`. The project
  is **not** published on PyPI at the time of this release (#169).
- **Console script** — `agent-guard = "agent_guard.main:cli"`, with
  `--version` reporting `0.1.0` (#170).
- **Build backend** — Hatchling, targeting `src/agent_guard`. `uv build`
  produces `agentperm_py-0.1.0` sdist and wheel.
- **PyPI publish workflow** — OIDC trusted publishing via
  `pypa/gh-action-pypi-publish` on release publication.

### Testing and CI

- **239 tests passing** across 8 test modules: core guard behavior, async
  integration, CLI entry points, install-name regression, lint cleanliness,
  policy templates, the ReDoS analyzer, and security regressions.
- **Test suite for the console script** — the entry point is verified by
  *executing* it rather than by reading its source (#170).
- **Install-name regression tests** — lock in the `agentperm-py` distribution
  name and the `agent_guard` import / `agent-guard` command so a future rename
  cannot silently break either (#168).
- **Async test support** — `pytest-asyncio` added to dev dependencies with
  `asyncio_mode = "auto"` (#145).
- **Pinned ruff lint gate** — `ruff==0.16.10` with an explicitly enumerated
  rule set, so a ruff upgrade cannot change CI results silently.
- **Cleared 8 pre-existing ruff findings** in the test files (#171).
- **CI workflows** — Python tests and the lint gate both run on push to `main`
  and on pull requests.

### Documentation and community

- **README** — quick start, Python and async API reference, configuration
  reference, five worked policy templates, a how-it-works walkthrough, FAQ,
  CI/CD usage, and use cases (#31, #44, #47).
- **CONTRIBUTING.md** — development setup, test and lint commands, and pull
  request guidelines (#33).
- **MIT license** (#14).
- **Project governance files** — `.github/FUNDING.yml`, issue and pull
  request templates, and CI and project badges (#167).

[Unreleased]: https://github.com/yunaremaia/agent-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yunaremaia/agent-guard/releases/tag/v0.1.0
