# agent-guard

**Policy-as-code for AI agent permissions.**

Define bounded permissions for AI agents in YAML. Enforce at runtime. Prevent scope creep.

## Why

AI agents need bounded permissions. Current solutions are either:
- **Sandboxes** (E2B, Daytona) — heavy, require infrastructure
- **Custom code** — rebuilt per project, error-prone
- **Nothing** — agents run unrestricted

`agent-guard` is a lightweight CLI + library that lets you declare *exactly* what an agent can do, then enforce it on every tool call.

## Install

```bash
pip install agent-guard
```

## Quick Start

### 1. Generate a policy

```bash
agent-guard init my-agent --output .agent-guard.yaml
```

### 2. Define permissions

```yaml
# .agent-guard.yaml
name: code-reviewer
default_action: deny

max_tool_calls: 50
blocked_tools:
  - destructive_*
  - admin_*

rules:
  - action: allow
    tool: fs.read
    resource: "./**/*"
    description: "Read project files"

  - action: allow
    tool: shell
    resource: "git *"
    description: "Read-only git commands"

  - action: deny
    tool: shell
    resource: "rm *"
    description: "Prevent deletion"
```

### 3. Check calls

```bash
agent-guard check .agent-guard.yaml --tool fs.read --resource ./src/main.py
# ✅ True — allowed by rule: Read project files
#    risk: low

agent-guard check .agent-guard.yaml --tool shell --resource "rm -rf /"
# ❌ False — denied by rule: Prevent deletion
#    risk: medium
```

### 4. Audit your policy

```bash
agent-guard audit .agent-guard.yaml --format table
```

## Features

- **YAML policies** — version-controlled, reviewable
- **Rule ordering** — first match wins (like firewall rules)
- **Tool wildcards** — `fs.*` matches `fs.read`, `fs.write`
- **Resource patterns** — glob + regex support
- **Domain controls** — allowlist/blocklist for network tools
- **Execution limits** — max tool calls per session
- **Risk scoring** — LOW/MEDIUM/HIGH/CRITICAL per verdict
- **Multiple outputs** — JSON for automation, table for humans
- **Exit codes** — 0 = allowed, 1 = denied (CI-friendly)

## CLI Commands

| Command | Purpose |
|---------|---------|
| `check` | Test a tool call against policy |
| `explain` | Show which rule matched and why |
| `audit` | Review effective ruleset |
| `init` | Generate starter policy |

## Python API Reference

Import classes directly from the package:

```python
from agent_guard import Guard, Policy, Rule, ToolCall, Action, RiskLevel

# 1. Load or construct a Policy
policy = Policy.from_file(".agent-guard.yaml")
# Alternatively, from a YAML string:
# policy = Policy.from_yaml(yaml_string)

# Or construct programmatically:
# policy = Policy(
#     name="custom-agent",
#     description="Custom security policy",
#     default_action=Action.DENY,
#     rules=[Rule(action=Action.ALLOW, tool="fs.read", resource="./**/*")],
#     max_tool_calls=50,
# )

# 2. Instantiate Guard
guard = Guard(policy)

# 3. Check / evaluate tool calls
call = ToolCall(tool="fs.read", resource="./src/main.py", arguments={"mode": "r"})
verdict = guard.check(call)

if verdict.allowed:
    print(f"Allowed: {verdict.reason} (Risk: {verdict.risk.value})")
else:
    print(f"Blocked: {verdict.reason} (Risk: {verdict.risk.value})")
```

### Core Classes & Methods

- `Policy`:
  - `Policy.from_file(path: str | Path) -> Policy`: Load policy from YAML file.
  - `Policy.from_yaml(text: str) -> Policy`: Parse policy from YAML string.
  - Attributes: `name`, `description`, `default_action` (`Action`), `rules` (`list[Rule]`), `max_tool_calls` (`int | None`), `max_executions` (`int | None`), `blocked_tools` (`list[str]`), `allowed_domains` (`list[str]`), `blocked_domains` (`list[str]`).
- `Guard`:
  - `Guard(policy: Policy)`: Initializes runtime guard with execution and call counters.
  - `guard.check(call: ToolCall) -> Verdict`: Evaluates tool call against limits, blocked tools, domain rules, and ordered policy rules.
- `ToolCall`:
  - `ToolCall(tool: str, resource: str = "", arguments: dict[str, Any] = ...)`: Represents an agent action.
- `Verdict`:
  - `allowed: bool`: Whether the action is permitted.
  - `rule: Rule | None`: Matched rule if applicable, or None if fell through to default/limits.
  - `reason: str`: Human-readable justification.
  - `risk: RiskLevel`: Risk category (`RiskLevel.LOW`, `RiskLevel.MEDIUM`, `RiskLevel.HIGH`, `RiskLevel.CRITICAL`).
- `Rule`:
  - `Rule(action: Action, resource: str, tool: str, description: str = "")`: Rule definition with glob/regex matching.

---

## Configuration Reference

Agent Guard policies are written in standard YAML. Below are all available fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `string` | *(required)* | Identifier for the policy. |
| `description` | `string` | `""` | Description of the agent's role and boundaries. |
| `default_action` | `string` (`allow` \| `deny`) | `"deny"` | Fallback action when no rules match. |
| `max_tool_calls` | `integer` | `null` | Maximum tool calls allowed per session before tripping a block. |
| `max_executions` | `integer` | `null` | Maximum policy execution count. |
| `blocked_tools` | `list[string]` | `[]` | Glob patterns for tools that are unconditionally blocked (e.g. `destructive_*`). |
| `allowed_domains` | `list[string]` | `[]` | Glob patterns for permitted domains on network tools (`browser`, `http`, `fetch`, `request`). If specified, any non-matching domain is blocked. |
| `blocked_domains` | `list[string]` | `[]` | Glob patterns for domains that are explicitly blocked. |
| `rules` | `list[object]` | `[]` | Ordered list of evaluation rules evaluated top-to-bottom. First match wins. |

### Rule Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `action` | `string` (`allow` \| `deny`) | *(required)* | Verdict returned when this rule matches. |
| `tool` | `string` | `"*"` | Tool name pattern. Supports wildcards (e.g., `fs.*`, `shell`). |
| `resource` | `string` | `"*"` | Target resource path, glob (`./**/*.py`), command prefix (`git *`), or regex. |
| `description` | `string` | `""` | Human-readable explanation shown in audit and check logs. |

---

## Policy Examples

### 1. Code Reviewer Policy (`code-reviewer.yaml`)
Enables reading repository files and running read-only git queries, while preventing any file writes or remote repository pushes:

```yaml
name: code-reviewer
description: "Restricted policy for autonomous code review"
default_action: deny

max_tool_calls: 50
blocked_tools:
  - destructive_*
  - admin_*

rules:
  # Allow reading project code
  - action: allow
    tool: fs.read
    resource: "./**/*"
    description: "Read project files"

  # Allow read-only git commands
  - action: allow
    tool: shell
    resource: "git diff *"
    description: "Inspect code diffs"

  - action: allow
    tool: shell
    resource: "git log *"
    description: "Inspect commit history"

  - action: allow
    tool: shell
    resource: "git status"
    description: "Check working tree status"

  # Deny git mutations or pushes
  - action: deny
    tool: shell
    resource: "git push *"
    description: "Prevent pushing commits"
```

### 2. Read-Only Audit Policy (`read-only.yaml`)
A zero-mutation policy suitable for security scanning or static code analysis:

```yaml
name: read-only-audit
description: "Strict read-only policy for static analysis and inspection"
default_action: deny

max_tool_calls: 100
blocked_tools:
  - shell
  - fs.write
  - fs.delete
  - exec_*

rules:
  # Allow directory listing and inspection
  - action: allow
    tool: fs.read
    resource: "./**/*"
    description: "Read repository contents"

  # Allow querying internal security docs or allowlisted APIs
  - action: allow
    tool: http
    resource: "https://api.github.com/*"
    description: "Query GitHub API"
```

### 3. Deploy Gate Policy (`deploy-gate.yaml`)
Allows executing deployment tools only against specific target environments with strict domain restrictions:

```yaml
name: deploy-gate
description: "Production and staging deployment gate policy"
default_action: deny

max_tool_calls: 20

allowed_domains:
  - "*.internal.company.com"
  - "api.github.com"

blocked_domains:
  - "*.public-cloud-sandbox.net"

rules:
  # Allow running staging deployments
  - action: allow
    tool: deploy
    resource: "staging-*"
    description: "Allow automated staging deployments"

  # Deny direct production deployment tool calls
  - action: deny
    tool: deploy
    resource: "production-*"
    description: "Block unapproved production deployment"

  # Allow notifications/status pings
  - action: allow
    tool: http
    resource: "https://*.internal.company.com/webhook/*"
    description: "Send status notifications"
```

---

## Frequently Asked Questions (FAQ)

### How can I audit my policy for gaps and effective rules?
Run `agent-guard audit` against your policy YAML file:
```bash
agent-guard audit .agent-guard.yaml --format table
```
You can also specify `--format json` or `--format yaml` for automated validation and CI pipelines.

### How do I test policies locally before deployment?
Use `agent-guard check` or `agent-guard explain` with test tool calls:
```bash
# Test whether a file write is prevented:
agent-guard check .agent-guard.yaml --tool fs.write --resource /etc/shadow

# Inspect rule resolution and rationale:
agent-guard explain .agent-guard.yaml --tool shell --resource "rm -rf /"
```

### How do wildcards work in rules?
- **Tool names**: Glob patterns matching tool names (e.g. `fs.*` matches `fs.read` and `fs.write`).
- **Resources**: Supports path globs (`./**/*.py`), prefixes (`git *`), and regex syntax for advanced resource constraints.

### What is the rule evaluation order?
Rules are evaluated sequentially from top to bottom. The first matching rule determines the verdict (`allow` or `deny`). If no rule matches, the policy falls back to `default_action`.

---

## Use Cases

- **CI/CD pipelines** — restrict agent to read-only operations
- **Code review agents** — allow `git log` but block `git push`
- **Browser agents** — restrict to specific domains
- **Multi-agent systems** — different policies per agent
- **Compliance** — audit trail of all enforcement decisions

## Comparison

| Tool | Self-hosted | Declarative | Lightweight | Domain-aware |
|------|:-:|:-:|:-:|:-:|
| agent-guard | ✅ | ✅ | ✅ | ✅ |
| E2B | ❌ | ❌ | ❌ | ❌ |
| Daytona | ✅ | ❌ | ❌ | ❌ |
| OpenAI sandbox | ❌ | ❌ | ❌ | ❌ |
| Custom code | ✅ | ❌ | ✅ | ❌ |

## License

MIT © Yunare Maia

