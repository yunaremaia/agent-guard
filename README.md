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

### 2. Define permissions (minimal example)

```yaml
# .agent-guard.yaml - Minimal working example
name: minimal-agent
default_action: deny

rules:
  - action: allow
    tool: fs.read
    resource: "./**/*"
```

This policy:
- Denies everything by default
- Allows reading files in the current directory
- Blocks all other operations

### 3. Test the policy

```bash
# Test allowed operation
agent-guard check .agent-guard.yaml --tool fs.read --resource ./src/main.py
# ✅ True — allowed
#    risk: low

# Test denied operation
agent-guard check .agent-guard.yaml --tool shell --resource "rm -rf /"
# ❌ False — denied by default_action
#    risk: medium
```

## Policy Templates

Pre-made templates for common scenarios. Copy, customize, and use.

### Template 1: Read-Only Code Reviewer

Perfect for code review agents that should only read files and run read-only git commands.

```yaml
# code-reviewer.yaml
name: code-reviewer
default_action: deny
max_tool_calls: 100

# Block all destructive operations
blocked_tools:
  - destructive_*
  - admin_*
  - shell:rm*
  - shell:del*

rules:
  # Read project files
  - action: allow
    tool: fs.read
    resource: "./**/*"
    description: "Read any project file"

  # Read-only git commands
  - action: allow
    tool: shell
    resource: "git log *"
    description: "View git history"
  
  - action: allow
    tool: shell
    resource: "git show *"
    description: "Show git commits"
  
  - action: allow
    tool: shell
    resource: "git diff *"
    description: "View git diffs"
  
  - action: allow
    tool: shell
    resource: "git status"
    description: "Check git status"

  # Block write operations
  - action: deny
    tool: shell
    resource: "git push *"
    description: "Prevent pushing changes"
  
  - action: deny
    tool: fs.write
    resource: "./**/*"
    description: "Prevent file modifications"
```

**Use case**: CI/CD code review agents that analyze but don't modify code.

### Template 2: Network-Restricted Research Agent

Allows web browsing but restricts to specific domains.

```yaml
# research-agent.yaml
name: research-agent
default_action: deny

# Domain allowlist
allowed_domains:
  - github.com
  - stackoverflow.com
  - docs.python.org
  - arxiv.org

# Block all other domains
blocked_domains:
  - "*"

rules:
  # Allow reading project files
  - action: allow
    tool: fs.read
    resource: "./**/*"
  
  # Allow web requests to approved domains
  - action: allow
    tool: http.get
    resource: "https://github.com/**"
    description: "Browse GitHub"
  
  - action: allow
    tool: http.get
    resource: "https://stackoverflow.com/**"
    description: "Search StackOverflow"
  
  - action: allow
    tool: http.get
    resource: "https://docs.python.org/**"
    description: "Read Python docs"
  
  - action: allow
    tool: http.get
    resource: "https://arxiv.org/**"
    description: "Browse research papers"

  # Block all other web requests
  - action: deny
    tool: http.*
    resource: "*"
    description: "Block unapproved domains"

  # Allow local file writes (for saving research)
  - action: allow
    tool: fs.write
    resource: "./research/**"
    description: "Save research notes"
```

**Use case**: Research agents that browse the web but stay within approved domains.

### Template 3: File-System Sandbox

Restricts agent to a specific directory tree.

```yaml
# sandbox.yaml
name: filesystem-sandbox
default_action: deny

rules:
  # Allow operations within sandbox directory only
  - action: allow
    tool: fs.read
    resource: "./sandbox/**"
    description: "Read within sandbox"
  
  - action: allow
    tool: fs.write
    resource: "./sandbox/**"
    description: "Write within sandbox"
  
  - action: allow
    tool: fs.delete
    resource: "./sandbox/**"
    description: "Delete within sandbox"

  # Block all operations outside sandbox
  - action: deny
    tool: fs.*
    resource: "../**"
    description: "Prevent parent directory access"
  
  - action: deny
    tool: fs.*
    resource: "/**"
    description: "Prevent system directory access"

  # Allow shell commands only within sandbox
  - action: allow
    tool: shell
    resource: "cd ./sandbox *"
    description: "Change to sandbox directory"
  
  - action: deny
    tool: shell
    resource: "cd .. *"
    description: "Prevent escaping sandbox"
```

**Use case**: Untrusted agents that should only operate within a isolated directory.

### Template 4: CI/CD Deployment Agent

For deployment agents with strict operational boundaries.

```yaml
# deploy-agent.yaml
name: ci-deploy-agent
default_action: deny
max_tool_calls: 30

rules:
  # Allow reading deployment configs
  - action: allow
    tool: fs.read
    resource: "./deploy/**"
    description: "Read deployment configs"
  
  - action: allow
    tool: fs.read
    resource: "./.github/**"
    description: "Read CI/CD configs"

  # Allow specific deployment commands
  - action: allow
    tool: shell
    resource: "kubectl apply *"
    description: "Apply Kubernetes manifests"
  
  - action: allow
    tool: shell
    resource: "docker build *"
    description: "Build Docker images"
  
  - action: allow
    tool: shell
    resource: "docker push *"
    description: "Push Docker images"

  # Block dangerous operations
  - action: deny
    tool: shell
    resource: "kubectl delete *"
    description: "Prevent resource deletion"
  
  - action: deny
    tool: shell
    resource: "docker rm *"
    description: "Prevent container removal"
  
  - action: deny
    tool: shell
    resource: "rm *"
    description: "Prevent file deletion"

  # Block production access unless explicitly allowed
  - action: deny
    tool: shell
    resource: "*--namespace=production*"
    description: "Block production namespace"
```

**Use case**: Automated deployment agents with strict operational boundaries.

### Template 5: Multi-Agent System

Different policies for different agent roles.

```yaml
# multi-agent.yaml
name: multi-agent-system
default_action: deny

# Agent-specific rules
agents:
  # Research agent - can browse web
  research:
    rules:
      - action: allow
        tool: http.get
        resource: "*"
      - action: allow
        tool: fs.read
        resource: "./**/*"
      - action: deny
        tool: fs.write
        resource: "./**/*"

  # Coding agent - can write code but not browse web
  coder:
    rules:
      - action: deny
        tool: http.*
        resource: "*"
      - action: allow
        tool: fs.read
        resource: "./src/**"
      - action: allow
        tool: fs.write
        resource: "./src/**"
      - action: allow
        tool: shell
        resource: "pytest *"

  # Reviewer agent - read-only
  reviewer:
    rules:
      - action: allow
        tool: fs.read
        resource: "./**/*"
      - action: allow
        tool: shell
        resource: "git log *"
      - action: deny
        tool: fs.write
        resource: "./**/*"
      - action: deny
        tool: shell
        resource: "git push *"
```

**Use case**: Multi-agent systems where each agent has different permission levels.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                     Tool Call Request                        │
│              (e.g., fs.read ./src/main.py)                  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  Load Policy (.agent-guard.yaml)            │
│                                                              │
│  name: my-agent                                             │
│  default_action: deny                                       │
│  rules:                                                     │
│    - action: allow                                          │
│      tool: fs.read                                          │
│      resource: "./**/*"                                     │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                   Evaluate Rules (First Match Wins)         │
│                                                              │
│  Rule 1: fs.read ./**/* → MATCH ✅                          │
│  Rule 2: shell rm * → no match                              │
│  Rule 3: default_action: deny → fallback                    │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                      Generate Verdict                        │
│                                                              │
│  allowed: true                                              │
│  reason: "Allowed by rule: Read project files"             │
│  risk: low                                                  │
│  matched_rule: 1                                            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    Return Result                             │
│                                                              │
│  Exit code: 0 (allowed) or 1 (denied)                      │
│  Output: JSON or human-readable table                      │
└─────────────────────────────────────────────────────────────┘
```

**Flow**:
1. Agent makes a tool call request
2. `agent-guard` loads the policy file
3. Evaluates rules in order (first match wins)
4. Returns verdict (allowed/denied) with reason
5. Agent proceeds or blocks based on verdict

## FAQ

### Q: What happens if no rules match?

**A**: The `default_action` determines the outcome. If `default_action: deny`, unmatched operations are blocked. If `default_action: allow`, they're permitted. We recommend `deny` for security.

### Q: Can I use wildcards in tool names?

**A**: Yes! Use `*` to match multiple tools. For example:
- `fs.*` matches `fs.read`, `fs.write`, `fs.delete`
- `shell:git*` matches `shell:git log`, `shell:git push`, etc.
- `http.*` matches `http.get`, `http.post`, etc.

### Q: How do resource patterns work?

**A**: Resource patterns support:
- **Glob patterns**: `./**/*` matches all files recursively
- **Prefix matching**: `git *` matches any string starting with "git "
- **Exact matching**: `./src/main.py` matches only that file
- **Regex**: Use `regex:` prefix for complex patterns

Examples:
```yaml
resource: "./**/*"          # All files in current directory
resource: "./src/*.py"      # Python files in src/
resource: "git *"           # Any git command
resource: "https://*.com"   # Any .com domain
```

### Q: Can I block specific commands but allow similar ones?

**A**: Yes! Rules are evaluated in order, first match wins. Put specific rules first:

```yaml
rules:
  # Allow safe git commands
  - action: allow
    tool: shell
    resource: "git log *"
  
  - action: allow
    tool: shell
    resource: "git status"
  
  # Block dangerous git commands
  - action: deny
    tool: shell
    resource: "git push *"
  
  - action: deny
    tool: shell
    resource: "git reset --hard *"
```

### Q: How do I test my policy without running the agent?

**A**: Use the `check` command:

```bash
agent-guard check .agent-guard.yaml --tool fs.read --resource ./src/main.py
```

This tells you if the operation would be allowed, which rule matched, and the risk level.

### Q: Can I set limits on how many tools an agent can call?

**A**: Yes! Use `max_tool_calls`:

```yaml
name: limited-agent
max_tool_calls: 50  # Agent can make at most 50 tool calls

rules:
  - action: allow
    tool: fs.read
    resource: "./**/*"
```

After 50 calls, all subsequent calls are denied.

### Q: What's the risk scoring system?

**A**: Each verdict includes a risk level:
- **LOW**: Read-only operations (fs.read, git log)
- **MEDIUM**: Write operations (fs.write, shell commands)
- **HIGH**: Destructive operations (fs.delete, rm)
- **CRITICAL**: System-level operations (sudo, system paths)

Risk is auto-calculated based on the tool and resource.

### Q: Can I use this in CI/CD pipelines?

**A**: Absolutely! Exit codes are CI-friendly:
- `0` = allowed
- `1` = denied

Example GitHub Actions step:
```yaml
- name: Check agent permissions
  run: |
    agent-guard check .agent-guard.yaml \
      --tool ${{ steps.agent.outputs.tool }} \
      --resource ${{ steps.agent.outputs.resource }}
```

### Q: How do I audit what my policy allows?

**A**: Use the `audit` command:

```bash
agent-guard audit .agent-guard.yaml --format table
```

This shows all effective rules, what they allow/deny, and any gaps or overlaps.

### Q: Can different agents have different policies?

**A**: Yes! Create separate policy files:

```bash
# Research agent
agent-guard check research-agent.yaml --tool http.get --resource "https://example.com"

# Coding agent
agent-guard check coding-agent.yaml --tool fs.write --resource "./src/main.py"
```

Or use the multi-agent template (see Policy Templates section).

## Advanced Usage

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

## Python API

```python
from agent_guard import Guard, Policy, ToolCall

policy = Policy.from_file(".agent-guard.yaml")
guard = Guard(policy)

call = ToolCall(tool="fs.read", resource="./src/main.py")
verdict = guard.check(call)

if verdict.allowed:
    print(f"OK: {verdict.reason}")
else:
    print(f"BLOCKED: {verdict.reason}")
```

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
