"""CLI for agent-guard."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from . import Guard, Policy, ToolCall


@click.group()
@click.version_option(version="0.1.0", prog_name="agent-guard")
def cli():
    """Policy-as-code for AI agent permissions."""


@cli.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.option("--tool", required=True, help="Tool name (e.g., browser, shell)")
@click.option("--resource", default="", help="Resource pattern (URL, path, command)")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def check(policy_file: str, tool: str, resource: str, as_json: bool):
    """Check if a tool call is allowed by the policy."""
    policy = Policy.from_file(policy_file)
    guard = Guard(policy)
    call = ToolCall(tool=tool, resource=resource)
    verdict = guard.check(call)

    if as_json:
        output = {
            "allowed": verdict.allowed,
            "reason": verdict.reason,
            "risk": verdict.risk.value,
            "rule": None,
        }
        if verdict.rule:
            output["rule"] = {
                "action": verdict.rule.action.value,
                "resource": verdict.rule.resource,
                "tool": verdict.rule.tool,
                "description": verdict.rule.description,
            }
        click.echo(json.dumps(output, indent=2))
    else:
        icon = "✅" if verdict.allowed else "❌"
        click.echo(f"{icon} {verdict.allowed} — {verdict.reason}")
        click.echo(f"   risk: {verdict.risk.value}")

    sys.exit(0 if verdict.allowed else 1)


@cli.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.option("--tool", required=True, help="Tool name")
@click.option("--resource", required=True, help="Resource pattern")
def explain(policy_file: str, tool: str, resource: str):
    """Explain which rule matched and why."""
    policy = Policy.from_file(policy_file)
    guard = Guard(policy)
    call = ToolCall(tool=tool, resource=resource)
    verdict = guard.check(call)

    click.echo(f"Policy: {policy.name}")
    click.echo(f"Tool: {tool}")
    click.echo(f"Resource: {resource}")
    click.echo(f"Verdict: {'ALLOW' if verdict.allowed else 'DENY'}")
    click.echo(f"Reason: {verdict.reason}")
    click.echo(f"Risk: {verdict.risk.value}")

    if verdict.rule:
        click.echo(f"Matched rule:")
        click.echo(f"  action: {verdict.rule.action.value}")
        click.echo(f"  resource: {verdict.rule.resource}")
        click.echo(f"  tool: {verdict.rule.tool}")
        click.echo(f"  description: {verdict.rule.description}")
    else:
        click.echo("Matched rule: none (fell through to default)")


@cli.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["json", "yaml", "table"]), default="table")
def audit(policy_file: str, fmt: str):
    """Audit a policy — show its effective ruleset and potential gaps."""
    policy = Policy.from_file(policy_file)

    if fmt == "json":
        rules = [
            {
                "action": r.action.value,
                "tool": r.tool,
                "resource": r.resource,
                "description": r.description,
            }
            for r in policy.rules
        ]
        click.echo(
            json.dumps(
                {
                    "name": policy.name,
                    "description": policy.description,
                    "default_action": policy.default_action.value,
                    "rules_count": len(policy.rules),
                    "rules": rules,
                    "blocked_tools": policy.blocked_tools,
                    "allowed_domains": policy.allowed_domains,
                    "blocked_domains": policy.blocked_domains,
                    "max_tool_calls": policy.max_tool_calls,
                },
                indent=2,
            )
        )
    elif fmt == "yaml":
        lines = [
            f"name: {policy.name}",
            f"default_action: {policy.default_action.value}",
            f"rules: {len(policy.rules)}",
        ]
        for r in policy.rules:
            lines.append(f"  - {r.action.value}: {r.tool} → {r.resource}")
        click.echo("\n".join(lines))
    else:
        click.echo(f"Policy: {policy.name}")
        click.echo(f"Default: {policy.default_action.value}")
        click.echo(f"Rules: {len(policy.rules)}")
        for i, r in enumerate(policy.rules, 1):
            icon = "✓" if r.action.value == "allow" else "✗"
            click.echo(f"  {i}. [{icon}] {r.action.value} {r.tool} → {r.resource}")
            if r.description:
                click.echo(f"       {r.description}")
        if policy.blocked_tools:
            click.echo(f"Blocked tools: {', '.join(policy.blocked_tools)}")
        if policy.allowed_domains:
            click.echo(f"Allowed domains: {', '.join(policy.allowed_domains)}")
        if policy.max_tool_calls:
            click.echo(f"Max tool calls: {policy.max_tool_calls}")


@cli.command(name="init")
@click.argument("name")
@click.option("--output", "-o", default=".agent-guard.yaml", help="Output file path")
@click.option(
    "--strict/--permissive",
    default=True,
    help="Strict=deny by default, Permissive=allow by default",
)
def init_policy(name: str, output: str, strict: bool):
    """Generate a starter policy file."""
    default_action = "deny" if strict else "allow"
    template = f"""# Agent Guard policy: {name}
# Auto-generated starter template

name: {name}
description: "Policy for {name} agent"
default_action: {default_action}

# Global limits
max_tool_calls: 100

# Always block these tools
blocked_tools:
  - destructive_*
  - admin_*

# Domain restrictions (for network tools)
blocked_domains:
  - "*.internal.corp"
  - "*.localhost"

# Rules are evaluated in order — first match wins
rules:
  # Allow local filesystem reads
  - action: allow
    tool: fs.read
    resource: "./**/*"
    description: "Read files within project"

  # Allow safe shell commands
  - action: allow
    tool: shell
    resource: "ls *"
    description: "List directory contents"

  # Deny writing to sensitive paths
  - action: deny
    tool: fs.write
    resource: "/etc/*"
    description: "Never write to system directories"

  # Deny dangerous shell
  - action: deny
    tool: shell
    resource: "rm -rf *"
    description: "Prevent destructive removal"
"""
    Path(output).write_text(template)
    click.echo(f"Policy template written to {output}")


if __name__ == "__main__":
    cli()
