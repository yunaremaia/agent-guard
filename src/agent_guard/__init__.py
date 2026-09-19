"""Guard: Policy-as-code for AI agent permissions.

Defines bounded permissions in YAML, enforces at runtime.
Prevents agents from exceeding defined scopes (network, filesystem, commands).
"""

from __future__ import annotations

import asyncio
import re
import fnmatch
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class Action(Enum):
    ALLOW = "allow"
    DENY = "deny"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Rule:
    action: Action
    resource: str  # glob or regex pattern
    tool: str  # tool name pattern (e.g., "browser", "shell", "fs.*")
    description: str = ""

    def matches_tool(self, tool_name: str) -> bool:
        return fnmatch.fnmatch(tool_name, self.tool)

    def matches_resource(self, resource: str | None) -> bool:
        if resource is None:
            return True
        from pathlib import PurePath
        # Normalize: strip leading ./
        res = resource[2:] if resource.startswith("./") else resource
        pat = self.resource[2:] if self.resource.startswith("./") else self.resource

        # Special handling for ** (recursive glob)
        if "**" in pat:
            prefix, _, suffix = pat.partition("**/")
            # Prefix match (before **)
            if prefix and not res.startswith(prefix.rstrip("/")):
                return False
            # Suffix match (after **/)
            if suffix:
                # Match any file ending with suffix
                if suffix.startswith("*"):
                    # e.g., *.py — match extension
                    if not res.endswith(suffix[1:]):
                        return False
                else:
                    # Exact suffix match (e.g., "foo.txt")
                    if not res.endswith(suffix):
                        return False
            return True

        # Try PurePath.match (handles single-level globs)
        try:
            if PurePath(res).match(pat):
                return True
        except (ValueError, TypeError):
            pass

        # Fallback to fnmatch
        if fnmatch.fnmatch(res, pat):
            return True

        # Try regex match for patterns with regex-specific chars
        # SECURITY: Limit pattern length and complexity to prevent ReDoS
        try:
            if any(c in pat for c in ['^', '$', '|', '(', ')', '+', '?', '{', '}']):
                if len(pat) > 100:
                    return False
                if re.search(r'\([^)]*\)[*+?]', pat) or re.search(r'[*+?]\s*[*+?]', pat):
                    return False
                return bool(re.fullmatch(pat, res))
        except re.error:
            pass

        return False


@dataclass
class Policy:
    name: str
    description: str
    default_action: Action
    rules: list[Rule] = field(default_factory=list)
    max_executions: int | None = None
    max_tool_calls: int | None = None
    blocked_tools: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    blocked_domains: list[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, text: str) -> "Policy":
        data = yaml.safe_load(text)
        rules = []
        for r in data.get("rules", []):
            rules.append(
                Rule(
                    action=Action(r["action"]),
                    resource=r.get("resource", "*"),
                    tool=r.get("tool", "*"),
                    description=r.get("description", ""),
                )
            )
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            default_action=Action(data.get("default_action", "deny")),
            rules=rules,
            max_executions=data.get("max_executions"),
            max_tool_calls=data.get("max_tool_calls"),
            blocked_tools=data.get("blocked_tools", []),
            allowed_domains=data.get("allowed_domains", []),
            blocked_domains=data.get("blocked_domains", []),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        return cls.from_yaml(Path(path).read_text())
    @classmethod
    async def from_file_async(cls, path: str | Path) -> "Policy":
        return await asyncio.to_thread(cls.from_file, path)


@dataclass
class ToolCall:
    tool: str
    resource: str | None = ""
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class Verdict:
    allowed: bool
    rule: Rule | None
    reason: str
    risk: RiskLevel = RiskLevel.LOW


@dataclass
class GuardStats:
    """Snapshot of Guard runtime execution metrics."""
    execution_count: int
    tool_call_count: int
    max_tool_calls: int | None
    max_executions: int | None

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_count": self.execution_count,
            "tool_call_count": self.tool_call_count,
            "max_tool_calls": self.max_tool_calls,
            "max_executions": self.max_executions,
        }


class Guard:
    """Evaluate tool calls against a policy."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self.execution_count = 0
        self.tool_call_count = 0
        self._lock = threading.Lock()

    def reset(self) -> "Guard":
        """Reset execution and tool call counters to zero."""
        with self._lock:
            self.execution_count = 0
            self.tool_call_count = 0
        return self

    def stats(self) -> GuardStats:
        """Return a snapshot of current guard metrics."""
        with self._lock:
            return GuardStats(
                execution_count=self.execution_count,
                tool_call_count=self.tool_call_count,
                max_tool_calls=self.policy.max_tool_calls,
                max_executions=self.policy.max_executions,
            )

    def check(self, call: ToolCall) -> Verdict:
        with self._lock:
            self.tool_call_count += 1
            current_count = self.tool_call_count

        # Global limits
        if self.policy.max_tool_calls and current_count > self.policy.max_tool_calls:
            return Verdict(
                allowed=False,
                rule=None,
                reason=f"max_tool_calls exceeded ({self.policy.max_tool_calls})",
                risk=RiskLevel.HIGH,
            )

        # Blocked tools
        for bt in self.policy.blocked_tools:
            if fnmatch.fnmatch(call.tool, bt):
                return Verdict(
                    allowed=False,
                    rule=None,
                    reason=f"tool '{call.tool}' is blocked",
                    risk=RiskLevel.MEDIUM,
                )

        # SECURITY: Sanitize shell resource to prevent command injection
        if call.tool in ("shell", "bash"):
            dangerous = [";", "|", "&", "$", "`", ">", "<", "\n", "\r", "#", "&&", "||"]
            for ch in dangerous:
                if ch in (call.resource or ""):
                    return Verdict(
                        allowed=False,
                        rule=None,
                        reason=f"shell resource contains injection character '{ch}'",
                        risk=RiskLevel.CRITICAL,
                    )

        # Domain checks for network tools
        if call.tool in ("browser", "http", "fetch", "request"):
            return self._check_network(call)

        # Match rules in order
        for rule in self.policy.rules:
            if rule.matches_tool(call.tool) and rule.matches_resource(call.resource):
                if rule.action == Action.ALLOW:
                    return Verdict(
                        allowed=True,
                        rule=rule,
                        reason=f"allowed by rule: {rule.description or rule.resource}",
                        risk=RiskLevel.LOW,
                    )
                else:
                    return Verdict(
                        allowed=False,
                        rule=rule,
                        reason=f"denied by rule: {rule.description or rule.resource}",
                        risk=RiskLevel.MEDIUM,
                    )

        # Default action
        if self.policy.default_action == Action.ALLOW:
            return Verdict(
                allowed=True,
                rule=None,
                reason="default allow (no matching rule)",
                risk=RiskLevel.MEDIUM,
            )
        return Verdict(
            allowed=False,
            rule=None,
            reason="default deny (no matching rule)",
            risk=RiskLevel.LOW,
        )

    async def check_async(self, call: ToolCall) -> Verdict:
        # Async version of check().
        
        return await asyncio.to_thread(self.check, call)

    async def check_batch_async(self, calls: list[ToolCall]) -> list[Verdict]:
        # Check multiple calls concurrently.
        
        tasks = [self.check_async(call) for call in calls]
        return await asyncio.gather(*tasks)

    def _check_network(self, call: ToolCall) -> Verdict:
        resource = call.resource or ""
        # Extract domain from URL if present
        domain = ""
        if "://" in resource:
            domain = resource.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        elif resource.startswith("www."):
            domain = resource.split("/", 1)[0]

        if domain:
            for bd in self.policy.blocked_domains:
                if fnmatch.fnmatch(domain, bd):
                    return Verdict(
                        allowed=False,
                        rule=None,
                        reason=f"domain '{domain}' is blocked",
                        risk=RiskLevel.MEDIUM,
                    )
            if self.policy.allowed_domains:
                allowed = any(fnmatch.fnmatch(domain, ad) for ad in self.policy.allowed_domains)
                if not allowed:
                    return Verdict(
                        allowed=False,
                        rule=None,
                        reason=f"domain '{domain}' not in allowlist",
                        risk=RiskLevel.MEDIUM,
                    )

        # Fall through to normal rules
        for rule in self.policy.rules:
            if rule.matches_tool(call.tool) and rule.matches_resource(call.resource):
                return Verdict(
                    allowed=rule.action == Action.ALLOW,
                    rule=rule,
                    reason=f"domain ok, {rule.action.value} by rule",
                    risk=RiskLevel.LOW,
                )

        return Verdict(
            allowed=self.policy.default_action == Action.ALLOW,
            rule=None,
            reason="domain check passed, no matching rule — using default",
            risk=RiskLevel.MEDIUM,
        )