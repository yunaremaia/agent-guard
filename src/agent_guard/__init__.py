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

    def matches_tool(self, tool_name: str | None) -> bool:
        if tool_name is None:
            return False
        return fnmatch.fnmatch(tool_name, self.tool)

    def matches_resource(self, resource: str | None) -> bool:
        if resource is None:
            return self.resource in ("*", "./**/*")
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
                # Reject nested quantifiers: (expr)*+? where expr itself contains a quantifier
                if re.search(r'\([^)]*[*+?][^)]*\)[*+?]', pat):
                    return False
                # Reject unbounded repetition on character classes: [a-z]{100,}
                if re.search(r'\[[^\]]+\]\s*\{\d+,}', pat):
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
        if not isinstance(data, dict):
            raise ValueError("Policy YAML must be a mapping")

        # Validate known fields and detect unknown ones
        known_fields = {
            "name", "description", "default_action", "rules",
            "max_executions", "max_tool_calls", "blocked_tools",
            "allowed_domains", "blocked_domains",
        }
        unknown = set(data.keys()) - known_fields
        if unknown:
            import warnings
            warnings.warn(
                f"Policy contains unknown fields: {sorted(unknown)}. "
                f"These will be ignored.",
                stacklevel=2,
            )

        # Validate required field
        if "name" not in data:
            raise ValueError("Policy must have a 'name' field")

        # Validate and coerce field types
        name = data["name"]
        if not isinstance(name, str) or not name:
            raise ValueError("Policy 'name' must be a non-empty string")

        description = data.get("description", "")
        if not isinstance(description, str):
            raise ValueError("Policy 'description' must be a string")

        default_action_raw = data.get("default_action", "deny")
        if not isinstance(default_action_raw, str):
            raise ValueError("Policy 'default_action' must be a string")
        try:
            default_action = Action(default_action_raw)
        except ValueError:
            raise ValueError(
                f"Policy 'default_action' must be 'allow' or 'deny', got '{default_action_raw}'"
            )

        rules = []
        for i, r in enumerate(data.get("rules", [])):
            if not isinstance(r, dict):
                raise ValueError(f"Rule {i} must be a mapping")
            action_raw = r.get("action", "allow")
            if not isinstance(action_raw, str):
                raise ValueError(f"Rule {i}: 'action' must be a string")
            try:
                action = Action(action_raw)
            except ValueError:
                raise ValueError(
                    f"Rule {i}: 'action' must be 'allow' or 'deny', got '{action_raw}'"
                )
            resource = r.get("resource", "*")
            tool = r.get("tool", "*")
            if not isinstance(resource, str):
                raise ValueError(f"Rule {i}: 'resource' must be a string")
            if not isinstance(tool, str):
                raise ValueError(f"Rule {i}: 'tool' must be a string")
            rules.append(
                Rule(
                    action=action,
                    resource=resource,
                    tool=tool,
                    description=r.get("description", "") or "",
                )
            )

        def _coerce_int_or_none(val, field_name: str):
            if val is None:
                return None
            if isinstance(val, int) and not isinstance(val, bool):
                return val
            raise ValueError(f"Policy '{field_name}' must be an integer or null, got {type(val).__name__}")

        max_executions = _coerce_int_or_none(data.get("max_executions"), "max_executions")
        max_tool_calls = _coerce_int_or_none(data.get("max_tool_calls"), "max_tool_calls")

        blocked_tools = data.get("blocked_tools", [])
        if not isinstance(blocked_tools, list) or not all(isinstance(t, str) for t in blocked_tools):
            raise ValueError("Policy 'blocked_tools' must be a list of strings")

        allowed_domains = data.get("allowed_domains", [])
        if not isinstance(allowed_domains, list) or not all(isinstance(d, str) for d in allowed_domains):
            raise ValueError("Policy 'allowed_domains' must be a list of strings")

        blocked_domains = data.get("blocked_domains", [])
        if not isinstance(blocked_domains, list) or not all(isinstance(d, str) for d in blocked_domains):
            raise ValueError("Policy 'blocked_domains' must be a list of strings")

        return cls(
            name=name,
            description=description,
            default_action=default_action,
            rules=rules,
            max_executions=max_executions,
            max_tool_calls=max_tool_calls,
            blocked_tools=blocked_tools,
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        return cls.from_yaml(Path(path).read_text())
    @classmethod
    async def from_file_async(cls, path: str | Path) -> "Policy":
        return await asyncio.to_thread(cls.from_file, path)


@dataclass
class ToolCall:
    tool: str | None = None
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
        # Validate inputs up front so invalid calls raise a clear ValueError
        # instead of a cryptic TypeError deep in fnmatch or attribute access.
        if not isinstance(call.tool, str) or not call.tool:
            raise ValueError("tool must be a non-empty string")
        if call.resource is not None and not isinstance(call.resource, str):
            raise ValueError("resource must be None or a string")
        if not isinstance(call.arguments, dict):
            # issue #137 specifies ValueError; TRY004 would prefer TypeError.
            raise ValueError("arguments must be a dict")  # noqa: TRY004

        with self._lock:
            self.tool_call_count += 1
            self.execution_count += 1
            current_count = self.tool_call_count
            current_exec = self.execution_count

        # Global limits
        if self.policy.max_tool_calls and current_count > self.policy.max_tool_calls:
            return Verdict(
                allowed=False,
                rule=None,
                reason=f"max_tool_calls exceeded ({self.policy.max_tool_calls})",
                risk=RiskLevel.HIGH,
            )
        if self.policy.max_executions and current_exec > self.policy.max_executions:
            return Verdict(
                allowed=False,
                rule=None,
                reason=f"max_executions exceeded ({self.policy.max_executions})",
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
            dangerous = [";", "|", "&", "$", "`", ">", "<", "\n", "\r", "&&", "||"]
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


@dataclass
class PolicyDecision:
    """Result of an async policy evaluation.

    Wraps the internal Verdict with a user-friendly interface for async callers.
    """

    allowed: bool
    reason: str
    risk: RiskLevel
    rule: Rule | None = None

    @property
    def denied(self) -> bool:
        """True when the tool call was denied."""
        return not self.allowed

    @classmethod
    def from_verdict(cls, verdict: Verdict) -> "PolicyDecision":
        """Create a PolicyDecision from an internal Verdict."""
        return cls(
            allowed=verdict.allowed,
            reason=verdict.reason,
            risk=verdict.risk,
            rule=verdict.rule,
        )


class PolicyViolation(Exception):
    """Raised when a tool call is denied by the policy.

    Attributes:
        decision: The PolicyDecision that triggered the violation.
    """

    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Policy violation: {decision.reason} (risk={decision.risk.value})"
        )


async def check_async(
    policy: Policy,
    tool_call: ToolCall,
    context: dict[str, Any] | None = None,
    *,
    raise_on_deny: bool = False,
) -> PolicyDecision:
    """Asynchronously evaluate a single tool call against a policy.

    Creates a one-shot Guard and runs the check in a thread so the
    calling event loop is never blocked.

    Args:
        policy: The Policy to enforce.
        tool_call: The ToolCall to evaluate.
        context: Optional context dict (reserved for future use).
        raise_on_deny: If True, raise PolicyViolation instead of returning
            a denied PolicyDecision.

    Returns:
        A PolicyDecision indicating whether the call is allowed.

    Raises:
        PolicyViolation: When *raise_on_deny* is True and the call is denied.
    """
    guard = Guard(policy)
    verdict = await asyncio.to_thread(guard.check, tool_call)
    decision = PolicyDecision.from_verdict(verdict)
    if raise_on_deny and decision.denied:
        raise PolicyViolation(decision)
    return decision


async def check_batch_async(
    policy: Policy,
    tool_calls: list[ToolCall],
    context: dict[str, Any] | None = None,
    *,
    raise_on_deny: bool = False,
) -> list[PolicyDecision]:
    """Asynchronously evaluate multiple tool calls against a policy.

    Each call is checked concurrently via asyncio.gather.

    Args:
        policy: The Policy to enforce.
        tool_calls: List of ToolCalls to evaluate.
        context: Optional context dict (reserved for future use).
        raise_on_deny: If True, raise PolicyViolation on the first
            denied call encountered.

    Returns:
        A list of PolicyDecision objects, one per tool call.

    Raises:
        PolicyViolation: When *raise_on_deny* is True and any call is denied.
    """
    guard = Guard(policy)
    tasks = [asyncio.to_thread(guard.check, call) for call in tool_calls]
    verdicts = await asyncio.gather(*tasks)
    decisions = [PolicyDecision.from_verdict(v) for v in verdicts]
    if raise_on_deny:
        for decision in decisions:
            if decision.denied:
                raise PolicyViolation(decision)
    return decisions


__all__ = [
    "Action",
    "Guard",
    "GuardStats",
    "Policy",
    "PolicyDecision",
    "PolicyViolation",
    "RiskLevel",
    "Rule",
    "ToolCall",
    "Verdict",
    "check_async",
    "check_batch_async",
]