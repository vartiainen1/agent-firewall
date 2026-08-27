"""Deterministic policy linter (Phase 3, DESIGN 39).

Inspect a loaded Policy snapshot for structural and semantic issues without
weakening authorization.  The linter is read-only: it never modifies the
policy, never activates an invalid policy, and never produces ALLOW.

Checks implemented (per DESIGN 39):

    duplicate_rule     — same action+resource in the same collection
    conflicting_rule   — same action+resource in both allow and deny
    unreachable_rule   — allow rule shadowed by a more-specific deny
    broad_wildcard     — ``**`` resource pattern in allow rules
    no_resource        — action with no resource constraint (info)
    empty_agent        — agent defined with no rules in any collection
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from .policy import AgentPolicy, Policy


class LintSeverity(Enum):
    """Severity of a lint finding."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class LintFinding:
    """One lint finding against a policy."""

    severity: LintSeverity
    code: str
    message: str
    agent: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None


def _rule_key(rule) -> Tuple[str, Optional[str]]:
    """Return the (action, resource) identity of a rule for comparison."""
    return (rule.action, rule.resource)


def _has_double_star(rule) -> bool:
    """True if the rule's resource pattern contains a ``**`` wildcard."""
    if rule.resource_segments is None:
        return False
    return any("**" in seg for seg in rule.resource_segments)


def _lint_agent(name: str, ap: AgentPolicy) -> List[LintFinding]:
    """Run all lint checks for one agent's policy."""
    findings: List[LintFinding] = []

    # ── empty_agent ───────────────────────────────────────────────────────
    if not ap.allow and not ap.deny and not ap.approve:
        findings.append(LintFinding(
            severity=LintSeverity.INFO,
            code="empty_agent",
            message=f"agent {name!r} is defined but has no rules",
            agent=name,
        ))
        return findings

    # ── duplicate_rule (within each collection) ───────────────────────────
    for label, rules in [("allow", ap.allow), ("deny", ap.deny),
                         ("approve", ap.approve)]:
        seen: dict = {}
        for rule in rules:
            key = _rule_key(rule)
            if key in seen:
                findings.append(LintFinding(
                    severity=LintSeverity.WARNING,
                    code="duplicate_rule",
                    message=(
                        f"agent {name!r} has duplicate {label} rule "
                        f"{rule.action}"
                        + (f":{rule.resource}" if rule.resource else "")
                    ),
                    agent=name,
                    action=rule.action,
                    resource=rule.resource,
                ))
            else:
                seen[key] = True

    # ── conflicting_rule (allow vs deny for same action+resource) ────────
    allow_keys = {_rule_key(r) for r in ap.allow}
    deny_keys = {_rule_key(r) for r in ap.deny}
    for key in allow_keys & deny_keys:
        action, resource = key
        findings.append(LintFinding(
            severity=LintSeverity.WARNING,
            code="conflicting_rule",
            message=(
                f"agent {name!r} has conflicting allow and deny rules for "
                f"{action}" + (f":{resource}" if resource else "")
                + " (deny takes precedence)"
            ),
            agent=name,
            action=action,
            resource=resource,
        ))

    # ── unreachable_rule (allow shadowed by more-specific deny) ───────────
    # A deny rule shadows an allow rule when:
    #   same action, and
    #   the deny resource is more specific (not a superset of allow).
    # Heuristic: if allow has ``**`` but deny has a concrete resource for
    # the same action, the deny is more specific and the allow is partially
    # unreachable.
    deny_by_action: dict = {}
    for rule in ap.deny:
        deny_by_action.setdefault(rule.action, []).append(rule)
    for rule in ap.allow:
        if rule.resource is None:
            continue  # general allow — not easily shadowed
        for deny_rule in deny_by_action.get(rule.action, []):
            if deny_rule.resource is None:
                continue  # general deny — different concern
            if deny_rule.resource == rule.resource:
                continue  # exact duplicate — already flagged
            # Allow has ``**`` and deny is a concrete subset → unreachable
            if _has_double_star(rule) and not _has_double_star(deny_rule):
                findings.append(LintFinding(
                    severity=LintSeverity.WARNING,
                    code="unreachable_rule",
                    message=(
                        f"agent {name!r} allow rule {rule.action}:{rule.resource} "
                        f"is partially unreachable — deny rule "
                        f"{deny_rule.action}:{deny_rule.resource} shadows "
                        f"a subset"
                    ),
                    agent=name,
                    action=rule.action,
                    resource=rule.resource,
                ))

    # ── broad_wildcard (``**`` in allow rules) ───────────────────────────
    for rule in ap.allow:
        if _has_double_star(rule):
            findings.append(LintFinding(
                severity=LintSeverity.WARNING,
                code="broad_wildcard",
                message=(
                    f"agent {name!r} has a broad wildcard allow: "
                    f"{rule.action}:{rule.resource}"
                ),
                agent=name,
                action=rule.action,
                resource=rule.resource,
            ))

    # ── no_resource (action without resource constraint) ──────────────────
    for label, rules in [("allow", ap.allow), ("deny", ap.deny),
                         ("approve", ap.approve)]:
        for rule in rules:
            if rule.resource is None:
                findings.append(LintFinding(
                    severity=LintSeverity.INFO,
                    code="no_resource",
                    message=(
                        f"agent {name!r} {label} rule {rule.action} "
                        f"has no resource constraint"
                    ),
                    agent=name,
                    action=rule.action,
                ))

    return findings


def lint_policy(policy: Policy) -> List[LintFinding]:
    """Analyse *policy* and return a list of findings.

    The returned list is empty when no issues are detected.  Findings are
    ordered by agent name, then by check order within each agent.  This
    function is deterministic and side-effect free.
    """
    findings: List[LintFinding] = []
    for name in sorted(policy.agents):
        findings.extend(_lint_agent(name, policy.agents[name]))
    return findings
