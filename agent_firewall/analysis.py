"""Optional read-only policy analysis tools (Phase 16).

Provides structured analysis results that answer questions about policy
structure without modifying authorization behavior.

All analysis is **informational only**.  It never produces ALLOW/DENY/APPROVE.
It never modifies the policy.  It never executes operations.

    PolicyAnalyzer
        |
        +-- permission_graph()     → List[CapabilityNode]
        +-- privilege_mismatches() → List[PrivilegeMismatch]
        +-- unused_capabilities()  → List[UnusedCapability]
        +-- broad_permissions()    → List[BroadPermission]
        +-- conflicts()            → List[ConflictEntry]
        +-- reachability()         → ReachabilityResult

Design constraints:
    - Keep analysis separate from authorization (ROADMAP 16)
    - Analysis never produces Decision objects
    - Analysis never invokes Firewall.check()
    - Analysis never modifies Policy
    - Analysis uses the same resource matching semantics as the evaluator
    - Zero third-party dependencies
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .normalize import resource_matches
from .policy import AgentPolicy, Policy


# ── Result dataclasses ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class CapabilityNode:
    """One node in the permission graph.

    Describes a single declared capability in the policy.
    """

    agent: str
    action: str
    resource: Optional[str] = None
    collection: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "agent": self.agent,
            "action": self.action,
            "collection": self.collection,
        }
        if self.resource is not None:
            d["resource"] = self.resource
        return d

    def to_text(self) -> str:
        res = f" {self.resource}" if self.resource is not None else ""
        return f"{self.agent} {self.collection} {self.action}{res}"


@dataclass(frozen=True)
class PrivilegeMismatch:
    """An analytical observation of a cross-agent privilege difference.

    Agent B has a capability (allow/approve) that Agent A lacks (denied
    or no matching rule).  This is advisory only — it does NOT prove
    that escalation is possible.
    """

    agent_lacking: str
    agent_having: str
    action: str
    resource: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "agent_lacking": self.agent_lacking,
            "agent_having": self.agent_having,
            "action": self.action,
        }
        if self.resource is not None:
            d["resource"] = self.resource
        if self.reason:
            d["reason"] = self.reason
        return d

    def to_text(self) -> str:
        res = f" {self.resource}" if self.resource is not None else ""
        return (
            f"privilege mismatch: {self.agent_lacking} lacks "
            f"{self.action}{res} that {self.agent_having} has"
        )


@dataclass(frozen=True)
class UnusedCapability:
    """A capability not exercised by any supplied test case.

    Evidence-based only — does NOT prove actual non-use.
    """

    agent: str
    action: str
    resource: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "agent": self.agent,
            "action": self.action,
        }
        if self.resource is not None:
            d["resource"] = self.resource
        return d

    def to_text(self) -> str:
        res = f" {self.resource}" if self.resource is not None else ""
        return f"unused: {self.agent} {self.action}{res}"


@dataclass(frozen=True)
class BroadPermission:
    """An allow rule with a wide resource scope."""

    agent: str
    action: str
    resource: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "agent": self.agent,
            "action": self.action,
        }
        if self.resource is not None:
            d["resource"] = self.resource
        if self.reason:
            d["reason"] = self.reason
        return d

    def to_text(self) -> str:
        res = f" {self.resource}" if self.resource is not None else ""
        reason = f" ({self.reason})" if self.reason else ""
        return f"broad: {self.agent} {self.action}{res}{reason}"


@dataclass(frozen=True)
class ConflictEntry:
    """A conflict between an allow and a deny rule for the same agent."""

    agent: str
    action: str
    resource: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "agent": self.agent,
            "action": self.action,
        }
        if self.resource is not None:
            d["resource"] = self.resource
        return d

    def to_text(self) -> str:
        res = f" {self.resource}" if self.resource is not None else ""
        return f"conflict: {self.agent} {self.action}{res} in allow and deny"


@dataclass(frozen=True)
class ReachabilityResult:
    """Whether an agent can reach a specific action+resource in the policy.

    This is an analysis question, NOT an authorization decision.
    """

    reachable: bool
    agent: str
    action: str
    resource: str = ""
    blocked_by: str = ""
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "reachable": self.reachable,
            "agent": self.agent,
            "action": self.action,
        }
        if self.resource:
            d["resource"] = self.resource
        if self.blocked_by:
            d["blocked_by"] = self.blocked_by
        if self.reason:
            d["reason"] = self.reason
        return d

    def to_text(self) -> str:
        res = f" {self.resource}" if self.resource else ""
        status = "reachable" if self.reachable else f"not reachable ({self.blocked_by})"
        return f"reachability: {self.agent} {self.action}{res} — {status}"


# ── Analyzer ─────────────────────────────────────────────────────────────────


def _rule_matches_resource(rule, request_segments):
    """Check if a rule's resource pattern matches request segments.

    Uses the same semantics as the evaluator: resource_matches() from
    normalize.py.  A rule with resource_segments=None matches any resource.
    """
    return resource_matches(request_segments, rule.resource_segments)


def _is_broad_resource(resource: Optional[str], resource_segments) -> bool:
    """Check if a resource pattern is overly broad.

    Broad patterns:
    - resource=None (no resource constraint)
    - resource_segments contains '**'
    - any segment contains '*'
    """
    if resource is None:
        return True
    if resource_segments is None:
        return True
    for seg in resource_segments:
        if "**" in seg:
            return True
        if "*" in seg:
            return True
    return False


def _has_deny_match(agent_cfg: AgentPolicy, action: str,
                    request_segments) -> bool:
    """Check if any deny rule matches action+resource for an agent."""
    for rule in agent_cfg.deny:
        if rule.action == action and _rule_matches_resource(rule, request_segments):
            return True
    return False


def _has_allow_or_approve_match(agent_cfg: AgentPolicy, action: str,
                                 request_segments) -> bool:
    """Check if any allow or approve rule matches action+resource."""
    for rule in agent_cfg.allow:
        if rule.action == action and _rule_matches_resource(rule, request_segments):
            return True
    for rule in agent_cfg.approve:
        if rule.action == action and _rule_matches_resource(rule, request_segments):
            return True
    return False


def _agent_has_deny(agent_name: str, agent_cfg: AgentPolicy,
                    action: str, resource_segments) -> bool:
    """Check if agent has a deny rule matching action+resource."""
    for rule in agent_cfg.deny:
        if rule.action == action and _rule_matches_resource(rule, resource_segments):
            return True
    return False


def _agent_has_allow_or_approve(agent_cfg: AgentPolicy, action: str,
                                 resource_segments) -> bool:
    """Check if agent has an allow or approve rule matching action+resource."""
    for rule in agent_cfg.allow:
        if rule.action == action and _rule_matches_resource(rule, resource_segments):
            return True
    for rule in agent_cfg.approve:
        if rule.action == action and _rule_matches_resource(rule, resource_segments):
            return True
    return False


class PolicyAnalyzer:
    """Optional read-only analysis tools for policies.

    Analysis is purely descriptive.  It never produces authorization
    decisions and never modifies the policy.

    Usage::

        from agent_firewall import Firewall
        from agent_firewall.analysis import PolicyAnalyzer

        firewall = Firewall.from_file("policy.json")
        analyzer = PolicyAnalyzer(firewall.policy)

        graph = analyzer.permission_graph()
        mismatches = analyzer.privilege_mismatches()
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    # ── Permission graph ─────────────────────────────────────────────────

    def permission_graph(self) -> List[CapabilityNode]:
        """Return all declared capabilities as structured nodes.

        Enumerates every rule from every agent in all three collections.
        Does NOT resolve effective authorization or precedence.
        """
        nodes: List[CapabilityNode] = []
        for agent_name in sorted(self._policy.agents):
            agent_cfg = self._policy.agents[agent_name]
            for collection, rules in [
                ("allow", agent_cfg.allow),
                ("deny", agent_cfg.deny),
                ("approve", agent_cfg.approve),
            ]:
                for rule in rules:
                    nodes.append(CapabilityNode(
                        agent=agent_name,
                        action=rule.action,
                        resource=rule.resource,
                        collection=collection,
                    ))
        return nodes

    # ── Privilege mismatches ─────────────────────────────────────────────

    def privilege_mismatches(self) -> List[PrivilegeMismatch]:
        """Identify cross-agent privilege differences.

        Reports when Agent B has an allow/approve capability for an
        action+resource that Agent A lacks (denied or no matching rule).

        This is advisory only.  It does NOT prove that escalation is
        possible.  It does NOT model delegation, impersonation, or
        approval transfer.
        """
        mismatches: List[PrivilegeMismatch] = []
        agents = sorted(self._policy.agents)

        for i, name_a in enumerate(agents):
            cfg_a = self._policy.agents[name_a]
            for name_b in agents:
                if name_a == name_b:
                    continue
                cfg_b = self._policy.agents[name_b]

                # Check each allow/approve rule of B against A
                for rule_b in cfg_b.allow + cfg_b.approve:
                    action = rule_b.action
                    resource = rule_b.resource

                    # Does A have a deny for the same action+resource?
                    a_has_deny = _agent_has_deny(
                        name_a, cfg_a, action, rule_b.resource_segments)

                    # A mismatch is only when A is explicitly denied while
                    # B has allow/approve for the same action+resource.
                    # Different agents having different capabilities is normal.
                    if a_has_deny:
                        reason = (
                            f"{name_b} has allow/approve for {action}"
                            + (f":{resource}" if resource else "")
                            + f" but {name_a} lacks it"
                        )
                        mismatches.append(PrivilegeMismatch(
                            agent_lacking=name_a,
                            agent_having=name_b,
                            action=action,
                            resource=resource,
                            reason=reason,
                        ))

        return mismatches

    # ── Unused capabilities ──────────────────────────────────────────────

    def unused_capabilities(
        self,
        test_cases: Optional[List] = None,
    ) -> List[UnusedCapability]:
        """Find capabilities not exercised by supplied test cases.

        Evidence-based only.  ``test_cases=None`` returns ``[]``
        (insufficient evidence).  Only reports capabilities not matched
        by explicitly supplied requests.
        """
        if test_cases is None:
            return []
        if not test_cases:
            return []

        # Collect all declared capabilities
        capabilities: List[Tuple[str, str, Optional[str], object]] = []
        for agent_name in self._policy.agents:
            agent_cfg = self._policy.agents[agent_name]
            for rule in agent_cfg.allow + agent_cfg.approve:
                capabilities.append((
                    agent_name, rule.action, rule.resource,
                    rule.resource_segments,
                ))

        unused: List[UnusedCapability] = []
        for agent, action, resource, res_segments in capabilities:
            exercised = False
            for req in test_cases:
                req_agent = getattr(req, "agent", None)
                req_action = getattr(req, "action", None)
                req_resource = getattr(req, "resource", None)
                if req_agent != agent or req_action != action:
                    continue
                # Check resource matching
                from .normalize import normalize_request_resource
                req_segments = normalize_request_resource(action, req_resource)
                if _rule_matches_resource(
                    type("R", (), {"resource_segments": res_segments})(),
                    req_segments,
                ):
                    exercised = True
                    break
            if not exercised:
                unused.append(UnusedCapability(
                    agent=agent, action=action, resource=resource,
                ))

        return unused

    # ── Broad permissions ────────────────────────────────────────────────

    def broad_permissions(self) -> List[BroadPermission]:
        """Find overly broad allow rules.

        Detects: ** wildcards, resource=None, * within segments.
        Deny rules are NOT reported as broad.
        """
        results: List[BroadPermission] = []
        for agent_name in sorted(self._policy.agents):
            agent_cfg = self._policy.agents[agent_name]
            for rule in agent_cfg.allow:
                if _is_broad_resource(rule.resource, rule.resource_segments):
                    reason = "no resource constraint" if rule.resource is None else "broad wildcard"
                    results.append(BroadPermission(
                        agent=agent_name,
                        action=rule.action,
                        resource=rule.resource,
                        reason=reason,
                    ))
        return results

    # ── Conflicts ────────────────────────────────────────────────────────

    def conflicts(self) -> List[ConflictEntry]:
        """Find conflicting rules where the same agent has both allow and deny
        for the same action+resource.

        Preserves Phase 3 lint semantics.
        """
        results: List[ConflictEntry] = []
        for agent_name in sorted(self._policy.agents):
            agent_cfg = self._policy.agents[agent_name]
            # Build set of (action, resource) from deny rules
            deny_keys = set()
            for rule in agent_cfg.deny:
                deny_keys.add((rule.action, rule.resource))
            # Check each allow rule against deny rules
            for rule in agent_cfg.allow:
                key = (rule.action, rule.resource)
                if key in deny_keys:
                    results.append(ConflictEntry(
                        agent=agent_name,
                        action=rule.action,
                        resource=rule.resource,
                    ))
        return results

    # ── Reachability ─────────────────────────────────────────────────────

    def reachability(
        self,
        agent: str,
        action: str,
        resource: str = "",
    ) -> ReachabilityResult:
        """Check if a request matches a capability in the policy.

        This is an analysis question, NOT an authorization decision.
        It does NOT evaluate approval state, expiration, revocation,
        or any post-evaluation checks.  It does NOT invoke
        Firewall.check().
        """
        agent_cfg = self._policy.agents.get(agent)
        if agent_cfg is None:
            return ReachabilityResult(
                reachable=False,
                agent=agent,
                action=action,
                resource=resource,
                blocked_by="unknown_agent",
                reason="agent not defined in policy",
            )

        # Normalize resource segments for matching
        from .normalize import normalize_request_resource
        from .model import InvalidRequestError
        try:
            request_segments = normalize_request_resource(action, resource or None)
        except InvalidRequestError:
            return ReachabilityResult(
                reachable=False,
                agent=agent,
                action=action,
                resource=resource,
                blocked_by="invalid_resource",
                reason="resource normalization failed",
            )

        # 1. Check deny rules
        for rule in agent_cfg.deny:
            if rule.action == action and _rule_matches_resource(rule, request_segments):
                return ReachabilityResult(
                    reachable=False,
                    agent=agent,
                    action=action,
                    resource=resource,
                    blocked_by="deny_rule",
                    reason=f"blocked by deny rule {rule.action}"
                           + (f":{rule.resource}" if rule.resource else ""),
                )

        # 2. Check approve rules
        for rule in agent_cfg.approve:
            if rule.action == action and _rule_matches_resource(rule, request_segments):
                return ReachabilityResult(
                    reachable=True,
                    agent=agent,
                    action=action,
                    resource=resource,
                    reason=f"matches approve rule {rule.action}"
                           + (f":{rule.resource}" if rule.resource else ""),
                )

        # 3. Check allow rules
        for rule in agent_cfg.allow:
            if rule.action == action and _rule_matches_resource(rule, request_segments):
                return ReachabilityResult(
                    reachable=True,
                    agent=agent,
                    action=action,
                    resource=resource,
                    reason=f"matches allow rule {rule.action}"
                           + (f":{rule.resource}" if rule.resource else ""),
                )

        # 4. Default deny
        return ReachabilityResult(
            reachable=False,
            agent=agent,
            action=action,
            resource=resource,
            blocked_by="default_deny",
            reason="no matching rule",
        )

    # ── Serialization ────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return the complete analysis as a JSON-serializable dict."""
        return {
            "permission_graph": [n.to_dict() for n in self.permission_graph()],
            "privilege_mismatches": [m.to_dict() for m in self.privilege_mismatches()],
            "broad_permissions": [b.to_dict() for b in self.broad_permissions()],
            "conflicts": [c.to_dict() for c in self.conflicts()],
        }

    def to_text(self) -> str:
        """Return the complete analysis as human-readable text."""
        lines: List[str] = []
        graph = self.permission_graph()
        if graph:
            lines.append("Permission Graph:")
            for node in graph:
                lines.append(f"  {node.to_text()}")

        mismatches = self.privilege_mismatches()
        if mismatches:
            lines.append("Privilege Mismatches:")
            for m in mismatches:
                lines.append(f"  {m.to_text()}")

        broad = self.broad_permissions()
        if broad:
            lines.append("Broad Permissions:")
            for b in broad:
                lines.append(f"  {b.to_text()}")

        conflicts = self.conflicts()
        if conflicts:
            lines.append("Conflicts:")
            for c in conflicts:
                lines.append(f"  {c.to_text()}")

        return "\n".join(lines)
