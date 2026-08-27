"""Advisory policy suggestion engine (Phase 17).

This module generates policy modification proposals from observations
and analysis findings.  It is strictly advisory: it never modifies the
active policy, never calls Firewall.check(), never produces Decision
objects, and never writes to disk.

Trust model (ROADMAP Phase 17, DESIGN 82):

    observed behavior
        |
        v
    analysis / evidence
        |
        v
    policy suggestion        <-- this module
        |
        v
    human review
        |
        v
    explicit external activation
        |
        v
    active policy

Design constraints:
    - Advisory only: suggestions never become authorization decisions.
    - Never mutates the source Policy.
    - Never modifies the active policy.
    - Never calls Firewall.check() or the evaluator.
    - Never produces Decision or DecisionKind objects.
    - Never writes to disk or accesses the network.
    - Deterministic for identical inputs.
    - Zero third-party runtime dependencies.
    - Malformed input fails safely.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .model import Rule
from .policy import AgentPolicy, Policy, policy_from_dict


# ── Exceptions ──────────────────────────────────────────────────────────────


class SuggestionError(Exception):
    """Base exception for suggestion-related errors."""


class InvalidSuggestionError(SuggestionError):
    """Raised when a suggestion is structurally invalid."""


# ── Data structures ─────────────────────────────────────────────────────────


_VALID_SUGGESTION_TYPES = ("add_rule", "remove_rule")
_VALID_COLLECTIONS = ("allow", "deny", "approve")


@dataclass(frozen=True)
class PolicySuggestion:
    """A proposed policy change.  Advisory only.

    This is a proposal, not an authorization decision.  It never modifies
    the active policy, evaluator, or any filesystem state.  It must be
    reviewed by a human before any policy activation occurs.

    The ``rule`` dict is defensively copied on construction so callers
    cannot mutate suggestion state through the original dictionary.
    """

    suggestion_type: str
    agent: str
    collection: str
    rule: Dict[str, Any]
    reason: str = ""
    evidence: str = ""

    def __post_init__(self) -> None:
        # Frozen dataclass prevents attribute reassignment, but we need
        # to defensively copy the mutable rule dict.  Use object.__setattr__
        # because the dataclass is frozen.
        if not isinstance(self.suggestion_type, str):
            raise TypeError("suggestion_type must be a string")
        if self.suggestion_type not in _VALID_SUGGESTION_TYPES:
            raise ValueError(
                f"suggestion_type must be one of {_VALID_SUGGESTION_TYPES}, "
                f"got {self.suggestion_type!r}"
            )
        if not isinstance(self.agent, str) or not self.agent:
            raise ValueError("agent must be a non-empty string")
        if not isinstance(self.collection, str):
            raise TypeError("collection must be a string")
        if self.collection not in _VALID_COLLECTIONS:
            raise ValueError(
                f"collection must be one of {_VALID_COLLECTIONS}, "
                f"got {self.collection!r}"
            )
        if not isinstance(self.rule, dict):
            raise TypeError("rule must be a dict")
        # Defensive copy: make the stored rule an independent copy
        object.__setattr__(self, "rule", copy.deepcopy(self.rule))

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable dict representation."""
        d: Dict[str, Any] = {
            "suggestion_type": self.suggestion_type,
            "agent": self.agent,
            "collection": self.collection,
            "rule": copy.deepcopy(self.rule),
        }
        if self.reason:
            d["reason"] = self.reason
        if self.evidence:
            d["evidence"] = self.evidence
        return d

    def to_text(self) -> str:
        """Return a human-readable text representation."""
        rule_desc = json.dumps(self.rule, sort_keys=True)
        return (
            f"{self.suggestion_type}: {self.agent} {self.collection} {rule_desc}"
            + (f"  ({self.reason})" if self.reason else "")
        )


# ── Engine ──────────────────────────────────────────────────────────────────


def _normalize_rule(rule: Any) -> Optional[Dict[str, Any]]:
    """Attempt to normalize a raw dict into a valid rule dict.

    Returns None if the input is not a usable rule.  Never raises.
    """
    if not isinstance(rule, dict):
        return None
    action = rule.get("action")
    if not isinstance(action, str) or not action:
        return None
    resource = rule.get("resource")
    if resource is not None and not isinstance(resource, str):
        return None
    normalized: Dict[str, Any] = {"action": action}
    if resource is not None:
        normalized["resource"] = resource
    # Only include known rule fields
    return normalized


class PolicySuggestionEngine:
    """Generates policy suggestions from observations and analysis findings.

    This engine is strictly advisory.  It:

    - NEVER modifies the source policy
    - NEVER modifies the active policy
    - NEVER calls Firewall.check()
    - NEVER produces Decision objects
    - NEVER writes to disk
    - NEVER accesses the network
    - NEVER activates suggestions

    Suggestions must be reviewed by a human before any policy activation
    occurs.
    """

    def __init__(self, policy: Policy) -> None:
        """Initialize with an immutable policy snapshot.

        The engine holds a read-only reference to the policy.  It never
        modifies the provided policy.
        """
        if not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy instance")
        self._policy = policy

    @property
    def policy(self) -> Policy:
        """Return the source policy (read-only reference)."""
        return self._policy

    def suggest_from_findings(
        self,
        findings: List[Any],
    ) -> List[PolicySuggestion]:
        """Generate suggestions from analysis findings.

        Accepts findings from PolicyAnalyzer (Phase 16) or compatible
        analysis objects.  Each finding may produce zero or more
        suggestions.

        Returns an empty list if no suggestions are warranted.
        Never modifies the source policy.
        """
        if not findings:
            return []

        suggestions: List[PolicySuggestion] = []

        for finding in findings:
            name = type(finding).__name__
            if not (hasattr(finding, "agent") and hasattr(finding, "action")):
                continue
            agent = finding.agent
            action = finding.action
            resource = getattr(finding, "resource", None)

            if name == "BroadPermission":
                # BroadPermission → suggest adding deny rule
                reason_text = getattr(finding, "reason", "broad permission detected")
                rule_dict = {"action": action}
                if resource is not None:
                    rule_dict["resource"] = resource
                suggestions.append(PolicySuggestion(
                    suggestion_type="add_rule",
                    agent=agent,
                    collection="deny",
                    rule=rule_dict,
                    reason=f"Broad allow detected: {reason_text}",
                    evidence=f"broad_permission: {agent} {action}"
                             + (f" {resource}" if resource else ""),
                ))

            elif name == "UnusedCapability":
                # UnusedCapability → suggest removing allow rule
                rule_dict = {"action": action}
                if resource is not None:
                    rule_dict["resource"] = resource
                suggestions.append(PolicySuggestion(
                    suggestion_type="remove_rule",
                    agent=agent,
                    collection="allow",
                    rule=rule_dict,
                    reason="Capability appears unused by supplied test cases",
                    evidence=f"unused_capability: {agent} {action}"
                             + (f" {resource}" if resource else ""),
                ))

            elif name == "ConflictEntry":
                # ConflictEntry → suggest removing the deny rule
                rule_dict = {"action": action}
                if resource is not None:
                    rule_dict["resource"] = resource
                suggestions.append(PolicySuggestion(
                    suggestion_type="remove_rule",
                    agent=agent,
                    collection="deny",
                    rule=rule_dict,
                    reason="Conflicting allow and deny rules for same agent",
                    evidence=f"conflict: {agent} {action}"
                             + (f" {resource}" if resource else ""),
                ))

        return suggestions

    def suggest_from_audit(
        self,
        audit_records: List[dict],
    ) -> List[PolicySuggestion]:
        """Generate suggestions from audit evidence records.

        Each audit record is a dict as produced by EvidenceLogger.
        Malformed records are skipped, not raised as errors.

        Returns an empty list if no suggestions are warranted.
        Never modifies the source policy.
        """
        if not audit_records:
            return []

        suggestions: List[PolicySuggestion] = []
        denied_actions: Dict[str, Dict[str, int]] = {}  # agent -> {action: count}

        for record in audit_records:
            if not isinstance(record, dict):
                continue
            agent = record.get("agent")
            action = record.get("action")
            decision = record.get("decision")
            if not isinstance(agent, str) or not isinstance(action, str):
                continue
            if not isinstance(decision, str):
                continue

            if decision == "DENY":
                if agent not in denied_actions:
                    denied_actions[agent] = {}
                denied_actions[agent][action] = denied_actions[agent].get(action, 0) + 1

        # For agents with multiple denials of the same action, suggest review
        for agent, actions in sorted(denied_actions.items()):
            for action, count in sorted(actions.items()):
                if count >= 3:
                    suggestions.append(PolicySuggestion(
                        suggestion_type="add_rule",
                        agent=agent,
                        collection="deny",
                        rule={"action": action},
                        reason=f"Agent {agent} denied {action} {count} times — review whether explicit deny is needed",
                        evidence=f"audit_deny_frequency: {agent} {action} denied {count} times",
                    ))

        return suggestions

    def validate_suggestion(
        self,
        suggestion: PolicySuggestion,
    ) -> bool:
        """Check whether a suggestion would produce valid policy structure.

        Returns True if the suggestion's rule dict is well-formed and
        compatible with the current policy version.
        Returns False otherwise.  Never raises.
        Never modifies anything.
        """
        if not isinstance(suggestion, PolicySuggestion):
            return False

        # Validate suggestion type
        if suggestion.suggestion_type not in _VALID_SUGGESTION_TYPES:
            return False

        # Validate collection
        if suggestion.collection not in _VALID_COLLECTIONS:
            return False

        # Validate agent is non-empty string
        if not isinstance(suggestion.agent, str) or not suggestion.agent:
            return False

        # Validate rule structure
        rule = suggestion.rule
        if not isinstance(rule, dict):
            return False

        action = rule.get("action")
        if not isinstance(action, str) or not action:
            return False

        resource = rule.get("resource")
        if resource is not None and not isinstance(resource, str):
            return False

        # For remove_rule, check that the rule actually exists in the policy
        if suggestion.suggestion_type == "remove_rule":
            agent_cfg = self._policy.agents.get(suggestion.agent)
            if agent_cfg is None:
                return False
            collection_rules = getattr(agent_cfg, suggestion.collection, ())
            found = False
            for existing_rule in collection_rules:
                if existing_rule.action == action:
                    if resource is None and existing_rule.resource is None:
                        found = True
                        break
                    if resource is not None and existing_rule.resource == resource:
                        found = True
                        break
            if not found:
                return False

        return True


# ── Pure functions ──────────────────────────────────────────────────────────


def proposed_policy(
    source: Policy,
    suggestions: List[PolicySuggestion],
) -> Policy:
    """Construct a new inactive Policy from suggestions.

    Returns a NEW Policy object.  Never modifies:

    - the source Policy
    - the active policy
    - the evaluator
    - any filesystem state
    - any authorization state

    The returned Policy is inactive until explicitly loaded by a human
    or trusted authority.
    """
    if not isinstance(source, Policy):
        raise TypeError("source must be a Policy instance")

    # Start by deep-copying the existing agents dict
    new_agents: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    for agent_name, agent_cfg in source.agents.items():
        new_agents[agent_name] = {
            "allow": [copy.deepcopy({"action": r.action, "resource": r.resource})
                      for r in agent_cfg.allow],
            "deny": [copy.deepcopy({"action": r.action, "resource": r.resource})
                     for r in agent_cfg.deny],
            "approve": [copy.deepcopy({"action": r.action, "resource": r.resource})
                        for r in agent_cfg.approve],
        }

    # Apply suggestions in order
    for suggestion in suggestions:
        if not isinstance(suggestion, PolicySuggestion):
            continue

        agent = suggestion.agent
        collection = suggestion.collection
        rule = suggestion.rule
        action = rule.get("action")
        resource = rule.get("resource")

        if suggestion.suggestion_type == "add_rule":
            # Ensure agent exists in new policy
            if agent not in new_agents:
                new_agents[agent] = {"allow": [], "deny": [], "approve": []}

            # Check for duplicate before adding
            existing = new_agents[agent].get(collection, [])
            is_duplicate = False
            for existing_rule in existing:
                if existing_rule.get("action") == action:
                    if (resource is None and existing_rule.get("resource") is None) or \
                       (resource is not None and existing_rule.get("resource") == resource):
                        is_duplicate = True
                        break
            if not is_duplicate:
                new_agents[agent][collection].append(copy.deepcopy(rule))

        elif suggestion.suggestion_type == "remove_rule":
            if agent in new_agents and collection in new_agents[agent]:
                new_agents[agent][collection] = [
                    r for r in new_agents[agent][collection]
                    if not (r.get("action") == action and
                            ((resource is None and r.get("resource") is None) or
                             (resource is not None and r.get("resource") == resource)))
                ]

    # Build the new policy through the standard policy_from_dict path
    policy_dict = {
        "version": source.version,
        "agents": {},
    }

    for agent_name, collections in new_agents.items():
        agent_dict: Dict[str, Any] = {}
        for coll_name in ("allow", "deny", "approve"):
            rules = collections.get(coll_name, [])
            if rules:
                agent_dict[coll_name] = [
                    copy.deepcopy(r) for r in rules
                ]
        policy_dict["agents"][agent_name] = agent_dict

    return policy_from_dict(policy_dict, generation=source.generation + 1)


def export_suggestions(
    suggestions: List[PolicySuggestion],
    fmt: str = "json",
) -> str:
    """Serialize suggestions as a machine-readable string.

    Supported formats: ``"json"``, ``"text"``.
    Returns a deterministic string representation.
    Never writes to disk.  Never accesses the network.
    """
    if fmt == "json":
        data = [s.to_dict() for s in suggestions]
        return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)
    elif fmt == "text":
        if not suggestions:
            return ""
        lines = [s.to_text() for s in suggestions]
        return "\n".join(lines) + "\n"
    else:
        raise ValueError(f"unsupported format {fmt!r} (use 'json' or 'text')")
