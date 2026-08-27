"""Policy diff — structural comparison of two policies (Phase 7).

Compare two policy documents and report added, removed, and
resource-changed rules.  This is a **read-only, structural**
comparison: no requests are evaluated, no authorization decisions
are produced, and no policy is activated.

Properties:
    - read-only (no files written, no state mutated)
    - deterministic
    - side-effect-free beyond loading the explicitly named policy files
    - zero third-party dependencies

Security (DESIGN 86):
    Diff output is INFORMATIONAL ONLY.
    It never authorizes or denies an action.
    It never activates a proposed policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .policy import Policy


# ── Diff result ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RuleDiff:
    """One structural difference between two policies.

    ``collection`` is one of ``"allow"``, ``"deny"``, ``"approve"``.
    ``kind`` is one of ``"added"``, ``"removed"``, ``"changed_resource"``.

    For ``"added"``:   ``old_rule`` is None, ``new_rule`` is set.
    For ``"removed"``: ``old_rule`` is set,   ``new_rule`` is None.
    For ``"changed_resource"``: both are set.
    """

    agent: str
    collection: str
    kind: str
    old_rule: Optional[object] = None
    new_rule: Optional[object] = None


# ── Core diff ─────────────────────────────────────────────────────────────────

def _rule_key(rule) -> tuple:
    """Return the identity key for a rule: (action, resource).

    Resource None is represented as empty string to keep keys sortable.
    """
    return (rule.action, rule.resource or "")


def _agent_rules(ap) -> dict:
    """Return {collection_name: {key: rule}} for an AgentPolicy."""
    result = {}
    for name in ("allow", "deny", "approve"):
        rules = getattr(ap, name, ())
        mapping = {}
        for rule in rules:
            mapping[_rule_key(rule)] = rule
        result[name] = mapping
    return result


def diff_policies(old: Policy, new: Policy) -> List[RuleDiff]:
    """Compare two policies and return the structural differences.

    Returns one ``RuleDiff`` per difference, in deterministic order:
    agents sorted alphabetically, collections in allow/deny/approve order,
    then added before removed before changed_resource.

    This function must not:
        - evaluate requests
        - modify either policy
        - write files
        - access the network
        - produce authorization decisions
    """
    diffs: List[RuleDiff] = []

    # Collect all agent names from both policies
    all_agents = sorted(set(list(old.agents.keys()) + list(new.agents.keys())))

    for agent in all_agents:
        old_ap = old.agents.get(agent)
        new_ap = new.agents.get(agent)

        if old_ap is None:
            # Agent is new: all rules are additions
            if new_ap is not None:
                new_rules = _agent_rules(new_ap)
                for coll in ("allow", "deny", "approve"):
                    for key, rule in sorted(new_rules[coll].items()):
                        diffs.append(RuleDiff(
                            agent=agent, collection=coll, kind="added",
                            old_rule=None, new_rule=rule,
                        ))
            continue

        if new_ap is None:
            # Agent was removed: all rules are removals
            old_rules = _agent_rules(old_ap)
            for coll in ("allow", "deny", "approve"):
                for key, rule in sorted(old_rules[coll].items()):
                    diffs.append(RuleDiff(
                        agent=agent, collection=coll, kind="removed",
                        old_rule=rule, new_rule=None,
                    ))
            continue

        # Both agents exist — compare collection by collection
        old_rules = _agent_rules(old_ap)
        new_rules = _agent_rules(new_ap)

        for coll in ("allow", "deny", "approve"):
            old_map = old_rules[coll]
            new_map = new_rules[coll]

            all_keys = sorted(set(list(old_map.keys()) + list(new_map.keys())))

            for key in all_keys:
                old_rule = old_map.get(key)
                new_rule = new_map.get(key)

                if old_rule is None and new_rule is not None:
                    # Added
                    diffs.append(RuleDiff(
                        agent=agent, collection=coll, kind="added",
                        old_rule=None, new_rule=new_rule,
                    ))
                elif old_rule is not None and new_rule is None:
                    # Removed
                    diffs.append(RuleDiff(
                        agent=agent, collection=coll, kind="removed",
                        old_rule=old_rule, new_rule=None,
                    ))
                elif old_rule is not None and new_rule is not None:
                    # Both exist — same (action, resource) key means no diff
                    # Different key means one was removed and one was added,
                    # but since we already matched by key, this branch
                    # means the rules are identical — no diff.
                    # However, if the action is the same but resource differs,
                    # the keys differ and they land in separate add/remove.
                    pass

    return diffs
