"""Deterministic, pure policy evaluation (the authorization core).

Flow (DESIGN 13, IMPLEMENTATION 8):

    request -> validate -> normalize -> locate agent
        -> match deny -> match approve -> match allow -> default DENY
        -> decision

The evaluator is side-effect free: it never executes commands, touches the
network, writes files, mutates policy, or calls an LLM. It has no mutable
global state. The same normalized request against the same immutable Policy
snapshot always yields the same decision.
"""

from typing import Optional, Tuple

from .model import Decision, DecisionKind, Request, Rule
from .normalize import (
    normalize_request_resource,
    resource_matches,
    validate_request,
)
from .policy import Policy


def _matches(rule: Rule,
             action: str,
             request_segments: Optional[Tuple[str, ...]]) -> bool:
    """Rule matches when actions are equal AND the resource pattern matches.

    A rule with no resource applies to the action generally (SPEC 10).
    """
    if rule.action != action:
        return False
    return resource_matches(request_segments, rule.resource_segments)


def evaluate(request: Request, policy: Policy) -> Decision:
    """Evaluate one request against one immutable policy snapshot.

    Raises InvalidRequestError on a malformed request; never produces ALLOW
    for unknown agents, unknown actions, unknown resources or failed
    normalization (SPEC 4/36).
    """
    validate_request(request)
    action = request.action
    # Normalize the request resource once, per its action class.
    request_segments = normalize_request_resource(action, request.resource)

    version = policy.version
    generation = policy.generation

    agent_cfg = policy.agents.get(request.agent)
    if agent_cfg is None:
        return Decision(
            kind=DecisionKind.DENY,
            agent=request.agent,
            action=action,
            resource=request.resource,
            reason="unknown agent",
            policy_version=version,
            policy_generation=generation,
        )

    # 1. deny
    for rule in agent_cfg.deny:
        if _matches(rule, action, request_segments):
            return Decision(
                kind=DecisionKind.DENY,
                agent=request.agent,
                action=action,
                resource=request.resource,
                rule=rule,
                reason=f"denied by rule {rule.action}"
                       + (f":{rule.resource}" if rule.resource else ""),
                policy_version=version,
                policy_generation=generation,
            )
    # 2. approve
    for rule in agent_cfg.approve:
        if _matches(rule, action, request_segments):
            return Decision(
                kind=DecisionKind.APPROVE,
                agent=request.agent,
                action=action,
                resource=request.resource,
                rule=rule,
                reason=f"approval required by rule {rule.action}"
                       + (f":{rule.resource}" if rule.resource else ""),
                policy_version=version,
                policy_generation=generation,
            )
    # 3. allow
    for rule in agent_cfg.allow:
        if _matches(rule, action, request_segments):
            return Decision(
                kind=DecisionKind.ALLOW,
                agent=request.agent,
                action=action,
                resource=request.resource,
                rule=rule,
                reason=f"allowed by rule {rule.action}"
                       + (f":{rule.resource}" if rule.resource else ""),
                policy_version=version,
                policy_generation=generation,
            )
    # 4. default deny
    return Decision(
        kind=DecisionKind.DENY,
        agent=request.agent,
        action=action,
        resource=request.resource,
        reason="no matching rule - default deny",
        policy_version=version,
        policy_generation=generation,
    )