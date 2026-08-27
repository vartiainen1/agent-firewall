"""Orchestrator integration — thin query layer for external orchestrators (Phase 13).

Provides structured authorization queries for orchestrators.  The orchestrator
remains responsible for task decomposition, agent selection, scheduling, and
coordination.  The firewall remains responsible for authorization (ROADMAP 13,
DESIGN 50).

Architecture (DESIGN 50, 111):
    orchestrator → firewall → Decision → orchestrator decides → adapter/sandbox

This module sits at the "orchestrator → firewall" boundary only.  It does NOT:
- execute filesystem, process, Git, network, or MCP operations
- contain scheduling or task-decomposition logic
- duplicate evaluator logic
- introduce third-party dependencies
- modify the policy or evaluator

The bridge delegates every authorization query to ``Firewall.check()`` and
preserves its deterministic, side-effect-free behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, TYPE_CHECKING

from .model import Decision, InvalidRequestError, Request

if TYPE_CHECKING:
    from . import Firewall


# ── Structured result ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TaskAuthorization:
    """Structured authorization result for orchestrator consumption.

    Immutable/frozen: once created, the result cannot be mutated.  This
    preserves the same immutability guarantee as the core Decision and
    Policy snapshot (DESIGN 29, SECURITY 13).
    """

    decision: Decision
    agent: str
    action: str
    resource: Optional[str] = None
    reason: str = ""


# ── Orchestrator bridge ──────────────────────────────────────────────────────


class OrchestratorBridge:
    """Thin orchestrator integration for agent-firewall.

    Provides structured authorization queries for external orchestrators.
    Does NOT contain scheduling, task decomposition, or execution logic.

    The firewall owns authorization.  The orchestrator owns coordination
    (DESIGN 50).

    Usage::

        from agent_firewall import Firewall
        from agent_firewall.orchestrator import OrchestratorBridge

        firewall = Firewall.from_file("policy.json")
        bridge = OrchestratorBridge(firewall)

        decision = bridge.can_perform("developer", "filesystem.write", "./src/main.py")
        # decision.kind is DecisionKind.ALLOW, DENY, or APPROVE
    """

    def __init__(self, firewall: "Firewall") -> None:
        """Create a bridge over an existing Firewall instance.

        The bridge holds a reference to the firewall's immutable policy
        snapshot.  It does not copy, cache, or mutate the policy.
        """
        self._firewall = firewall

    @property
    def firewall(self) -> "Firewall":
        """The underlying firewall instance (read-only access)."""
        return self._firewall

    # ── Primary query ────────────────────────────────────────────────────

    def can_perform(
        self, agent: str, action: str, resource: str = None
    ) -> Decision:
        """Can this agent perform this action?

        Delegates directly to ``Firewall.check()``.  Returns the Decision
        without modification.  Never converts errors into ALLOW.

        Raises ``InvalidRequestError`` for malformed requests (SPEC 36).
        """
        request = Request(agent=agent, action=action, resource=resource)
        return self._firewall.check(request)

    # ── Batch query ──────────────────────────────────────────────────────

    def can_perform_batch(self, requests: List[Request]) -> List[Decision]:
        """Evaluate multiple requests against the same policy snapshot.

        Returns one Decision per Request, in the same order as the input.
        Uses sequential ``Firewall.check()`` calls — no separate evaluator
        is introduced, and no caching or concurrency is added.

        An empty input list returns an empty result list.
        """
        return [self._firewall.check(r) for r in requests]

    # ── Structured result ────────────────────────────────────────────────

    def evaluate_task(
        self, agent: str, action: str, resource: str = None
    ) -> TaskAuthorization:
        """Evaluate a task and return structured authorization information.

        Returns a frozen ``TaskAuthorization`` with the decision and
        metadata preserved from the underlying ``Firewall.check()`` call.
        """
        request = Request(agent=agent, action=action, resource=resource)
        decision = self._firewall.check(request)
        return TaskAuthorization(
            decision=decision,
            agent=decision.agent,
            action=decision.action,
            resource=decision.resource,
            reason=decision.reason,
        )
