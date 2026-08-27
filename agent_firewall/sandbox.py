"""Sandbox integration — authorized execution within an external sandbox (Phase 14).

Provides a thin adapter that authorizes operations through the firewall
before delegating execution to a caller-supplied external sandbox.

Architecture (DESIGN 51, ROADMAP 14):

    caller / orchestrator
            |
            v
        SandboxAdapter
            |
            |-- builds Request
            |-- calls Firewall.check()
            |
            +-- ALLOW  → external sandbox executes
            +-- DENY   → SandboxDeniedError (never execute)
            +-- APPROVE → SandboxApprovalRequiredError (never execute)
            +-- error  → SandboxError (never execute)

The sandbox owns isolation.  The firewall owns authorization.
Neither layer replaces the other (DESIGN 51).

This module is ONLY an integration layer.  It does NOT:
- implement process isolation
- implement filesystem isolation
- implement network isolation
- implement containers, namespaces, or VMs
- implement resource limits
- implement OS sandboxing
- add third-party dependencies
- modify the firewall evaluator or policy
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable, TYPE_CHECKING

from .model import Decision, DecisionKind, InvalidRequestError, Request

if TYPE_CHECKING:
    from . import Firewall


# ── Exceptions ────────────────────────────────────────────────────────────────


class SandboxDeniedError(Exception):
    """Raised when the firewall denies a sandbox operation.

    The requested operation is NOT performed.  The sandbox is never called.
    """

    def __init__(self, agent: str, action: str, resource: str = "",
                 reason: str = "") -> None:
        self.agent = agent
        self.action = action
        self.resource = resource
        self.reason = reason
        msg = f"denied: {agent} {action}"
        if resource:
            msg += f" {resource}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


class SandboxApprovalRequiredError(Exception):
    """Raised when the firewall requires approval for a sandbox operation.

    The requested operation is NOT performed.  The sandbox is never called.
    """

    def __init__(self, agent: str, action: str, resource: str = "",
                 reason: str = "") -> None:
        self.agent = agent
        self.action = action
        self.resource = resource
        self.reason = reason
        msg = f"approval required: {agent} {action}"
        if resource:
            msg += f" {resource}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


class SandboxError(Exception):
    """Raised when the firewall encounters an error during authorization.

    The requested operation is NOT performed.  The sandbox is never called.
    This covers invalid requests, invalid policies, unexpected errors,
    and sandbox execution failures.  The adapter must NOT treat this as
    ALLOW.
    """

    def __init__(self, agent: str, action: str, resource: str = "",
                 reason: str = "") -> None:
        self.agent = agent
        self.action = action
        self.resource = resource
        self.reason = reason
        msg = f"error: {agent} {action}"
        if resource:
            msg += f" {resource}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


# ── Sandbox protocol ──────────────────────────────────────────────────────────


@runtime_checkable
class SandboxProtocol(Protocol):
    """Protocol defining what an external sandbox must provide.

    The sandbox owns isolation (DESIGN 51).  The adapter does not
    implement isolation — it delegates to this protocol supplied by
    the caller.

    Any callable with the correct signature satisfies this protocol.
    """

    def execute(self, action: str, resource: Optional[str] = None,
                **kwargs: Any) -> Any:
        """Execute the operation within the sandbox isolation boundary.

        The sandbox is responsible for:
        - process isolation
        - filesystem isolation
        - network isolation
        - resource limits
        - environment control

        The adapter has already authorized this operation.
        """
        ...


# ── Structured result ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SandboxResult:
    """Structured result from a sandboxed execution.

    Immutable/frozen: once created, the result cannot be mutated.
    Preserves the authorization decision alongside the sandbox output.
    """

    decision: Decision
    agent: str
    action: str
    resource: Optional[str] = None
    result: Any = None


# ── Sandbox adapter ──────────────────────────────────────────────────────────


class SandboxAdapter:
    """Optional adapter that combines sandbox authorization with execution.

    The adapter depends on the core (Firewall).  The core never depends
    on adapters (DESIGN 48).

    The sandbox is an external component supplied by the caller.
    The adapter authorizes the operation; the sandbox isolates it.
    Neither layer replaces the other (DESIGN 51).

    Usage::

        from agent_firewall import Firewall
        from agent_firewall.sandbox import SandboxAdapter

        firewall = Firewall.from_file("policy.json")

        # External sandbox supplied by the caller
        my_sandbox = MySandboxImplementation()

        adapter = SandboxAdapter(firewall, my_sandbox)

        # Authorized sandboxed execution
        result = adapter.execute("developer", "process.spawn", "pytest")
    """

    def __init__(self, firewall: "Firewall",
                 sandbox: SandboxProtocol) -> None:
        """Create a sandbox adapter over an existing Firewall and sandbox.

        The firewall provides authorization.  The sandbox provides
        isolation.  The adapter bridges them without implementing either.
        """
        self._firewall = firewall
        self._sandbox = sandbox

    @property
    def firewall(self) -> "Firewall":
        """The underlying firewall instance (read-only access)."""
        return self._firewall

    @property
    def sandbox(self) -> SandboxProtocol:
        """The underlying sandbox instance (read-only access)."""
        return self._sandbox

    # ── Authorized execution ─────────────────────────────────────────────

    def execute(
        self,
        agent: str,
        action: str,
        resource: str = None,
        **kwargs: Any,
    ) -> SandboxResult:
        """Authorize and execute an operation within the sandbox.

        1. Builds Request(agent, action, resource)
        2. Calls Firewall.check() to get a Decision
        3. If ALLOW: delegates to sandbox.execute(action, resource, **kwargs)
        4. If DENY/APPROVE/error: raises, sandbox is never called

        Sandbox execution errors are wrapped in SandboxError to maintain
        fail-closed behavior (never convert errors into ALLOW).
        """
        request = Request(agent=agent, action=action, resource=resource)
        try:
            decision = self._firewall.check(request)
        except InvalidRequestError as exc:
            # Invalid requests must fail closed: never reach sandbox
            raise SandboxError(
                agent=agent, action=action,
                resource=resource or "",
                reason=str(exc),
            ) from exc

        if decision.kind is DecisionKind.DENY:
            raise SandboxDeniedError(
                agent=decision.agent,
                action=decision.action,
                resource=decision.resource or "",
                reason=decision.reason,
            )

        if decision.kind is DecisionKind.APPROVE:
            raise SandboxApprovalRequiredError(
                agent=decision.agent,
                action=decision.action,
                resource=decision.resource or "",
                reason=decision.reason,
            )

        # ALLOW — delegate to the external sandbox
        try:
            sandbox_result = self._sandbox.execute(
                action=action, resource=resource, **kwargs
            )
        except (SandboxDeniedError, SandboxApprovalRequiredError):
            # Let adapter-level exceptions propagate directly
            raise
        except Exception as exc:
            # Sandbox execution errors must not become ALLOW
            raise SandboxError(
                agent=decision.agent,
                action=decision.action,
                resource=decision.resource or "",
                reason=str(exc),
            ) from exc

        return SandboxResult(
            decision=decision,
            agent=decision.agent,
            action=decision.action,
            resource=decision.resource,
            result=sandbox_result,
        )

    # ── Authorization only ───────────────────────────────────────────────

    def check_only(
        self,
        agent: str,
        action: str,
        resource: str = None,
    ) -> Decision:
        """Authorize without executing.  Returns the Decision.

        The sandbox is never called.  This is a pure authorization
        query identical to Firewall.check().
        """
        request = Request(agent=agent, action=action, resource=resource)
        return self._firewall.check(request)
