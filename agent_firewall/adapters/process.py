"""Process adapter — authorized process execution (Phase 9).

Combines authorization with execution for process spawning.
Each operation:
    1. Builds a structured Request(agent, "process.spawn", executable)
    2. Calls Firewall.check() to get a Decision
    3. Executes the process ONLY if ALLOW
    4. Raises an error for DENY, APPROVE, or any error

Security (DESIGN 22, SECURITY 18, THREAT_MODEL 7/29):
    - Never executes on DENY
    - Never executes on APPROVE
    - Never executes on error
    - Never treats firewall errors as ALLOW
    - Preserves agent identity
    - Uses list-based subprocess invocation (never shell=True)
    - Does not parse arbitrary shell strings
    - Authorization covers the executable name only, not arguments

Properties:
    - Depends on the core (Firewall); the core never depends on adapters
    - Zero third-party dependencies
    - Deterministic authorization path

Limitations (THREAT_MODEL 29):
    - Authorization covers the executable name, not command-line arguments
    - Shell injection via arguments is an enforcement-layer concern
    - The adapter does not parse or interpret shell strings
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, List, Optional

from ..model import DecisionKind, InvalidRequestError, Request

if TYPE_CHECKING:
    from .. import Firewall


# ── Exceptions ────────────────────────────────────────────────────────────────

class ProcessDeniedError(Exception):
    """Raised when the firewall denies process execution.

    The requested process is NOT started.
    """

    def __init__(self, agent: str, action: str, resource: str,
                 reason: str = "") -> None:
        self.agent = agent
        self.action = action
        self.resource = resource
        self.reason = reason
        msg = f"denied: {agent} {action} {resource}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


class ProcessApprovalRequiredError(Exception):
    """Raised when the firewall requires approval for process execution.

    The requested process is NOT started.
    """

    def __init__(self, agent: str, action: str, resource: str,
                 reason: str = "") -> None:
        self.agent = agent
        self.action = action
        self.resource = resource
        self.reason = reason
        msg = f"approval required: {agent} {action} {resource}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


class ProcessError(Exception):
    """Raised when the firewall encounters an error during authorization.

    The requested process is NOT started.  This covers invalid
    requests, invalid policies, and unexpected errors.  The adapter
    must NOT treat this as ALLOW.
    """

    def __init__(self, agent: str, action: str, resource: str,
                 reason: str = "") -> None:
        self.agent = agent
        self.action = action
        self.resource = resource
        self.reason = reason
        msg = f"error: {agent} {action} {resource}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


# ── Adapter ───────────────────────────────────────────────────────────────────

class ProcessAdapter:
    """Optional adapter that combines process authorization with execution.

    The adapter depends on the core (Firewall).  The core never depends
    on adapters (DESIGN 48).

    Usage::

        firewall = Firewall.from_file("policy.json")
        adapter = ProcessAdapter(firewall)

        # Spawn (authorized)
        result = adapter.spawn("developer", "pytest", ["-v"])

        # Spawn without args
        result = adapter.spawn("developer", "python")

    Security:
        - ALLOW  → execute the process via subprocess.run()
        - DENY   → raise ProcessDeniedError
        - APPROVE → raise ProcessApprovalRequiredError
        - error  → raise ProcessError

    Limitations:
        - Authorization covers the executable name only
        - Command-line arguments are NOT authorized by the firewall
        - Shell injection via arguments is an enforcement-layer concern
        - The adapter does not parse shell strings
    """

    def __init__(self, firewall: "Firewall") -> None:
        """Initialize with an existing Firewall instance.

        The firewall holds the immutable policy snapshot.  The adapter
        does not modify the firewall or its policy.
        """
        self._firewall = firewall

    def _check(self, agent: str, action: str,
               resource: str) -> None:
        """Authorize the operation.  Raises on DENY / APPROVE / error.

        This method must NOT catch ProcessDeniedError or
        ProcessApprovalRequiredError — those propagate to the caller.
        """
        request = Request(agent=agent, action=action, resource=resource)
        try:
            decision = self._firewall.check(request)
        except InvalidRequestError as exc:
            raise ProcessError(
                agent, action, resource, str(exc)
            ) from exc
        except Exception as exc:
            raise ProcessError(
                agent, action, resource, str(exc)
            ) from exc

        if decision.kind is DecisionKind.ALLOW:
            return  # authorized

        if decision.kind is DecisionKind.DENY:
            raise ProcessDeniedError(
                agent, action, resource, decision.reason
            )

        if decision.kind is DecisionKind.APPROVE:
            raise ProcessApprovalRequiredError(
                agent, action, resource, decision.reason
            )

        # Should never reach here, but fail closed if it does
        raise ProcessError(
            agent, action, resource,
            f"unexpected decision kind: {decision.kind}"
        )

    def spawn(
        self,
        agent: str,
        executable: str,
        args: Optional[List[str]] = None,
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """Spawn a process if authorized.

        Uses ``subprocess.run()`` with list-based invocation.  The
        ``shell`` parameter is never set to ``True``.

        The resource in the authorization request is the executable
        name only.  Arguments are NOT authorized by the firewall.

        Args:
            agent: The agent identifier for authorization.
            executable: The executable name (resource for authorization).
            args: Optional list of arguments passed to the executable.
            **kwargs: Passed through to ``subprocess.run()`` (e.g.
                ``cwd``, ``env``, ``timeout``, ``capture_output``).

        Returns:
            ``subprocess.CompletedProcess`` from ``subprocess.run()``.

        Raises:
            ProcessDeniedError: if the firewall denies the operation
            ProcessApprovalRequiredError: if approval is required
            ProcessError: on authorization errors
            FileNotFoundError: if executable not found (after auth)
            PermissionError: if OS denies access (after auth)
            subprocess.TimeoutExpired: if timeout exceeded (after auth)
        """
        # Never allow shell=True — this is a security invariant
        kwargs.pop("shell", None)

        self._check(agent, "process.spawn", executable)

        cmd = [executable]
        if args:
            cmd.extend(args)

        return subprocess.run(cmd, **kwargs)
