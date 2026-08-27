"""Git adapter — authorized Git operations (Phase 10).

Combines authorization with execution for Git CLI operations.
Each operation:
    1. Builds a structured Request(agent, "git.<op>", resource)
    2. Calls Firewall.check() to get a Decision
    3. Executes the Git command ONLY if ALLOW
    4. Raises an error for DENY, APPROVE, or any error

Supported operations:
    - git.read   — read-only operations (log, show, diff, status, branch)
    - git.write  — write operations (add, rm, mv, checkout, merge)
    - git.commit — create commits
    - git.push   — push to remotes

Security (DESIGN 23, IMPLEMENTATION 28/31):
    - Never executes on DENY
    - Never executes on APPROVE
    - Never executes on error
    - Never treats firewall errors as ALLOW
    - Preserves agent identity
    - Uses list-based subprocess invocation (never shell=True)
    - Uses Git CLI through subprocess (no Python Git package)
    - Authorization covers the operation type; arguments are opaque

Properties:
    - Depends on the core (Firewall); the core never depends on adapters
    - Zero third-party dependencies
    - Deterministic authorization path

Limitations:
    - Authorization covers the operation type (git.read, etc.), not individual arguments
    - The resource is an opaque policy string
    - Argument-level authorization is future work
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, List, Optional

from ..model import DecisionKind, InvalidRequestError, Request

if TYPE_CHECKING:
    from .. import Firewall


# ── Exceptions ────────────────────────────────────────────────────────────────

class GitDeniedError(Exception):
    """Raised when the firewall denies a Git operation.

    The Git command is NOT executed.
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


class GitApprovalRequiredError(Exception):
    """Raised when the firewall requires approval for a Git operation.

    The Git command is NOT executed.
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


class GitError(Exception):
    """Raised when the firewall encounters an error during authorization.

    The Git command is NOT executed.  This covers invalid requests,
    invalid policies, and unexpected errors.
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

class GitAdapter:
    """Optional adapter that combines Git authorization with execution.

    The adapter depends on the core (Firewall).  The core never depends
    on adapters (DESIGN 48).

    Supported actions:
        - git.read   — read-only operations (log, show, diff, status, branch)
        - git.write  — write operations (add, rm, mv, checkout, merge)
        - git.commit — create commits
        - git.push   — push to remotes

    Usage::

        firewall = Firewall.from_file("policy.json")
        adapter = GitAdapter(firewall)

        # Read (authorized)
        result = adapter.execute("developer", "git.read", "origin",
                                 ["log", "--oneline", "-5"])

        # Commit (authorized)
        result = adapter.execute("developer", "git.commit", "origin",
                                 ["commit", "-m", "fix: update docs"])

    Security:
        - ALLOW  → execute the Git command via subprocess.run()
        - DENY   → raise GitDeniedError
        - APPROVE → raise GitApprovalRequiredError
        - error  → raise GitError

    Limitations:
        - Authorization covers the operation type, not individual arguments
        - The resource is an opaque policy string
        - Argument-level authorization is future work
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

        This method must NOT catch GitDeniedError or
        GitApprovalRequiredError — those propagate to the caller.
        """
        request = Request(agent=agent, action=action, resource=resource)
        try:
            decision = self._firewall.check(request)
        except InvalidRequestError as exc:
            raise GitError(
                agent, action, resource, str(exc)
            ) from exc
        except Exception as exc:
            raise GitError(
                agent, action, resource, str(exc)
            ) from exc

        if decision.kind is DecisionKind.ALLOW:
            return  # authorized

        if decision.kind is DecisionKind.DENY:
            raise GitDeniedError(
                agent, action, resource, decision.reason
            )

        if decision.kind is DecisionKind.APPROVE:
            raise GitApprovalRequiredError(
                agent, action, resource, decision.reason
            )

        # Should never reach here, but fail closed if it does
        raise GitError(
            agent, action, resource,
            f"unexpected decision kind: {decision.kind}"
        )

    def execute(
        self,
        agent: str,
        action: str,
        resource: str,
        args: Optional[List[str]] = None,
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """Execute a Git command if authorized.

        Uses ``subprocess.run()`` with list-based invocation.  The
        ``shell`` parameter is never set to ``True``.

        The resource is an opaque policy string passed through to the
        authorization request.  Individual Git arguments are NOT
        authorized by the firewall.

        Args:
            agent: The agent identifier for authorization.
            action: The Git action (git.read, git.write, git.commit,
                git.push).
            resource: Opaque resource string for authorization.
            args: Git command arguments (e.g. ["log", "--oneline"]).
                If None or empty, runs bare "git".
            **kwargs: Passed through to ``subprocess.run()`` (e.g.
                ``cwd``, ``env``, ``timeout``, ``capture_output``).

        Returns:
            ``subprocess.CompletedProcess`` from ``subprocess.run()``.

        Raises:
            GitDeniedError: if the firewall denies the operation
            GitApprovalRequiredError: if approval is required
            GitError: on authorization errors
            FileNotFoundError: if git not found (after auth)
            PermissionError: if OS denies access (after auth)
            subprocess.TimeoutExpired: if timeout exceeded (after auth)
        """
        # Never allow shell=True — this is a security invariant
        kwargs.pop("shell", None)

        self._check(agent, action, resource)

        cmd = ["git"]
        if args:
            cmd.extend(args)

        return subprocess.run(cmd, **kwargs)
