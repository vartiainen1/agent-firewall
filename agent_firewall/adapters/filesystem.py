"""Filesystem adapter — authorized file I/O (Phase 8).

Combines authorization with execution for filesystem operations.
Each operation:
    1. Builds a structured Request
    2. Calls Firewall.check() to get a Decision
    3. Executes the filesystem operation ONLY if ALLOW
    4. Raises an error for DENY, APPROVE, or any error

Security (DESIGN 20, SECURITY 15-16, THREAT_MODEL 4-5):
    - Never executes on DENY
    - Never executes on APPROVE
    - Never executes on error
    - Never treats firewall errors as ALLOW
    - Preserves agent identity
    - Does not resolve symlinks (enforcement-layer concern)
    - Does not perform pre-existence checks (avoids TOCTOU)

Properties:
    - Depends on the core (Firewall); the core never depends on adapters
    - Zero third-party dependencies
    - Deterministic authorization path
    - Side-effect-free authorization (filesystem I/O is the intended side effect)

Limitations (SECURITY 15-16):
    - Lexical path normalization does not prevent symlink attacks
    - check-then-act creates a TOCTOU window
    - These are documented limitations; stronger guarantees require
      OS-level primitives in the enforcement layer
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..model import DecisionKind, InvalidRequestError, Request

if TYPE_CHECKING:
    from .. import Firewall


# ── Exceptions ────────────────────────────────────────────────────────────────

class FilesystemDeniedError(Exception):
    """Raised when the firewall denies a filesystem operation.

    The requested operation is NOT performed.
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


class FilesystemApprovalRequiredError(Exception):
    """Raised when the firewall requires approval for a filesystem operation.

    The requested operation is NOT performed.
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


class FilesystemError(Exception):
    """Raised when the firewall encounters an error during authorization.

    The requested operation is NOT performed.  This covers invalid
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

class FilesystemAdapter:
    """Optional adapter that combines filesystem authorization with execution.

    The adapter depends on the core (Firewall).  The core never depends
    on adapters (DESIGN 48).

    Usage::

        firewall = Firewall.from_file("policy.json")
        adapter = FilesystemAdapter(firewall)

        # Read (authorized)
        data = adapter.read("developer", "./src/main.py")

        # Write (authorized)
        adapter.write("developer", "./src/main.py", b"new content")

        # Delete (authorized)
        adapter.delete("developer", "./src/old.py")

    Security:
        - ALLOW  → execute the operation
        - DENY   → raise FilesystemDeniedError
        - APPROVE → raise FilesystemApprovalRequiredError
        - error  → raise FilesystemError
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

        This method must NOT catch FilesystemDeniedError or
        FilesystemApprovalRequiredError — those propagate to the caller.
        """
        request = Request(agent=agent, action=action, resource=resource)
        try:
            decision = self._firewall.check(request)
        except InvalidRequestError as exc:
            raise FilesystemError(
                agent, action, resource, str(exc)
            ) from exc
        except Exception as exc:
            raise FilesystemError(
                agent, action, resource, str(exc)
            ) from exc

        if decision.kind is DecisionKind.ALLOW:
            return  # authorized

        if decision.kind is DecisionKind.DENY:
            raise FilesystemDeniedError(
                agent, action, resource, decision.reason
            )

        if decision.kind is DecisionKind.APPROVE:
            raise FilesystemApprovalRequiredError(
                agent, action, resource, decision.reason
            )

        # Should never reach here, but fail closed if it does
        raise FilesystemError(
            agent, action, resource,
            f"unexpected decision kind: {decision.kind}"
        )

    def read(self, agent: str, resource: str) -> bytes:
        """Read a file if authorized.

        Returns the file contents as raw bytes.  Decoding is the
        caller's responsibility.

        Raises:
            FilesystemDeniedError: if the firewall denies the operation
            FilesystemApprovalRequiredError: if approval is required
            FilesystemError: on authorization errors
            FileNotFoundError: if the file does not exist (after auth)
            PermissionError: if OS denies access (after auth)
        """
        self._check(agent, "filesystem.read", resource)
        return Path(resource).read_bytes()

    def write(self, agent: str, resource: str, data: bytes) -> None:
        """Write a file if authorized.

        Creates the file if it does not exist, or overwrites if it does.
        Parent directories are NOT created automatically.

        Raises:
            FilesystemDeniedError: if the firewall denies the operation
            FilesystemApprovalRequiredError: if approval is required
            FilesystemError: on authorization errors
            FileNotFoundError: if parent directory does not exist (after auth)
            PermissionError: if OS denies access (after auth)
        """
        self._check(agent, "filesystem.write", resource)
        Path(resource).write_bytes(data)

    def delete(self, agent: str, resource: str) -> None:
        """Delete a file if authorized.

        Raises:
            FilesystemDeniedError: if the firewall denies the operation
            FilesystemApprovalRequiredError: if approval is required
            FilesystemError: on authorization errors
            FileNotFoundError: if the file does not exist (after auth)
            PermissionError: if OS denies access (after auth)
        """
        self._check(agent, "filesystem.delete", resource)
        Path(resource).unlink()
