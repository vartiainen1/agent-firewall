"""Network adapter — authorized network connections (Phase 11).

Combines authorization with execution for network operations.
Each operation:
    1. Builds a structured Request(agent, "network.connect", "host:port")
    2. Calls Firewall.check() to get a Decision
    3. Executes the network connection ONLY if ALLOW
    4. Raises an error for DENY, APPROVE, or any error

Security (DESIGN 21, SECURITY 17, THREAT_MODEL 6):
    - Never connects on DENY
    - Never connects on APPROVE
    - Never connects on error
    - Never treats firewall errors as ALLOW
    - Preserves agent identity
    - Uses urllib.request from stdlib (no third-party HTTP library)
    - Builds URL from structured host/port/scheme/path arguments
    - Does NOT accept or parse a full URL as authorization input
    - Resource for authorization is opaque "host:port"

Properties:
    - Depends on the core (Firewall); the core never depends on adapters
    - Zero third-party dependencies
    - Deterministic authorization path

Limitations (DESIGN 21, SECURITY 17):
    - DNS rebinding and address changes are enforcement-layer concerns
    - The adapter authorizes the declared resource string, not the
      actual resolved endpoint
    - TLS certificate validation uses stdlib defaults
    - Redirect following uses stdlib defaults
"""

from __future__ import annotations

import urllib.request
import urllib.error
from typing import TYPE_CHECKING, Union

from ..model import DecisionKind, InvalidRequestError, Request

if TYPE_CHECKING:
    from .. import Firewall


# ── Exceptions ────────────────────────────────────────────────────────────────

class NetworkDeniedError(Exception):
    """Raised when the firewall denies a network operation.

    The connection is NOT made.
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


class NetworkApprovalRequiredError(Exception):
    """Raised when the firewall requires approval for a network operation.

    The connection is NOT made.
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


class NetworkError(Exception):
    """Raised when the firewall encounters an error during authorization.

    The connection is NOT made.  This covers invalid requests,
    invalid policies, and unexpected errors.  The adapter must NOT
    treat this as ALLOW.
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

class NetworkAdapter:
    """Optional adapter that combines network authorization with execution.

    The adapter depends on the core (Firewall).  The core never depends
    on adapters (DESIGN 48).

    Usage::

        firewall = Firewall.from_file("policy.json")
        adapter = NetworkAdapter(firewall)

        # Connect (authorized)
        data = adapter.connect("developer", "api.example.com", 443)

        # Connect with explicit scheme and path
        data = adapter.connect("developer", "api.example.com", 443,
                               scheme="http", path="/health")

    Security:
        - ALLOW  → connect via urllib.request.urlopen()
        - DENY   → raise NetworkDeniedError
        - APPROVE → raise NetworkApprovalRequiredError
        - error  → raise NetworkError

    Limitations:
        - Authorization covers "host:port" only
        - Path is NOT part of the authorization resource
        - DNS rebinding is an enforcement-layer concern (SECURITY 17)
        - TLS certificate validation uses stdlib defaults
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

        This method must NOT catch NetworkDeniedError or
        NetworkApprovalRequiredError — those propagate to the caller.
        """
        request = Request(agent=agent, action=action, resource=resource)
        try:
            decision = self._firewall.check(request)
        except InvalidRequestError as exc:
            raise NetworkError(
                agent, action, resource, str(exc)
            ) from exc
        except Exception as exc:
            raise NetworkError(
                agent, action, resource, str(exc)
            ) from exc

        if decision.kind is DecisionKind.ALLOW:
            return  # authorized

        if decision.kind is DecisionKind.DENY:
            raise NetworkDeniedError(
                agent, action, resource, decision.reason
            )

        if decision.kind is DecisionKind.APPROVE:
            raise NetworkApprovalRequiredError(
                agent, action, resource, decision.reason
            )

        # Should never reach here, but fail closed if it does
        raise NetworkError(
            agent, action, resource,
            f"unexpected decision kind: {decision.kind}"
        )

    def connect(
        self,
        agent: str,
        host: str,
        port: int,
        *,
        scheme: str = "https",
        path: str = "",
        **kwargs,
    ) -> bytes:
        """Connect to a network endpoint if authorized.

        The resource for authorization is ``"host:port"`` (opaque string).
        The URL is built from structured arguments:
        ``scheme://host[:port]/path``

        Uses ``urllib.request.urlopen()`` from the Python standard library.

        Args:
            agent: The agent identifier for authorization.
            host: The target hostname or IP address.
            port: The target port number.
            scheme: URL scheme (default ``"https"``).
            path: URL path appended after host:port (NOT part of
                authorization resource).
            **kwargs: Passed through to ``urllib.request.urlopen()``
                (e.g. ``timeout``, ``data``, ``headers``).

        Returns:
            Response body as bytes.

        Raises:
            NetworkDeniedError: if the firewall denies the operation
            NetworkApprovalRequiredError: if approval is required
            NetworkError: on authorization errors
            urllib.error.URLError: if the connection fails (after auth)
        """
        resource = f"{host}:{port}"
        self._check(agent, "network.connect", resource)

        # Build URL from structured arguments
        if port and port not in (80, 443):
            netloc = f"{host}:{port}"
        else:
            netloc = host

        url = f"{scheme}://{netloc}"
        if path:
            if not path.startswith("/"):
                url += "/"
            url += path

        response = urllib.request.urlopen(url, **kwargs)
        return response.read()
