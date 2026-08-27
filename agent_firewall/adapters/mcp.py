"""Optional MCP SDK adapter — authorized MCP tool calls (Phase 12).

Wraps the zero-dependency mcp_bridge translation layer with optional
MCP SDK support.  If the ``mcp`` package is installed, this adapter
can work directly with MCP SDK objects.  If not, it falls back to
the bridge's plain-dict API.

This adapter depends on the core (Firewall) and optionally on the
mcp SDK.  The core never depends on adapters (DESIGN 48).

Usage (without MCP SDK)::

    from agent_firewall.adapters.mcp import MCPFirewallAdapter
    from agent_firewall import Firewall

    firewall = Firewall.from_file("policy.json")
    adapter = MCPFirewallAdapter(firewall)

    result = adapter.authorize("developer", "read_file", {"path": "./src/main.py"})
    if result["allowed"]:
        # execute the tool
        ...

Usage (with MCP SDK installed)::

    from agent_firewall.adapters.mcp import MCPFirewallAdapter
    from agent_firewall import Firewall

    firewall = Firewall.from_file("policy.json")
    adapter = MCPFirewallAdapter(firewall)

    # Works with plain dicts OR MCP SDK objects
    result = adapter.authorize("developer", "read_file", {"path": "./src/main.py"})

Security (DESIGN 49):
    - MCP → structured Request → Firewall.check() is mandatory
    - DENY → never authorize/execute
    - APPROVE → never authorize/execute
    - Unknown tools → fail closed
    - Agent identity comes from caller, not arguments
    - No secrets/prompts/credentials in error responses
    - Adapter does NOT execute filesystem/process/git/network operations

Properties:
    - Depends on the core (Firewall); the core never depends on adapters
    - Zero third-party runtime dependencies (mcp SDK is optional)
    - Deterministic authorization path
    - mcp_bridge.py is pure translation, zero dependencies
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from ..model import DecisionKind, InvalidRequestError, Request
from .mcp_bridge import (
    TranslationError,
    translate_mcp_result,
    translate_mcp_tool_call,
)

try:
    import mcp  # type: ignore[import-not-found]
    _HAS_MCP = True
except ImportError:
    mcp = None  # type: ignore[assignment]
    _HAS_MCP = False


# ── Exceptions ────────────────────────────────────────────────────────────────

class MCPDeniedError(Exception):
    """Raised when the firewall denies an MCP tool call.

    The tool operation is NOT performed.
    """

    def __init__(self, agent: str, tool_name: str,
                 reason: str = "") -> None:
        self.agent = agent
        self.tool_name = tool_name
        self.reason = reason
        msg = f"denied: {agent} {tool_name}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


class MCPApprovalRequiredError(Exception):
    """Raised when the firewall requires approval for an MCP tool call.

    The tool operation is NOT performed.
    """

    def __init__(self, agent: str, tool_name: str,
                 reason: str = "") -> None:
        self.agent = agent
        self.tool_name = tool_name
        self.reason = reason
        msg = f"approval required: {agent} {tool_name}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


class MCPError(Exception):
    """Raised on authorization errors for MCP tool calls.

    The tool operation is NOT performed.  This covers invalid
    requests, invalid policies, translation errors, and unexpected
    errors.  Must NOT be treated as ALLOW.
    """

    def __init__(self, agent: str, tool_name: str,
                 reason: str = "") -> None:
        self.agent = agent
        self.tool_name = tool_name
        self.reason = reason
        msg = f"error: {agent} {tool_name}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


# ── Adapter ───────────────────────────────────────────────────────────────────

class MCPFirewallAdapter:
    """Optional adapter that authorizes MCP tool calls through the firewall.

    Uses mcp_bridge for zero-dependency translation.  Optionally
    integrates with the MCP SDK when installed.

    Usage::

        firewall = Firewall.from_file("policy.json")
        adapter = MCPFirewallAdapter(firewall)

        # Authorize a tool call (plain dict)
        result = adapter.authorize("developer", "read_file",
                                   {"path": "./src/main.py"})

        if result["allowed"]:
            # proceed with tool execution
            ...

    Security:
        - ALLOW  → result["allowed"] is True
        - DENY   → result["allowed"] is False, result["isError"] is True
        - APPROVE → result["allowed"] is False, result["isError"] is True
        - error  → MCPError raised (fail closed)

    The adapter does NOT execute any tool.  It only returns an
    authorization decision.  The MCP server implementation is
    responsible for executing the tool when authorized.
    """

    def __init__(
        self,
        firewall,
        *,
        tool_map: Optional[Dict[str, str]] = None,
        resource_extractors: Optional[
            Dict[str, Callable[[Dict[str, Any]], Optional[str]]]
        ] = None,
    ) -> None:
        """Initialize with an existing Firewall instance.

        Args:
            firewall: A Firewall instance with an immutable policy snapshot.
            tool_map: Optional custom tool-name → action mapping.
                Falls back to mcp_bridge.DEFAULT_TOOL_MAP.
            resource_extractors: Optional custom action-prefix → extractor
                mapping.  Falls back to mcp_bridge._DEFAULT_EXTRACTORS.

        Raises:
            ImportError: if ``require_sdk=True`` was intended but the
                MCP SDK is not installed.  (Default: SDK is optional.)
        """
        self._firewall = firewall
        self._tool_map = tool_map
        self._resource_extractors = resource_extractors

    @property
    def mcp_sdk_available(self) -> bool:
        """True if the MCP SDK is importable."""
        return _HAS_MCP

    def _translate(
        self,
        agent: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]],
    ) -> Request:
        """Translate MCP tool call to a firewall Request.

        Raises:
            MCPError: on translation failure (fail closed).
            InvalidRequestError: on invalid agent/tool_name.
        """
        try:
            return translate_mcp_tool_call(
                agent,
                tool_name,
                arguments,
                tool_map=self._tool_map,
                resource_extractors=self._resource_extractors,
            )
        except TranslationError as exc:
            # Unknown tool → fail closed
            raise MCPError(agent, tool_name, str(exc)) from exc
        except InvalidRequestError:
            raise

    def authorize(
        self,
        agent: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Authorize an MCP tool call through the firewall.

        Translates the tool call to a Request, evaluates it through
        Firewall.check(), and returns an MCP-compatible result dict.

        Args:
            agent: Agent identifier.  MUST come from the trusted MCP
                server caller context, NOT from tool arguments.
            tool_name: The MCP tool name (e.g. "read_file").
            arguments: Tool call arguments dict.  May be None.

        Returns:
            A dict with:
                - "allowed": bool — True only for ALLOW
                - "isError": bool — True for DENY/APPROVE/error
                - "content": list of content block dicts
                - "decision": the Decision object (convenience)

        Raises:
            MCPError: on authorization errors (fail closed).
            InvalidRequestError: on malformed agent/tool_name.
        """
        request = self._translate(agent, tool_name, arguments)

        try:
            decision = self._firewall.check(request)
        except InvalidRequestError as exc:
            raise MCPError(agent, tool_name, str(exc)) from exc
        except Exception as exc:
            raise MCPError(agent, tool_name, str(exc)) from exc

        result = translate_mcp_result(decision, tool_name)
        result["decision"] = decision
        return result
