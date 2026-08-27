"""MCP translation bridge — zero-dependency tool-call-to-request translation (Phase 12).

Pure translation layer that converts MCP-style tool call arguments into
standard firewall Request objects and translates Decision results back
into MCP-compatible response dicts.

This module has ZERO third-party dependencies.  It does NOT import the
MCP SDK.  It does NOT perform authorization.  It does NOT execute tools.

Conceptual flow (DESIGN 49):

    MCP tool call
         |
    translate_mcp_tool_call()
         |
         v
    Request(agent, action, resource)
         |
    Firewall.check()
         |
         v
    Decision
         |
    translate_mcp_result()
         |
         v
    MCP-compatible result dict

The bridge is intentionally thin and synchronous.  MCP server
implementations that need async wrappers can wrap the bridge calls
in their own async adapter layer.

Security (DESIGN 49, SECURITY 17, THREAT_MODEL 6):
    - Translation never bypasses Firewall.check()
    - Unknown tool names default to DENY (fail closed)
    - Agent identity comes from the trusted caller, not from arguments
    - Resource derivation is configurable and explicit
    - No secrets, prompts, or credentials in responses

Properties:
    - Zero third-party dependencies
    - Pure translation (no authorization, no execution)
    - Deterministic
    - Side-effect-free
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from ..model import (
    Decision,
    DecisionKind,
    InvalidRequestError,
    Request,
)


# ── Default tool-name → action mapping ────────────────────────────────────────
#
# This mapping translates common MCP-style tool names into the
# firewall action namespace.  Users may override it entirely.

DEFAULT_TOOL_MAP: Dict[str, str] = {
    # Filesystem
    "read_file": "filesystem.read",
    "read_resource": "filesystem.read",
    "write_file": "filesystem.write",
    "create_file": "filesystem.write",
    "delete_file": "filesystem.delete",
    # Process
    "execute_command": "process.spawn",
    "run_command": "process.spawn",
    # Git
    "git_read": "git.read",
    "git_write": "git.write",
    "git_commit": "git.commit",
    "git_push": "git.push",
    # Network
    "network_connect": "network.connect",
}


# ── Default resource extractors ───────────────────────────────────────────────
#
# Each extractor receives the tool arguments dict and returns an
# optional resource string.  Return None for resource-less actions.

def _extract_filesystem_resource(args: Dict[str, Any]) -> Optional[str]:
    """Extract filesystem path from common MCP argument names."""
    for key in ("path", "file_path", "resource", "target"):
        val = args.get(key)
        if isinstance(val, str) and val:
            return val
    return None


def _extract_process_resource(args: Dict[str, Any]) -> Optional[str]:
    """Extract executable name from common MCP argument names."""
    for key in ("command", "executable", "program", "resource"):
        val = args.get(key)
        if isinstance(val, str) and val:
            # For process.spawn, the resource is the executable name.
            # If the command contains spaces, take the first token.
            return val.split()[0] if val else None
    return None


def _extract_network_resource(args: Dict[str, Any]) -> Optional[str]:
    """Extract host:port from common MCP argument names."""
    # Check for full URL/endpoint first
    for key in ("url", "endpoint", "resource"):
        val = args.get(key)
        if isinstance(val, str) and val:
            return val
    # Try constructing from host + port
    host = args.get("host") or args.get("hostname")
    port = args.get("port")
    if isinstance(host, str) and host:
        if port is not None:
            return f"{host}:{port}"
        return host
    return None


def _extract_git_resource(args: Dict[str, Any]) -> Optional[str]:
    """Extract git resource (repo/remote) from common MCP argument names."""
    for key in ("repository", "repo", "remote", "resource"):
        val = args.get(key)
        if isinstance(val, str) and val:
            return val
    return None


# Map action prefixes to resource extractors
_DEFAULT_EXTRACTORS: Dict[str, Callable[[Dict[str, Any]], Optional[str]]] = {
    "filesystem": _extract_filesystem_resource,
    "process": _extract_process_resource,
    "network": _extract_network_resource,
    "git": _extract_git_resource,
}


# ── Translation functions ─────────────────────────────────────────────────────

class TranslationError(Exception):
    """Raised when MCP tool call arguments cannot be translated.

    This is NOT an authorization decision.  It indicates that the
    translation layer itself cannot produce a valid Request.  Callers
    must treat this as fail-closed (never ALLOW).
    """


def translate_mcp_tool_call(
    agent: str,
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    *,
    tool_map: Optional[Dict[str, str]] = None,
    resource_extractors: Optional[
        Dict[str, Callable[[Dict[str, Any]], Optional[str]]]
    ] = None,
) -> Request:
    """Translate MCP tool call arguments into a firewall Request.

    This is a pure translation function with zero dependencies.  It does
    NOT perform authorization and does NOT execute tools.

    Args:
        agent: Agent identifier.  MUST come from the trusted MCP server
            caller context, NOT from tool arguments.
        tool_name: The MCP tool name (e.g. "read_file", "write_file").
        arguments: Tool call arguments dict.  May be None.
        tool_map: Custom tool-name → action mapping.  Falls back to
            DEFAULT_TOOL_MAP if not provided.
        resource_extractors: Custom action-prefix → extractor mapping.
            Falls back to _DEFAULT_EXTRACTORS if not provided.

    Returns:
        A Request ready for Firewall.check().

    Raises:
        TranslationError: if the tool name is not mapped and no
            fallback action is configured.  Callers must treat this
            as fail-closed.
        InvalidRequestError: if agent is empty or translation produces
            an invalid Request.
    """
    if not agent or not isinstance(agent, str):
        raise InvalidRequestError("agent is required and must be non-empty")

    if not tool_name or not isinstance(tool_name, str):
        raise InvalidRequestError("tool_name is required and must be non-empty")

    if arguments is None:
        arguments = {}

    # Resolve action from tool name
    mapping = tool_map if tool_map is not None else DEFAULT_TOOL_MAP
    action = mapping.get(tool_name)

    if action is None:
        # Unknown tool → fail closed.  The caller must not treat
        # this as ALLOW.  We raise TranslationError so the caller
        # can produce a DENY response.
        raise TranslationError(
            f"unknown MCP tool: {tool_name!r}"
        )

    # Derive resource from arguments using the appropriate extractor
    resource = None
    extractors = (
        resource_extractors
        if resource_extractors is not None
        else _DEFAULT_EXTRACTORS
    )

    # Find extractor by action prefix (e.g. "filesystem" from "filesystem.read")
    action_prefix = action.split(".")[0] if "." in action else action
    extractor = extractors.get(action_prefix)

    if extractor is not None:
        resource = extractor(arguments)

    return Request(agent=agent, action=action, resource=resource)


def translate_mcp_result(
    decision: Decision,
    tool_name: str,
) -> Dict[str, Any]:
    """Translate a firewall Decision into an MCP-compatible result dict.

    Returns a dict with:
        - "content": list of content block dicts
        - "isError": True for DENY/APPROVE, False for ALLOW
        - "allowed": True for ALLOW, False otherwise (convenience field)

    This function does NOT execute any tool.  It only formats the
    decision into a response structure.
    """
    is_allowed = decision.kind is DecisionKind.ALLOW
    is_error = not is_allowed

    if is_allowed:
        text = f"Tool {tool_name!r} is authorized."
    elif decision.kind is DecisionKind.DENY:
        reason = decision.reason or "not authorized by policy"
        text = f"Tool {tool_name!r} is denied: {reason}"
    elif decision.kind is DecisionKind.APPROVE:
        reason = decision.reason or "requires external approval"
        text = f"Tool {tool_name!r} requires approval: {reason}"
    else:
        text = f"Tool {tool_name!r}: unexpected decision"

    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
        "allowed": is_allowed,
    }
