"""Optional adapters for external system integration (Phase 8+).

Adapters translate external operations into firewall requests and execute
only when authorized.  The adapter depends on the core; the core never
depends on adapters (DESIGN 48).

Phase 8 provides:
    - FilesystemAdapter: read / write / delete with authorization

Phase 9 provides:
    - ProcessAdapter: spawn with authorization

Phase 10 provides:
    - GitAdapter: git.read / git.write / git.commit / git.push with authorization

Phase 11 provides:
    - NetworkAdapter: network.connect with authorization

Phase 12 provides:
    - MCPFirewallAdapter: MCP tool call authorization (optional MCP SDK)
    - mcp_bridge: zero-dependency MCP translation (no SDK required)
"""

from .filesystem import (
    FilesystemAdapter,
    FilesystemApprovalRequiredError,
    FilesystemDeniedError,
)
from .git import (
    GitAdapter,
    GitApprovalRequiredError,
    GitDeniedError,
    GitError,
)
from .mcp import (
    MCPApprovalRequiredError,
    MCPDeniedError,
    MCPError,
    MCPFirewallAdapter,
)
from .mcp_bridge import (
    TranslationError,
    translate_mcp_result,
    translate_mcp_tool_call,
)
from .network import (
    NetworkAdapter,
    NetworkApprovalRequiredError,
    NetworkDeniedError,
    NetworkError,
)
from .process import (
    ProcessAdapter,
    ProcessApprovalRequiredError,
    ProcessDeniedError,
    ProcessError,
)

__all__ = [
    "FilesystemAdapter",
    "FilesystemApprovalRequiredError",
    "FilesystemDeniedError",
    "GitAdapter",
    "GitApprovalRequiredError",
    "GitDeniedError",
    "GitError",
    "MCPApprovalRequiredError",
    "MCPDeniedError",
    "MCPError",
    "MCPFirewallAdapter",
    "NetworkAdapter",
    "NetworkApprovalRequiredError",
    "NetworkDeniedError",
    "NetworkError",
    "ProcessAdapter",
    "ProcessApprovalRequiredError",
    "ProcessDeniedError",
    "ProcessError",
    "TranslationError",
    "translate_mcp_result",
    "translate_mcp_tool_call",
]
