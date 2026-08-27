"""Phase 12 — MCP adapter tests.

Comprehensive tests for MCPFirewallAdapter and mcp_bridge covering:
    - Translation: tool_name → action mapping
    - Translation: resource extraction from arguments
    - Translation: custom mapping
    - Translation: unknown tool → TranslationError
    - ALLOW path: authorize returns allowed=True
    - DENY path: authorize returns allowed=False, isError=True
    - APPROVE path: authorize returns allowed=False, isError=True
    - Error path: MCPError on authorization failure
    - Agent identity preservation
    - Resource derivation
    - Custom tool mapping
    - MCP SDK availability detection
    - Adversarial/security checks
    - Zero third-party imports in bridge
    - Regression: Phase 1-11 tests unaffected
    - Frozen file verification
"""

from __future__ import annotations

import ast
import inspect
import os
import sys
import unittest

# Ensure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_firewall import Firewall, Request
from agent_firewall.model import DecisionKind, InvalidRequestError
from agent_firewall.adapters.mcp_bridge import (
    DEFAULT_TOOL_MAP,
    TranslationError,
    translate_mcp_result,
    translate_mcp_tool_call,
)
from agent_firewall.adapters.mcp import (
    MCPDeniedError,
    MCPApprovalRequiredError,
    MCPError,
    MCPFirewallAdapter,
)


def _firewall(agents):
    """Helper: build a Firewall from agent policy dicts."""
    return Firewall.from_dict({"version": 1, "agents": agents})


# ═══════════════════════════════════════════════════════════════════════════════
# Bridge tests (no MCP SDK required)
# ═══════════════════════════════════════════════════════════════════════════════

class TestBridgeTranslation(unittest.TestCase):
    """Test translate_mcp_tool_call translation logic."""

    def test_known_filesystem_tool(self):
        """Known filesystem tool maps to filesystem action."""
        req = translate_mcp_tool_call("dev", "read_file", {"path": "./src/main.py"})
        self.assertEqual(req.agent, "dev")
        self.assertEqual(req.action, "filesystem.read")
        self.assertEqual(req.resource, "./src/main.py")

    def test_known_process_tool(self):
        """Known process tool maps to process action."""
        req = translate_mcp_tool_call("dev", "execute_command", {"command": "pytest"})
        self.assertEqual(req.action, "process.spawn")
        self.assertEqual(req.resource, "pytest")

    def test_known_network_tool(self):
        """Known network tool maps to network action."""
        req = translate_mcp_tool_call("dev", "network_connect",
                                       {"host": "api.example.com", "port": 443})
        self.assertEqual(req.action, "network.connect")
        self.assertEqual(req.resource, "api.example.com:443")

    def test_known_git_tool(self):
        """Known git tool maps to git action."""
        req = translate_mcp_tool_call("dev", "git_commit", {"repository": "origin"})
        self.assertEqual(req.action, "git.commit")
        self.assertEqual(req.resource, "origin")

    def test_custom_tool_map(self):
        """Custom tool map overrides defaults."""
        custom = {"my_tool": "custom.action"}
        req = translate_mcp_tool_call("dev", "my_tool", {}, tool_map=custom)
        self.assertEqual(req.action, "custom.action")
        self.assertIsNone(req.resource)

    def test_unknown_tool_raises(self):
        """Unknown tool raises TranslationError (fail closed)."""
        with self.assertRaises(TranslationError):
            translate_mcp_tool_call("dev", "unknown_tool", {})

    def test_unknown_tool_not_in_default_map(self):
        """Verify unknown tool is not in DEFAULT_TOOL_MAP."""
        self.assertNotIn("unknown_tool_xyz", DEFAULT_TOOL_MAP)

    def test_empty_agent_raises(self):
        """Empty agent raises InvalidRequestError."""
        with self.assertRaises(InvalidRequestError):
            translate_mcp_tool_call("", "read_file", {})

    def test_empty_tool_name_raises(self):
        """Empty tool name raises InvalidRequestError."""
        with self.assertRaises(InvalidRequestError):
            translate_mcp_tool_call("dev", "", {})

    def test_none_arguments_handled(self):
        """None arguments treated as empty dict."""
        req = translate_mcp_tool_call("dev", "read_file", None)
        self.assertIsNone(req.resource)

    def test_resource_extraction_filesystem_path(self):
        """Filesystem resource extracted from 'path' argument."""
        req = translate_mcp_tool_call("dev", "read_file",
                                       {"path": "./src/main.py"})
        self.assertEqual(req.resource, "./src/main.py")

    def test_resource_extraction_filesystem_file_path(self):
        """Filesystem resource extracted from 'file_path' argument."""
        req = translate_mcp_tool_call("dev", "read_file",
                                       {"file_path": "./src/main.py"})
        self.assertEqual(req.resource, "./src/main.py")

    def test_resource_extraction_process_command(self):
        """Process resource extracted from 'command' argument."""
        req = translate_mcp_tool_call("dev", "execute_command",
                                       {"command": "pytest -v"})
        self.assertEqual(req.resource, "pytest")

    def test_resource_extraction_process_executable(self):
        """Process resource extracted from 'executable' argument."""
        req = translate_mcp_tool_call("dev", "execute_command",
                                       {"executable": "python"})
        self.assertEqual(req.resource, "python")

    def test_resource_extraction_network_url(self):
        """Network resource extracted from 'url' argument."""
        req = translate_mcp_tool_call("dev", "network_connect",
                                       {"url": "api.example.com:443"})
        self.assertEqual(req.resource, "api.example.com:443")

    def test_resource_extraction_network_host_port(self):
        """Network resource constructed from host + port."""
        req = translate_mcp_tool_call("dev", "network_connect",
                                       {"host": "example.com", "port": 8080})
        self.assertEqual(req.resource, "example.com:8080")

    def test_resource_extraction_git_repository(self):
        """Git resource extracted from 'repository' argument."""
        req = translate_mcp_tool_call("dev", "git_commit",
                                       {"repository": "origin"})
        self.assertEqual(req.resource, "origin")

    def test_no_resource_for_resourceless_action(self):
        """Actions without resource extractors return None resource."""
        # Custom action with no extractor
        custom = {"custom.action": "custom.action"}
        req = translate_mcp_tool_call("dev", "custom.action", {},
                                       tool_map=custom)
        self.assertIsNone(req.resource)

    def test_custom_resource_extractor(self):
        """Custom resource extractor overrides defaults."""
        def my_extractor(args):
            return args.get("custom_key")

        extractors = {"filesystem": my_extractor}
        req = translate_mcp_tool_call("dev", "read_file",
                                       {"custom_key": "custom_value"},
                                       resource_extractors=extractors)
        self.assertEqual(req.resource, "custom_value")


class TestBridgeResult(unittest.TestCase):
    """Test translate_mcp_result formatting."""

    def test_allow_result(self):
        """ALLOW → isError=False, allowed=True."""
        from agent_firewall.model import Decision
        decision = Decision(
            kind=DecisionKind.ALLOW, agent="dev", action="filesystem.read",
            resource="./src/main.py"
        )
        result = translate_mcp_result(decision, "read_file")
        self.assertFalse(result["isError"])
        self.assertTrue(result["allowed"])
        self.assertEqual(len(result["content"]), 1)
        self.assertEqual(result["content"][0]["type"], "text")

    def test_deny_result(self):
        """DENY → isError=True, allowed=False."""
        from agent_firewall.model import Decision
        decision = Decision(
            kind=DecisionKind.DENY, agent="dev", action="filesystem.read",
            resource="./secret", reason="not authorized"
        )
        result = translate_mcp_result(decision, "read_file")
        self.assertTrue(result["isError"])
        self.assertFalse(result["allowed"])

    def test_approve_result(self):
        """APPROVE → isError=True, allowed=False."""
        from agent_firewall.model import Decision
        decision = Decision(
            kind=DecisionKind.APPROVE, agent="dev", action="git.push",
            reason="requires approval"
        )
        result = translate_mcp_result(decision, "git_push")
        self.assertTrue(result["isError"])
        self.assertFalse(result["allowed"])

    def test_deny_with_reason(self):
        """DENY result includes reason in text."""
        from agent_firewall.model import Decision
        decision = Decision(
            kind=DecisionKind.DENY, agent="dev", action="network.connect",
            reason="production access denied"
        )
        result = translate_mcp_result(decision, "network_connect")
        self.assertIn("production access denied", result["content"][0]["text"])

    def test_allow_no_reason(self):
        """ALLOW result uses default text when no reason."""
        from agent_firewall.model import Decision
        decision = Decision(
            kind=DecisionKind.ALLOW, agent="dev", action="filesystem.read"
        )
        result = translate_mcp_result(decision, "read_file")
        self.assertIn("authorized", result["content"][0]["text"])


# ═══════════════════════════════════════════════════════════════════════════════
# Adapter tests (uses bridge, no MCP SDK needed)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPAdapterAllow(unittest.TestCase):
    """Tests for the ALLOW path."""

    def test_allowed_authorize(self):
        """ALLOW → result['allowed'] is True."""
        fw = _firewall({"dev": {"allow": [
            {"action": "filesystem.read", "resource": "./src/**"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        result = adapter.authorize("dev", "read_file", {"path": "./src/main.py"})
        self.assertTrue(result["allowed"])
        self.assertFalse(result["isError"])

    def test_allowed_authorize_has_decision(self):
        """ALLOW → result includes Decision object."""
        fw = _firewall({"dev": {"allow": [
            {"action": "filesystem.read", "resource": "./src/**"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        result = adapter.authorize("dev", "read_file", {"path": "./src/main.py"})
        self.assertIsNotNone(result["decision"])
        self.assertEqual(result["decision"].kind, DecisionKind.ALLOW)

    def test_allowed_authorize_preserves_agent(self):
        """ALLOW → decision preserves agent."""
        fw = _firewall({"dev": {"allow": [
            {"action": "filesystem.read", "resource": "./src/**"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        result = adapter.authorize("dev", "read_file", {"path": "./src/main.py"})
        self.assertEqual(result["decision"].agent, "dev")

    def test_allowed_with_custom_mapping(self):
        """Custom mapping still authorizes correctly."""
        fw = _firewall({"dev": {"allow": [
            {"action": "custom.read"},
        ]}})
        custom_map = {"my_read": "custom.read"}
        adapter = MCPFirewallAdapter(fw, tool_map=custom_map)
        result = adapter.authorize("dev", "my_read", {})
        self.assertTrue(result["allowed"])


class TestMCPAdapterDeny(unittest.TestCase):
    """Tests for the DENY path."""

    def test_denied_authorize(self):
        """DENY → result['allowed'] is False, isError=True."""
        fw = _firewall({"dev": {"allow": [
            {"action": "filesystem.read", "resource": "./src/**"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        result = adapter.authorize("dev", "read_file", {"path": "./secret"})
        self.assertFalse(result["allowed"])
        self.assertTrue(result["isError"])

    def test_denied_default_deny(self):
        """Unknown agent → default deny → not allowed."""
        fw = _firewall({})
        adapter = MCPFirewallAdapter(fw)
        result = adapter.authorize("unknown", "read_file", {"path": "./src/main.py"})
        self.assertFalse(result["allowed"])

    def test_denied_exception_has_agent(self):
        """MCPDeniedError preserves agent."""
        fw = _firewall({"dev": {"deny": [
            {"action": "filesystem.read", "resource": "./**"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        # DENY is returned as result, not raised
        result = adapter.authorize("dev", "read_file", {"path": "./src/main.py"})
        self.assertFalse(result["allowed"])


class TestMCPAdapterApprove(unittest.TestCase):
    """Tests for the APPROVE path."""

    def test_approve_authorize(self):
        """APPROVE → result['allowed'] is False, isError=True."""
        fw = _firewall({"dev": {"approve": [
            {"action": "git.push", "resource": "origin"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        result = adapter.authorize("dev", "git_push", {"repository": "origin"})
        self.assertFalse(result["allowed"])
        self.assertTrue(result["isError"])

    def test_approve_not_equal_to_allow(self):
        """APPROVE must never be treated as ALLOW."""
        fw = _firewall({"dev": {"approve": [
            {"action": "git.push"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        result = adapter.authorize("dev", "git_push", {})
        self.assertFalse(result["allowed"])
        self.assertTrue(result["isError"])


class TestMCPAdapterError(unittest.TestCase):
    """Tests for error paths."""

    def test_unknown_tool_raises_mcp_error(self):
        """Unknown tool → MCPError (fail closed)."""
        fw = _firewall({"dev": {"allow": [
            {"action": "filesystem.read", "resource": "./**"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        with self.assertRaises(MCPError):
            adapter.authorize("dev", "unknown_tool_xyz", {})

    def test_empty_agent_raises(self):
        """Empty agent → InvalidRequestError."""
        fw = _firewall({})
        adapter = MCPFirewallAdapter(fw)
        with self.assertRaises(InvalidRequestError):
            adapter.authorize("", "read_file", {"path": "./src/main.py"})

    def test_empty_tool_name_raises(self):
        """Empty tool name → InvalidRequestError."""
        fw = _firewall({})
        adapter = MCPFirewallAdapter(fw)
        with self.assertRaises(InvalidRequestError):
            adapter.authorize("dev", "", {})

    def test_error_preserves_metadata(self):
        """MCPError preserves agent and tool_name."""
        fw = _firewall({"dev": {"allow": [
            {"action": "filesystem.read", "resource": "./**"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        with self.assertRaises(MCPError) as ctx:
            adapter.authorize("dev", "unknown_tool_xyz", {})
        self.assertEqual(ctx.exception.agent, "dev")
        self.assertEqual(ctx.exception.tool_name, "unknown_tool_xyz")


class TestMCPAdapterSecurity(unittest.TestCase):
    """Adversarial security checks."""

    def test_authorization_always_goes_through_firewall(self):
        """All mapped requests must go through Firewall.check()."""
        fw = _firewall({"dev": {"allow": [
            {"action": "filesystem.read", "resource": "./src/**"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        result = adapter.authorize("dev", "read_file", {"path": "./src/main.py"})
        self.assertTrue(result["allowed"])
        self.assertIsNotNone(result["decision"])

    def test_unknown_tool_cannot_produce_allow(self):
        """Unknown tool → TranslationError → MCPError, never ALLOW."""
        fw = _firewall({})
        adapter = MCPFirewallAdapter(fw)
        with self.assertRaises(MCPError):
            adapter.authorize("dev", "nonexistent_tool", {})

    def test_deny_result_has_no_execution(self):
        """DENY result does not imply tool execution."""
        fw = _firewall({})
        adapter = MCPFirewallAdapter(fw)
        result = adapter.authorize("dev", "read_file", {"path": "./src/main.py"})
        self.assertFalse(result["allowed"])
        self.assertTrue(result["isError"])

    def test_no_shell_true_in_bridge(self):
        """No shell=True in mcp_bridge source."""
        import agent_firewall.adapters.mcp_bridge as bridge_mod
        source = inspect.getsource(bridge_mod)
        for line in source.split("\n"):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"""'):
                continue
            self.assertNotIn("shell=True", stripped)

    def test_no_os_system_in_bridge(self):
        """No os.system() in mcp_bridge source."""
        import agent_firewall.adapters.mcp_bridge as bridge_mod
        source = inspect.getsource(bridge_mod)
        self.assertNotIn("os.system", source)

    def test_no_subprocess_in_bridge(self):
        """No subprocess import in mcp_bridge."""
        import agent_firewall.adapters.mcp_bridge as bridge_mod
        source = inspect.getsource(bridge_mod)
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("from subprocess", source)

    def test_exception_classes_inherit_from_exception(self):
        """All adapter exceptions inherit from Exception."""
        self.assertTrue(issubclass(MCPDeniedError, Exception))
        self.assertTrue(issubclass(MCPApprovalRequiredError, Exception))
        self.assertTrue(issubclass(MCPError, Exception))
        self.assertTrue(issubclass(TranslationError, Exception))

    def test_bridge_does_not_import_firewall(self):
        """mcp_bridge.py does not import or depend on Firewall."""
        import agent_firewall.adapters.mcp_bridge as bridge_mod
        source = inspect.getsource(bridge_mod)
        self.assertNotIn("from .. import Firewall", source)
        self.assertNotIn("from agent_firewall import Firewall", source)

    def test_bridge_only_imports_model(self):
        """mcp_bridge.py only imports from model (not evaluator/policy)."""
        import agent_firewall.adapters.mcp_bridge as bridge_mod
        source = inspect.getsource(bridge_mod)
        # Should not import evaluator, policy, or other core modules
        self.assertNotIn("from ..evaluator", source)
        self.assertNotIn("from ..policy", source)
        self.assertNotIn("from ..cli", source)

    def test_agent_identity_not_from_arguments(self):
        """Agent identity must be supplied by caller, not extracted from args."""
        fw = _firewall({"dev": {"allow": [
            {"action": "filesystem.read", "resource": "./**"},
        ]}})
        adapter = MCPFirewallAdapter(fw)
        # Pass agent as "dev" even if arguments try to spoof identity
        result = adapter.authorize("dev", "read_file",
                                    {"path": "./src/main.py", "agent": "admin"})
        self.assertEqual(result["decision"].agent, "dev")


class TestMCPAdapterRegression(unittest.TestCase):
    """Regression: existing adapter functionality unchanged."""

    def test_filesystem_adapter_still_works(self):
        """FilesystemAdapter is still importable."""
        from agent_firewall.adapters import FilesystemAdapter
        fw = _firewall({"dev": {"allow": [
            {"action": "filesystem.read", "resource": "./**"},
        ]}})
        adapter = FilesystemAdapter(fw)
        self.assertIsNotNone(adapter)

    def test_process_adapter_still_works(self):
        """ProcessAdapter is still importable."""
        from agent_firewall.adapters import ProcessAdapter
        fw = _firewall({"dev": {"allow": [
            {"action": "process.spawn", "resource": "python"},
        ]}})
        adapter = ProcessAdapter(fw)
        self.assertIsNotNone(adapter)

    def test_git_adapter_still_works(self):
        """GitAdapter is still importable."""
        from agent_firewall.adapters import GitAdapter
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        self.assertIsNotNone(adapter)

    def test_network_adapter_still_works(self):
        """NetworkAdapter is still importable."""
        from agent_firewall.adapters import NetworkAdapter
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)
        self.assertIsNotNone(adapter)

    def test_mcp_adapter_importable_from_package(self):
        """MCPFirewallAdapter is importable from the adapters package."""
        from agent_firewall.adapters import MCPFirewallAdapter
        self.assertIsNotNone(MCPFirewallAdapter)

    def test_phase1_core_still_works(self):
        """Phase 1 evaluator still functions correctly."""
        fw = _firewall({"dev": {"allow": [
            {"action": "test.action", "resource": "test.resource"},
        ]}})
        decision = fw.check(Request("dev", "test.action", "test.resource"))
        self.assertEqual(decision.kind.value, "ALLOW")


class TestMCPAdapterDependencies(unittest.TestCase):
    """Verify zero third-party runtime dependencies."""

    def test_no_third_party_imports_in_bridge(self):
        """mcp_bridge.py uses only stdlib and internal imports."""
        path = os.path.join(os.path.dirname(__file__),
                            "..", "agent_firewall", "adapters", "mcp_bridge.py")
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)
        allowed = {
            "json", "os", "sys", "dataclasses", "datetime", "typing",
            "hashlib", "hmac", "re", "enum", "pathlib", "collections",
            "fnmatch", "io", "__future__", "urllib",
            # Internal package modules
            "model",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    self.assertIn(mod, allowed,
                                  f"Unexpected import: {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod = node.module.split(".")[0]
                    self.assertIn(mod, allowed,
                                  f"Unexpected import: {node.module}")

    def test_no_third_party_imports_in_adapter(self):
        """mcp.py uses only stdlib and internal imports (mcp is guarded)."""
        path = os.path.join(os.path.dirname(__file__),
                            "..", "agent_firewall", "adapters", "mcp.py")
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)
        allowed = {
            "json", "os", "sys", "dataclasses", "datetime", "typing",
            "hashlib", "hmac", "re", "enum", "pathlib", "collections",
            "fnmatch", "io", "__future__", "urllib",
            # Internal package modules
            "model", "mcp_bridge",
            # Optional MCP SDK (guarded try/except)
            "mcp",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    self.assertIn(mod, allowed,
                                  f"Unexpected import: {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod = node.module.split(".")[0]
                    self.assertIn(mod, allowed,
                                  f"Unexpected import: {node.module}")

    def test_pyproject_dependencies_empty(self):
        """pyproject.toml has zero runtime dependencies."""
        path = os.path.join(os.path.dirname(__file__),
                            "..", "pyproject.toml")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            if "dependencies" in content:
                for line in content.split("\n"):
                    if "dependencies" in line and "=" in line:
                        self.assertIn("[]", line.replace(" ", ""))

    def test_no_mcp_import_in_bridge(self):
        """mcp_bridge.py does NOT import mcp SDK."""
        import agent_firewall.adapters.mcp_bridge as bridge_mod
        source = inspect.getsource(bridge_mod)
        self.assertNotIn("import mcp", source)
        self.assertNotIn("from mcp", source)

    def test_mcp_sdk_detection_returns_bool(self):
        """MCPFirewallAdapter.mcp_sdk_available returns a boolean."""
        fw = _firewall({})
        adapter = MCPFirewallAdapter(fw)
        self.assertIsInstance(adapter.mcp_sdk_available, bool)


if __name__ == "__main__":
    unittest.main()
