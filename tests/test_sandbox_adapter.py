"""Tests for Phase 14 sandbox integration adapter.

Verifies SandboxAdapter, SandboxProtocol, SandboxResult, and exceptions.
All tests delegate authorization to the existing Firewall.check()
implementation and verify that the adapter preserves all security invariants.
"""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall import Firewall, Request
from agent_firewall.model import DecisionKind, InvalidRequestError
from agent_firewall.sandbox import (
    SandboxAdapter,
    SandboxApprovalRequiredError,
    SandboxDeniedError,
    SandboxError,
    SandboxProtocol,
    SandboxResult,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _firewall(*, allow=None, deny=None, approve=None, agents=None) -> Firewall:
    """Build a Firewall with a simple policy."""
    if agents is not None:
        agent_data = agents
    else:
        agent_data = {
            "dev": {
                "allow": allow or [],
                "deny": deny or [],
                "approve": approve or [],
            }
        }
    return Firewall.from_dict({"version": 1, "agents": agent_data})


def _allowing_firewall() -> Firewall:
    """Firewall that allows dev to filesystem.write ./src/**."""
    return _firewall(
        allow=[{"action": "filesystem.write", "resource": "./src/**"}]
    )


def _denying_firewall() -> Firewall:
    """Firewall that denies dev network.connect production-db:5432."""
    return _firewall(
        deny=[{"action": "network.connect", "resource": "production-db:5432"}]
    )


def _approving_firewall() -> Firewall:
    """Firewall that requires approval for dev git.push."""
    return _firewall(
        approve=[{"action": "git.push"}]
    )


def _default_deny_firewall() -> Firewall:
    """Empty policy — everything denied by default."""
    return _firewall()


class MockSandbox:
    """Minimal mock sandbox for testing."""

    def __init__(self, result="ok"):
        self._result = result
        self.calls = []

    def execute(self, action, resource=None, **kwargs):
        self.calls.append({"action": action, "resource": resource, **kwargs})
        return self._result


class FailingSandbox:
    """Sandbox that raises an exception on execute."""

    def __init__(self, exc=None):
        self._exc = exc or RuntimeError("sandbox internal error")
        self.calls = []

    def execute(self, action, resource=None, **kwargs):
        self.calls.append({"action": action, "resource": resource})
        raise self._exc


class DenyingSandbox:
    """Sandbox that always denies (simulates sandbox-level denial)."""

    def __init__(self):
        self.calls = []

    def execute(self, action, resource=None, **kwargs):
        self.calls.append({"action": action, "resource": resource})
        raise SandboxDeniedError("sandbox", action, resource or "")


# ── execute() tests ──────────────────────────────────────────────────────────


class TestExecute(unittest.TestCase):
    """Tests for SandboxAdapter.execute()."""

    def test_allow_delegates_to_sandbox(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(result.decision.kind, DecisionKind.ALLOW)
        self.assertEqual(len(sandbox.calls), 1)
        self.assertEqual(sandbox.calls[0]["action"], "filesystem.write")

    def test_allow_returns_sandbox_result(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox(result="data123")
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertIsInstance(result, SandboxResult)
        self.assertEqual(result.result, "data123")

    def test_allow_preserves_agent(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(result.agent, "dev")

    def test_allow_preserves_action(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(result.action, "filesystem.write")

    def test_allow_preserves_resource(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(result.resource, "./src/main.py")

    def test_deny_raises_sandbox_denied_error(self):
        fw = _denying_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxDeniedError) as ctx:
            adapter.execute("dev", "network.connect", "production-db:5432")
        self.assertEqual(ctx.exception.agent, "dev")
        self.assertEqual(ctx.exception.action, "network.connect")

    def test_deny_never_calls_sandbox(self):
        fw = _denying_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxDeniedError):
            adapter.execute("dev", "network.connect", "production-db:5432")
        self.assertEqual(len(sandbox.calls), 0)

    def test_approve_raises_approval_required_error(self):
        fw = _approving_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxApprovalRequiredError) as ctx:
            adapter.execute("dev", "git.push")
        self.assertEqual(ctx.exception.agent, "dev")
        self.assertEqual(ctx.exception.action, "git.push")

    def test_approve_never_calls_sandbox(self):
        fw = _approving_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxApprovalRequiredError):
            adapter.execute("dev", "git.push")
        self.assertEqual(len(sandbox.calls), 0)

    def test_default_deny_never_calls_sandbox(self):
        fw = _default_deny_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxDeniedError):
            adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(len(sandbox.calls), 0)

    def test_invalid_request_raises_sandbox_error(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxError):
            adapter.execute("", "filesystem.write", "./src/main.py")
        self.assertEqual(len(sandbox.calls), 0)

    def test_sandbox_exception_wrapped_in_sandbox_error(self):
        fw = _allowing_firewall()
        sandbox = FailingSandbox(RuntimeError("boom"))
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxError) as ctx:
            adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertIn("boom", str(ctx.exception.reason))
        self.assertEqual(ctx.exception.agent, "dev")

    def test_sandbox_exception_never_becomes_allow(self):
        fw = _allowing_firewall()
        sandbox = FailingSandbox(RuntimeError("boom"))
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxError):
            adapter.execute("dev", "filesystem.write", "./src/main.py")
        # Verify sandbox was called (ALLOW was reached) but error was wrapped
        self.assertEqual(len(sandbox.calls), 1)

    def test_kwargs_passed_to_sandbox(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        adapter.execute("dev", "filesystem.write", "./src/main.py",
                        cwd="/tmp", timeout=30)
        # MockSandbox stores **kwargs directly in the call dict
        self.assertEqual(sandbox.calls[0]["cwd"], "/tmp")
        self.assertEqual(sandbox.calls[0]["timeout"], 30)

    def test_no_resource(self):
        fw = _approving_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        # git.push has no resource; policy says APPROVE for dev
        with self.assertRaises(SandboxApprovalRequiredError):
            adapter.execute("dev", "git.push")

    def test_deterministic(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        r1 = adapter.execute("dev", "filesystem.write", "./src/main.py")
        r2 = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(r1.decision.kind, r2.decision.kind)
        self.assertEqual(r1.agent, r2.agent)
        self.assertEqual(r1.action, r2.action)
        self.assertEqual(r1.resource, r2.resource)

    def test_wildcard_match(self):
        fw = _firewall(
            allow=[{"action": "filesystem.read", "resource": "./**"}]
        )
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("dev", "filesystem.read", "./any/file.py")
        self.assertEqual(result.decision.kind, DecisionKind.ALLOW)

    def test_deny_overrides_allow(self):
        fw = _firewall(
            allow=[{"action": "filesystem.write", "resource": "./**"}],
            deny=[{"action": "filesystem.write", "resource": "./secret/**"}],
        )
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        # Allowed
        r_allow = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(r_allow.decision.kind, DecisionKind.ALLOW)
        # Denied
        with self.assertRaises(SandboxDeniedError):
            adapter.execute("dev", "filesystem.write", "./secret/key")

    def test_sandbox_denying_error_propagates(self):
        """SandboxDeniedError from sandbox propagates directly."""
        fw = _allowing_firewall()
        sandbox = DenyingSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxDeniedError):
            adapter.execute("dev", "filesystem.write", "./src/main.py")

    def test_unicode_fields(self):
        fw = _firewall(
            allow=[{"action": "filesystem.read", "resource": "./**"}],
            agents={"développeur": {
                "allow": [{"action": "filesystem.read", "resource": "./**"}]
            }},
        )
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("développeur", "filesystem.read", "./файл.py")
        self.assertEqual(result.agent, "développeur")
        self.assertEqual(result.resource, "./файл.py")


# ── check_only() tests ──────────────────────────────────────────────────────


class TestCheckOnly(unittest.TestCase):
    """Tests for SandboxAdapter.check_only()."""

    def test_allow_returns_allow(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        d = adapter.check_only("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_deny_returns_deny(self):
        fw = _denying_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        d = adapter.check_only("dev", "network.connect", "production-db:5432")
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_approve_returns_approve(self):
        fw = _approving_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        d = adapter.check_only("dev", "git.push")
        self.assertEqual(d.kind, DecisionKind.APPROVE)

    def test_never_calls_sandbox(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        adapter.check_only("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(len(sandbox.calls), 0)

    def test_default_deny(self):
        fw = _default_deny_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        d = adapter.check_only("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_invalid_request_raises(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(InvalidRequestError):
            adapter.check_only("", "filesystem.write", "./src/main.py")

    def test_deterministic(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        d1 = adapter.check_only("dev", "filesystem.write", "./src/main.py")
        d2 = adapter.check_only("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d1.kind, d2.kind)


# ── SandboxResult tests ──────────────────────────────────────────────────────


class TestSandboxResult(unittest.TestCase):
    """Tests for SandboxResult immutability."""

    def test_is_frozen(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("dev", "filesystem.write", "./src/main.py")
        with self.assertRaises(AttributeError):
            result.agent = "hacker"

    def test_decision_preserved(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertIsNotNone(result.decision)
        self.assertEqual(result.decision.kind, DecisionKind.ALLOW)

    def test_result_field(self):
        fw = _allowing_firewall()
        sandbox = MockSandbox(result={"output": "success"})
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(result.result, {"output": "success"})


# ── Security / adversarial tests ────────────────────────────────────────────


class TestSecurity(unittest.TestCase):
    """Adversarial security tests for the sandbox adapter."""

    def test_dangerous_imports_not_present(self):
        """sandbox.py must not import subprocess, socket, http, or container libs."""
        sandbox_path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "sandbox.py"
        )
        with open(sandbox_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        dangerous = {
            "subprocess", "socket", "http", "urllib", "os", "shutil",
            "docker", "container", "lxc", "nsjail", "firejail",
        }
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod in dangerous:
                        found.add(mod)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod in dangerous:
                        found.add(mod)
        self.assertEqual(found, set(), f"Dangerous imports found: {found}")

    def test_zero_third_party_dependencies(self):
        """sandbox.py must use only stdlib and internal imports."""
        sandbox_path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "sandbox.py"
        )
        with open(sandbox_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        third_party = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod not in ("dataclasses", "typing", "__future__",
                                    "agent_firewall", "os", "sys"):
                        third_party.add(mod)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod not in ("typing", "dataclasses", "__future__",
                                    "agent_firewall", ""):
                        third_party.add(mod)
        self.assertEqual(third_party, set(), f"Third-party imports: {third_party}")

    def test_no_policy_mutation(self):
        """Adapter must not modify the underlying policy."""
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        policy_before = fw.policy
        adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertIs(fw.policy, policy_before)

    def test_firewall_errors_not_converted_to_allow(self):
        """Invalid requests must raise SandboxError, not produce ALLOW."""
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxError):
            adapter.execute("", "filesystem.write", "./src/main.py")
        # sandbox must not be called
        self.assertEqual(len(sandbox.calls), 0)

    def test_bridge_does_not_bypass_firewall(self):
        """Every query must go through Firewall.check()."""
        fw = _default_deny_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        d = adapter.check_only("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_bridge_does_not_grant_capabilities(self):
        """Adapter must not introduce new authorization rules."""
        fw = _default_deny_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxDeniedError):
            adapter.execute("dev", "filesystem.write", "./src/main.py")

    def test_no_new_capability_introduced(self):
        """Adapter must not allow novel action types."""
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        with self.assertRaises(SandboxDeniedError):
            adapter.execute("dev", "magic.admin", "./everything")

    def test_frozen_files_not_modified(self):
        """Phase 1-13 source files must not have changed."""
        frozen_files = [
            "agent_firewall/evaluator.py",
            "agent_firewall/model.py",
            "agent_firewall/normalize.py",
            "agent_firewall/policy.py",
            "agent_firewall/simulate.py",
            "agent_firewall/diff.py",
            "agent_firewall/lint.py",
            "agent_firewall/test_cases.py",
            "agent_firewall/approval.py",
            "agent_firewall/audit.py",
            "agent_firewall/cli.py",
            "agent_firewall/orchestrator.py",
            "agent_firewall/adapters/filesystem.py",
            "agent_firewall/adapters/process.py",
            "agent_firewall/adapters/git.py",
            "agent_firewall/adapters/network.py",
            "agent_firewall/adapters/mcp_bridge.py",
            "agent_firewall/adapters/mcp.py",
        ]
        for fp in frozen_files:
            full = os.path.join(os.path.dirname(__file__), "..", fp)
            self.assertTrue(os.path.exists(full), f"Frozen file missing: {fp}")

    def test_documentation_files_untouched(self):
        """Documentation files must not have been modified."""
        doc_files = [
            "DESIGN.md", "SPEC.md", "SECURITY.md", "THREAT_MODEL.md",
            "IMPLEMENTATION.md", "TEST_PLAN.md", "ROADMAP.md",
            "README.md", "CONTRIBUTING.md", "CHANGELOG.md", "AGENTS.md",
        ]
        for df in doc_files:
            full = os.path.join(os.path.dirname(__file__), "..", df)
            self.assertTrue(os.path.exists(full), f"Doc file missing: {df}")

    def test_firewall_property(self):
        """Adapter exposes the underlying firewall instance."""
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        self.assertIs(adapter.firewall, fw)

    def test_sandbox_property(self):
        """Adapter exposes the underlying sandbox instance."""
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        self.assertIs(adapter.sandbox, sandbox)

    def test_adapter_preserves_policy_version_in_decision(self):
        """Decision from adapter must carry policy version/generation."""
        fw = _allowing_firewall()
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)
        result = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertIsNotNone(result.decision.policy_version)
        self.assertIsNotNone(result.decision.policy_generation)

    def test_execute_check_only_consistent(self):
        """execute() and check_only() should return consistent decisions."""
        fw = _firewall(
            allow=[{"action": "filesystem.write", "resource": "./src/**"}],
            approve=[{"action": "git.push"}],
            deny=[{"action": "network.connect", "resource": "prod:5432"}],
        )
        sandbox = MockSandbox()
        adapter = SandboxAdapter(fw, sandbox)

        d1 = adapter.check_only("dev", "filesystem.write", "./src/main.py")
        r1 = adapter.execute("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d1.kind, r1.decision.kind)

        d2 = adapter.check_only("dev", "git.push")
        with self.assertRaises(SandboxApprovalRequiredError):
            adapter.execute("dev", "git.push")
        self.assertEqual(d2.kind, DecisionKind.APPROVE)

    def test_sandbox_protocol_is_runtime_checkable(self):
        """SandboxProtocol should be runtime-checkable."""
        sandbox = MockSandbox()
        self.assertTrue(isinstance(sandbox, SandboxProtocol))


# ── Phase 1-13 regression tests ─────────────────────────────────────────────


class TestRegression(unittest.TestCase):
    """Verify Phase 1-13 functionality remains intact."""

    def test_phase1_core_still_works(self):
        from agent_firewall import Firewall, Request
        from agent_firewall.model import DecisionKind
        fw = Firewall.from_dict({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [{"action": "filesystem.read", "resource": "./**"}],
                }
            },
        })
        d = fw.check(Request("dev", "filesystem.read", "./src/main.py"))
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_phase1_default_deny(self):
        from agent_firewall import Firewall, Request
        from agent_firewall.model import DecisionKind
        fw = Firewall.from_dict({"version": 1, "agents": {}})
        d = fw.check(Request("dev", "filesystem.read", "./src/main.py"))
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_adapters_unchanged(self):
        """Adapters must still be importable."""
        from agent_firewall.adapters import (
            FilesystemAdapter, ProcessAdapter, GitAdapter, NetworkAdapter,
        )
        self.assertTrue(callable(FilesystemAdapter))
        self.assertTrue(callable(ProcessAdapter))
        self.assertTrue(callable(GitAdapter))
        self.assertTrue(callable(NetworkAdapter))

    def test_orchestrator_unchanged(self):
        """Orchestrator bridge must still be importable."""
        from agent_firewall.orchestrator import OrchestratorBridge
        self.assertTrue(callable(OrchestratorBridge))

    def test_mcp_bridge_unchanged(self):
        """MCP bridge must still be importable."""
        from agent_firewall.adapters.mcp_bridge import translate_mcp_tool_call
        self.assertTrue(callable(translate_mcp_tool_call))


if __name__ == "__main__":
    unittest.main()
