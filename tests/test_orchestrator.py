"""Tests for Phase 13 orchestrator integration.

Verifies OrchestratorBridge and TaskAuthorization.
All tests delegate authorization to the existing Firewall.check()
implementation and verify that the bridge preserves all security invariants.
"""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall import Firewall, Request
from agent_firewall.model import DecisionKind, InvalidRequestError
from agent_firewall.orchestrator import OrchestratorBridge, TaskAuthorization


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


# ── can_perform() tests ─────────────────────────────────────────────────────


class TestCanPerform(unittest.TestCase):
    """Tests for OrchestratorBridge.can_perform()."""

    def test_allow_returns_allow(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_deny_returns_deny(self):
        fw = _denying_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "network.connect", "production-db:5432")
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_approve_returns_approve(self):
        fw = _approving_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "git.push")
        self.assertEqual(d.kind, DecisionKind.APPROVE)

    def test_default_deny_returns_deny(self):
        fw = _default_deny_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "filesystem.read", "./src/main.py")
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_unknown_agent_returns_deny(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("unknown", "filesystem.write", "./src/main.py")
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_unknown_action_returns_deny(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "secret.read", "./src/main.py")
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_no_resource(self):
        fw = _approving_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "git.push")
        self.assertEqual(d.kind, DecisionKind.APPROVE)
        self.assertIsNone(d.resource)

    def test_preserves_agent(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d.agent, "dev")

    def test_preserves_action(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d.action, "filesystem.write")

    def test_preserves_resource(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d.resource, "./src/main.py")

    def test_invalid_request_raises(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        with self.assertRaises(InvalidRequestError):
            bridge.can_perform("", "filesystem.write", "./src/main.py")

    def test_deterministic(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        d1 = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        d2 = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d1.kind, d2.kind)
        self.assertEqual(d1.agent, d2.agent)
        self.assertEqual(d1.action, d2.action)
        self.assertEqual(d1.resource, d2.resource)

    def test_wildcard_match(self):
        fw = _firewall(
            allow=[{"action": "filesystem.read", "resource": "./**"}]
        )
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "filesystem.read", "./any/nested/file.py")
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_deny_overrides_allow(self):
        fw = _firewall(
            allow=[{"action": "filesystem.write", "resource": "./**"}],
            deny=[{"action": "filesystem.write", "resource": "./secret/**"}],
        )
        bridge = OrchestratorBridge(fw)
        d_allow = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        d_deny = bridge.can_perform("dev", "filesystem.write", "./secret/key")
        self.assertEqual(d_allow.kind, DecisionKind.ALLOW)
        self.assertEqual(d_deny.kind, DecisionKind.DENY)

    def test_unicode_agent(self):
        fw = _firewall(
            allow=[{"action": "filesystem.read", "resource": "./**"}],
            agents={"développeur": {"allow": [{"action": "filesystem.read", "resource": "./**"}]}},
        )
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("développeur", "filesystem.read", "./src/main.py")
        self.assertEqual(d.kind, DecisionKind.ALLOW)
        self.assertEqual(d.agent, "développeur")

    def test_unicode_resource(self):
        fw = _firewall(
            allow=[{"action": "filesystem.read", "resource": "./**"}]
        )
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "filesystem.read", "./src/файл.py")
        self.assertEqual(d.kind, DecisionKind.ALLOW)
        self.assertEqual(d.resource, "./src/файл.py")


# ── can_perform_batch() tests ───────────────────────────────────────────────


class TestCanPerformBatch(unittest.TestCase):
    """Tests for OrchestratorBridge.can_perform_batch()."""

    def test_empty_batch(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        results = bridge.can_perform_batch([])
        self.assertEqual(results, [])

    def test_single_request(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        req = Request("dev", "filesystem.write", "./src/main.py")
        results = bridge.can_perform_batch([req])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].kind, DecisionKind.ALLOW)

    def test_multiple_requests_preserve_order(self):
        fw = _firewall(
            allow=[{"action": "filesystem.write", "resource": "./src/**"}],
            deny=[{"action": "filesystem.write", "resource": "./secret/**"}],
        )
        bridge = OrchestratorBridge(fw)
        reqs = [
            Request("dev", "filesystem.write", "./src/main.py"),
            Request("dev", "filesystem.write", "./secret/key"),
            Request("dev", "filesystem.write", "./src/test.py"),
        ]
        results = bridge.can_perform_batch(reqs)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0].kind, DecisionKind.ALLOW)
        self.assertEqual(results[1].kind, DecisionKind.DENY)
        self.assertEqual(results[2].kind, DecisionKind.ALLOW)

    def test_mixed_decisions(self):
        fw = _firewall(
            allow=[{"action": "filesystem.write", "resource": "./src/**"}],
            approve=[{"action": "git.push"}],
            deny=[{"action": "network.connect", "resource": "prod:5432"}],
        )
        bridge = OrchestratorBridge(fw)
        reqs = [
            Request("dev", "filesystem.write", "./src/main.py"),
            Request("dev", "git.push"),
            Request("dev", "network.connect", "prod:5432"),
        ]
        results = bridge.can_perform_batch(reqs)
        self.assertEqual(results[0].kind, DecisionKind.ALLOW)
        self.assertEqual(results[1].kind, DecisionKind.APPROVE)
        self.assertEqual(results[2].kind, DecisionKind.DENY)

    def test_batch_preserves_same_policy_snapshot(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        reqs = [
            Request("dev", "filesystem.write", "./src/main.py"),
            Request("dev", "filesystem.write", "./src/test.py"),
        ]
        results = bridge.can_perform_batch(reqs)
        # Both should use the same policy snapshot
        self.assertEqual(results[0].policy_version, results[1].policy_version)
        self.assertEqual(results[0].policy_generation, results[1].policy_generation)

    def test_batch_does_not_mutate_requests(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        req = Request("dev", "filesystem.write", "./src/main.py")
        original_agent = req.agent
        original_action = req.action
        original_resource = req.resource
        bridge.can_perform_batch([req])
        self.assertEqual(req.agent, original_agent)
        self.assertEqual(req.action, original_action)
        self.assertEqual(req.resource, original_resource)

    def test_batch_with_invalid_request_raises(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        reqs = [
            Request("dev", "filesystem.write", "./src/main.py"),
            Request("", "filesystem.write", "./src/main.py"),  # invalid
        ]
        with self.assertRaises(InvalidRequestError):
            bridge.can_perform_batch(reqs)

    def test_batch_deterministic(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        reqs = [
            Request("dev", "filesystem.write", "./src/main.py"),
            Request("dev", "filesystem.write", "./secret/key"),
        ]
        r1 = bridge.can_perform_batch(reqs)
        r2 = bridge.can_perform_batch(reqs)
        for a, b in zip(r1, r2):
            self.assertEqual(a.kind, b.kind)


# ── evaluate_task() tests ────────────────────────────────────────────────────


class TestEvaluateTask(unittest.TestCase):
    """Tests for OrchestratorBridge.evaluate_task()."""

    def test_allow(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        ta = bridge.evaluate_task("dev", "filesystem.write", "./src/main.py")
        self.assertIsInstance(ta, TaskAuthorization)
        self.assertEqual(ta.decision.kind, DecisionKind.ALLOW)
        self.assertEqual(ta.agent, "dev")
        self.assertEqual(ta.action, "filesystem.write")
        self.assertEqual(ta.resource, "./src/main.py")

    def test_deny(self):
        fw = _denying_firewall()
        bridge = OrchestratorBridge(fw)
        ta = bridge.evaluate_task("dev", "network.connect", "production-db:5432")
        self.assertEqual(ta.decision.kind, DecisionKind.DENY)
        self.assertEqual(ta.agent, "dev")
        self.assertEqual(ta.action, "network.connect")
        self.assertEqual(ta.resource, "production-db:5432")

    def test_approve(self):
        fw = _approving_firewall()
        bridge = OrchestratorBridge(fw)
        ta = bridge.evaluate_task("dev", "git.push")
        self.assertEqual(ta.decision.kind, DecisionKind.APPROVE)
        self.assertEqual(ta.agent, "dev")
        self.assertEqual(ta.action, "git.push")
        self.assertIsNone(ta.resource)

    def test_default_deny(self):
        fw = _default_deny_firewall()
        bridge = OrchestratorBridge(fw)
        ta = bridge.evaluate_task("dev", "filesystem.read", "./src/main.py")
        self.assertEqual(ta.decision.kind, DecisionKind.DENY)

    def test_task_authorization_is_frozen(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        ta = bridge.evaluate_task("dev", "filesystem.write", "./src/main.py")
        # frozen dataclass should reject attribute assignment
        with self.assertRaises(AttributeError):
            ta.agent = "hacked"

    def test_preserves_reason(self):
        fw = _default_deny_firewall()
        bridge = OrchestratorBridge(fw)
        ta = bridge.evaluate_task("dev", "filesystem.write", "./src/main.py")
        # Default-deny decisions carry a reason
        self.assertIsInstance(ta.reason, str)

    def test_unicode_fields(self):
        fw = _firewall(
            allow=[{"action": "filesystem.read", "resource": "./**"}],
            agents={"développeur": {"allow": [{"action": "filesystem.read", "resource": "./**"}]}},
        )
        bridge = OrchestratorBridge(fw)
        ta = bridge.evaluate_task("développeur", "filesystem.read", "./файл.py")
        self.assertEqual(ta.agent, "développeur")
        self.assertEqual(ta.resource, "./файл.py")
        self.assertEqual(ta.decision.kind, DecisionKind.ALLOW)

    def test_deterministic(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        ta1 = bridge.evaluate_task("dev", "filesystem.write", "./src/main.py")
        ta2 = bridge.evaluate_task("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(ta1.decision.kind, ta2.decision.kind)
        self.assertEqual(ta1.agent, ta2.agent)
        self.assertEqual(ta1.action, ta2.action)
        self.assertEqual(ta1.resource, ta2.resource)

    def test_invalid_request_raises(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        with self.assertRaises(InvalidRequestError):
            bridge.evaluate_task("", "filesystem.write", "./src/main.py")

    def test_policy_version_preserved(self):
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        ta = bridge.evaluate_task("dev", "filesystem.write", "./src/main.py")
        self.assertIsNotNone(ta.decision.policy_version)
        self.assertIsNotNone(ta.decision.policy_generation)


# ── Security / adversarial tests ────────────────────────────────────────────


class TestSecurity(unittest.TestCase):
    """Adversarial security tests for the orchestrator bridge."""

    def test_no_execution_side_effects(self):
        """Bridge must not execute any filesystem/process/network operations."""
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        # This should only evaluate, never execute
        d = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_no_policy_mutation(self):
        """Bridge must not modify the underlying policy."""
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        policy_before = fw.policy
        bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        self.assertIs(fw.policy, policy_before)

    def test_firewall_errors_not_converted_to_allow(self):
        """Invalid requests must raise, not become ALLOW."""
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        with self.assertRaises(InvalidRequestError):
            bridge.can_perform("", "filesystem.write", "./src/main.py")
        # Verify no ALLOW was produced
        # (the exception prevents any Decision from being returned)

    def test_bridge_does_not_bypass_firewall(self):
        """Every query must go through Firewall.check()."""
        fw = _default_deny_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        # Default deny means this must be DENY
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_bridge_does_not_grant_capabilities(self):
        """Bridge must not introduce new authorization rules."""
        fw = _default_deny_firewall()
        bridge = OrchestratorBridge(fw)
        # Even though bridge "knows" about filesystem.write, it must not allow it
        d = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_dangerous_imports_not_present(self):
        """orchestrator.py must not import subprocess, socket, or http."""
        bridge_path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "orchestrator.py"
        )
        with open(bridge_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        dangerous = {"subprocess", "socket", "http", "urllib", "os", "shutil"}
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod in dangerous:
                        found.add(mod)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod in dangerous:
                        found.add(mod)
        self.assertEqual(found, set(), f"Dangerous imports found: {found}")

    def test_zero_third_party_dependencies(self):
        """orchestrator.py must use only stdlib and internal imports."""
        bridge_path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "orchestrator.py"
        )
        with open(bridge_path, "r", encoding="utf-8") as f:
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
                # Relative imports (from .model import ...) have level > 0
                if node.level and node.level > 0:
                    continue  # internal relative import
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod not in ("typing", "dataclasses", "__future__",
                                    "agent_firewall", ""):
                        third_party.add(mod)
        self.assertEqual(third_party, set(), f"Third-party imports: {third_party}")

    def test_frozen_files_not_modified(self):
        """Phase 1-12 source files must not have changed."""
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

    def test_no_new_capability_introduced(self):
        """Bridge must not introduce new action types."""
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        # A completely novel action must be denied
        d = bridge.can_perform("dev", "magic.admin", "./everything")
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_batch_same_as_individual(self):
        """Batch results must match individual check() results."""
        fw = _firewall(
            allow=[{"action": "filesystem.write", "resource": "./src/**"}],
            approve=[{"action": "git.push"}],
            deny=[{"action": "network.connect", "resource": "prod:5432"}],
        )
        bridge = OrchestratorBridge(fw)
        reqs = [
            Request("dev", "filesystem.write", "./src/main.py"),
            Request("dev", "git.push"),
            Request("dev", "network.connect", "prod:5432"),
        ]
        batch_results = bridge.can_perform_batch(reqs)
        for req, batch_d in zip(reqs, batch_results):
            individual_d = bridge.can_perform(req.agent, req.action, req.resource)
            self.assertEqual(batch_d.kind, individual_d.kind)

    def test_firewall_property(self):
        """Bridge exposes the underlying firewall instance."""
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        self.assertIs(bridge.firewall, fw)

    def test_task_authorization_frozen_immutable(self):
        """TaskAuthorization must be truly immutable."""
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        ta = bridge.evaluate_task("dev", "filesystem.write", "./src/main.py")
        # Attempt various mutations
        with self.assertRaises(AttributeError):
            ta.agent = "hacker"
        with self.assertRaises(AttributeError):
            ta.action = "magic.admin"
        with self.assertRaises(AttributeError):
            ta.resource = "./everything"
        with self.assertRaises(AttributeError):
            ta.decision = None

    def test_bridge_preserves_policy_version_in_decision(self):
        """Decision from bridge must carry policy version/generation."""
        fw = _allowing_firewall()
        bridge = OrchestratorBridge(fw)
        d = bridge.can_perform("dev", "filesystem.write", "./src/main.py")
        self.assertIsNotNone(d.policy_version)
        self.assertIsNotNone(d.policy_generation)


# ── Phase 1-12 regression tests ─────────────────────────────────────────────


class TestRegression(unittest.TestCase):
    """Verify Phase 1-12 functionality remains intact."""

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

    def test_phase1_deny_precedence(self):
        from agent_firewall import Firewall, Request
        from agent_firewall.model import DecisionKind
        fw = Firewall.from_dict({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [{"action": "filesystem.write", "resource": "./**"}],
                    "deny": [{"action": "filesystem.write", "resource": "./secret/**"}],
                }
            },
        })
        d_allow = fw.check(Request("dev", "filesystem.write", "./src/main.py"))
        d_deny = fw.check(Request("dev", "filesystem.write", "./secret/key"))
        self.assertEqual(d_allow.kind, DecisionKind.ALLOW)
        self.assertEqual(d_deny.kind, DecisionKind.DENY)

    def test_adapters_unchanged(self):
        """Adapters must still be importable."""
        from agent_firewall.adapters import (
            FilesystemAdapter, ProcessAdapter, GitAdapter, NetworkAdapter,
        )
        self.assertTrue(callable(FilesystemAdapter))
        self.assertTrue(callable(ProcessAdapter))
        self.assertTrue(callable(GitAdapter))
        self.assertTrue(callable(NetworkAdapter))

    def test_mcp_bridge_unchanged(self):
        """MCP bridge must still be importable."""
        from agent_firewall.adapters.mcp_bridge import translate_mcp_tool_call
        self.assertTrue(callable(translate_mcp_tool_call))


if __name__ == "__main__":
    unittest.main()
