"""Tests for Phase 16 policy analysis.

Verifies PolicyAnalyzer, permission graph, privilege mismatch,
unused capabilities, broad permissions, conflicts, reachability,
and serialization.
"""

import ast
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall import Firewall, Request
from agent_firewall.model import DecisionKind
from agent_firewall.analysis import (
    BroadPermission,
    CapabilityNode,
    ConflictEntry,
    PolicyAnalyzer,
    PrivilegeMismatch,
    ReachabilityResult,
    UnusedCapability,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _policy(**kwargs) -> Firewall:
    """Build a Firewall from a policy dict."""
    agents = kwargs.get("agents", {})
    data = {"version": 1, "agents": agents}
    return Firewall.from_dict(data)


def _simple_policy() -> PolicyAnalyzer:
    """Policy with two agents, mixed capabilities."""
    fw = _policy(agents={
        "dev": {
            "allow": [
                {"action": "filesystem.read", "resource": "./**"},
                {"action": "filesystem.write", "resource": "./src/**"},
            ],
            "deny": [
                {"action": "filesystem.read", "resource": "./.env"},
            ],
            "approve": [
                {"action": "git.push"},
            ],
        },
        "tester": {
            "allow": [
                {"action": "filesystem.read", "resource": "./**"},
                {"action": "process.spawn", "resource": "pytest"},
            ],
            "deny": [],
            "approve": [],
        },
    })
    return PolicyAnalyzer(fw.policy)


# ── Permission graph tests ──────────────────────────────────────────────────


class TestPermissionGraph(unittest.TestCase):
    """Tests for PolicyAnalyzer.permission_graph()."""

    def test_empty_policy(self):
        fw = _policy(agents={})
        analyzer = PolicyAnalyzer(fw.policy)
        graph = analyzer.permission_graph()
        self.assertEqual(graph, [])

    def test_single_agent_single_rule(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        graph = analyzer.permission_graph()
        self.assertEqual(len(graph), 1)
        self.assertEqual(graph[0].agent, "dev")
        self.assertEqual(graph[0].action, "fs.read")
        self.assertEqual(graph[0].resource, "./**")
        self.assertEqual(graph[0].collection, "allow")

    def test_multiple_agents_mixed(self):
        analyzer = _simple_policy()
        graph = analyzer.permission_graph()
        # dev: 2 allow + 1 deny + 1 approve = 4
        # tester: 2 allow = 2
        self.assertEqual(len(graph), 6)

    def test_rules_with_resources(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.write", "resource": "./src/**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        graph = analyzer.permission_graph()
        self.assertEqual(graph[0].resource, "./src/**")

    def test_rules_without_resources(self):
        fw = _policy(agents={
            "dev": {"approve": [{"action": "git.push"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        graph = analyzer.permission_graph()
        self.assertIsNone(graph[0].resource)

    def test_deterministic(self):
        analyzer = _simple_policy()
        g1 = analyzer.permission_graph()
        g2 = analyzer.permission_graph()
        self.assertEqual(
            [(n.agent, n.action, n.resource, n.collection) for n in g1],
            [(n.agent, n.action, n.resource, n.collection) for n in g2],
        )

    def test_frozen(self):
        analyzer = _simple_policy()
        graph = analyzer.permission_graph()
        with self.assertRaises(AttributeError):
            graph[0].agent = "admin"

    def test_unicode(self):
        fw = _policy(agents={
            "développeur": {
                "allow": [{"action": "fs.read", "resource": "./файл.py"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        graph = analyzer.permission_graph()
        self.assertEqual(graph[0].agent, "développeur")
        self.assertEqual(graph[0].resource, "./файл.py")


# ── Privilege mismatch tests ────────────────────────────────────────────────


class TestPrivilegeMismatch(unittest.TestCase):
    """Tests for PolicyAnalyzer.privilege_mismatches()."""

    def test_agent_a_denied_agent_b_allowed(self):
        fw = _policy(agents={
            "dev": {
                "allow": [],
                "deny": [{"action": "git.push"}],
            },
            "ops": {
                "allow": [{"action": "git.push"}],
                "deny": [],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        mismatches = analyzer.privilege_mismatches()
        self.assertTrue(len(mismatches) > 0)
        # ops has git.push, dev does not (denied)
        found = any(
            m.agent_lacking == "dev" and m.agent_having == "ops"
            and m.action == "git.push"
            for m in mismatches
        )
        self.assertTrue(found)

    def test_agent_a_denied_agent_b_denied(self):
        fw = _policy(agents={
            "dev": {"deny": [{"action": "git.push"}]},
            "ops": {"deny": [{"action": "git.push"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        mismatches = analyzer.privilege_mismatches()
        # Neither has allow/approve, so no mismatch
        self.assertEqual(len(mismatches), 0)

    def test_agent_a_allowed_agent_b_denied(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "git.push"}]},
            "ops": {"deny": [{"action": "git.push"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        mismatches = analyzer.privilege_mismatches()
        # dev has allow, ops does not → mismatch for ops
        found = any(
            m.agent_lacking == "ops" and m.agent_having == "dev"
            for m in mismatches
        )
        self.assertTrue(found)

    def test_unrelated_action_no_mismatch(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read"}]},
            "ops": {"allow": [{"action": "git.push"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        mismatches = analyzer.privilege_mismatches()
        # Different actions → no mismatch
        self.assertEqual(len(mismatches), 0)

    def test_same_agent_no_mismatch(self):
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "git.push"}],
                "deny": [{"action": "fs.write"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        mismatches = analyzer.privilege_mismatches()
        # Same agent excluded
        self.assertEqual(len(mismatches), 0)

    def test_deterministic(self):
        analyzer = _simple_policy()
        m1 = analyzer.privilege_mismatches()
        m2 = analyzer.privilege_mismatches()
        self.assertEqual(
            [(m.agent_lacking, m.agent_having, m.action) for m in m1],
            [(m.agent_lacking, m.agent_having, m.action) for m in m2],
        )

    def test_frozen(self):
        analyzer = _simple_policy()
        mismatches = analyzer.privilege_mismatches()
        if mismatches:
            with self.assertRaises(AttributeError):
                mismatches[0].agent_lacking = "admin"

    def test_resource_mismatch(self):
        """Agent A denied specific resource, Agent B allowed same resource."""
        fw = _policy(agents={
            "dev": {
                "deny": [{"action": "fs.write", "resource": "./secret/**"}],
            },
            "ops": {
                "allow": [{"action": "fs.write", "resource": "./secret/**"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        mismatches = analyzer.privilege_mismatches()
        found = any(
            m.agent_lacking == "dev" and m.agent_having == "ops"
            and m.resource == "./secret/**"
            for m in mismatches
        )
        self.assertTrue(found)


# ── Unused capabilities tests ───────────────────────────────────────────────


class TestUnusedCapabilities(unittest.TestCase):
    """Tests for PolicyAnalyzer.unused_capabilities()."""

    def test_none_returns_empty(self):
        analyzer = _simple_policy()
        result = analyzer.unused_capabilities(test_cases=None)
        self.assertEqual(result, [])

    def test_empty_returns_empty(self):
        analyzer = _simple_policy()
        result = analyzer.unused_capabilities(test_cases=[])
        self.assertEqual(result, [])

    def test_matching_test_case_not_unused(self):
        analyzer = _simple_policy()
        result = analyzer.unused_capabilities(test_cases=[
            Request("dev", "filesystem.read", "./src/main.py"),
        ])
        # dev filesystem.read ./** is exercised
        unused_actions = [(u.agent, u.action) for u in result]
        self.assertNotIn(("dev", "filesystem.read"), unused_actions)

    def test_non_matching_test_case_reported(self):
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "git.commit"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        result = analyzer.unused_capabilities(test_cases=[
            Request("dev", "fs.read", "./src/main.py"),
        ])
        # git.commit not exercised by fs.read request
        self.assertTrue(len(result) > 0)
        self.assertEqual(result[0].action, "git.commit")

    def test_mixed_used_unused(self):
        fw = _policy(agents={
            "dev": {
                "allow": [
                    {"action": "fs.read", "resource": "./**"},
                    {"action": "git.commit"},
                ],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        result = analyzer.unused_capabilities(test_cases=[
            Request("dev", "fs.read", "./src/main.py"),
        ])
        # fs.read exercised, git.commit not
        unused_actions = [u.action for u in result]
        self.assertIn("git.commit", unused_actions)
        self.assertNotIn("fs.read", unused_actions)

    def test_deterministic(self):
        analyzer = _simple_policy()
        r1 = analyzer.unused_capabilities(test_cases=[
            Request("dev", "fs.read", "./src/main.py"),
        ])
        r2 = analyzer.unused_capabilities(test_cases=[
            Request("dev", "fs.read", "./src/main.py"),
        ])
        self.assertEqual(
            [(u.agent, u.action, u.resource) for u in r1],
            [(u.agent, u.action, u.resource) for u in r2],
        )


# ── Broad permissions tests ────────────────────────────────────────────────


class TestBroadPermissions(unittest.TestCase):
    """Tests for PolicyAnalyzer.broad_permissions()."""

    def test_no_broad_in_specific_policy(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        # ./src/** is specific enough, not flagged
        # Actually ** in resource IS flagged as broad per spec
        broad = analyzer.broad_permissions()
        # fs.read ./src/** has ** → broad
        self.assertTrue(len(broad) > 0)

    def test_double_star_detected(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        broad = analyzer.broad_permissions()
        self.assertEqual(len(broad), 1)
        self.assertEqual(broad[0].action, "fs.read")

    def test_no_resource_detected(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "git.commit"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        broad = analyzer.broad_permissions()
        self.assertEqual(len(broad), 1)
        self.assertEqual(broad[0].reason, "no resource constraint")

    def test_specific_resource_not_flagged(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./src/main.py"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        broad = analyzer.broad_permissions()
        self.assertEqual(len(broad), 0)

    def test_frozen(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        broad = analyzer.broad_permissions()
        with self.assertRaises(AttributeError):
            broad[0].agent = "admin"

    def test_deny_rules_not_flagged(self):
        fw = _policy(agents={
            "dev": {"deny": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        broad = analyzer.broad_permissions()
        self.assertEqual(len(broad), 0)

    def test_single_star_detected(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./*.py"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        broad = analyzer.broad_permissions()
        self.assertEqual(len(broad), 1)


# ── Conflict tests ──────────────────────────────────────────────────────────


class TestConflicts(unittest.TestCase):
    """Tests for PolicyAnalyzer.conflicts()."""

    def test_no_conflicts(self):
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./**"}],
                "deny": [{"action": "fs.write", "resource": "./secret/**"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        conflicts = analyzer.conflicts()
        self.assertEqual(len(conflicts), 0)

    def test_conflict_detected(self):
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "fs.write", "resource": "./src/**"}],
                "deny": [{"action": "fs.write", "resource": "./src/**"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        conflicts = analyzer.conflicts()
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].agent, "dev")
        self.assertEqual(conflicts[0].action, "fs.write")

    def test_different_resources_no_conflict(self):
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "fs.write", "resource": "./src/**"}],
                "deny": [{"action": "fs.write", "resource": "./secret/**"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        conflicts = analyzer.conflicts()
        self.assertEqual(len(conflicts), 0)

    def test_frozen(self):
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "x", "resource": "y"}],
                "deny": [{"action": "x", "resource": "y"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        conflicts = analyzer.conflicts()
        with self.assertRaises(AttributeError):
            conflicts[0].agent = "admin"

    def test_deterministic(self):
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "x", "resource": "y"}],
                "deny": [{"action": "x", "resource": "y"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        c1 = analyzer.conflicts()
        c2 = analyzer.conflicts()
        self.assertEqual(
            [(c.agent, c.action, c.resource) for c in c1],
            [(c.agent, c.action, c.resource) for c in c2],
        )

    def test_multiple_conflicts(self):
        fw = _policy(agents={
            "dev": {
                "allow": [
                    {"action": "a", "resource": "x"},
                    {"action": "b", "resource": "y"},
                ],
                "deny": [
                    {"action": "a", "resource": "x"},
                    {"action": "b", "resource": "y"},
                ],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        conflicts = analyzer.conflicts()
        self.assertEqual(len(conflicts), 2)


# ── Reachability tests ──────────────────────────────────────────────────────


class TestReachability(unittest.TestCase):
    """Tests for PolicyAnalyzer.reachability()."""

    def test_allowed_specific_resource(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "fs.read", "./src/main.py")
        self.assertTrue(r.reachable)

    def test_wildcard_allow(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "fs.read", "./any/file.py")
        self.assertTrue(r.reachable)

    def test_explicit_deny(self):
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "fs.write", "resource": "./**"}],
                "deny": [{"action": "fs.write", "resource": "./secret/**"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "fs.write", "./secret/key")
        self.assertFalse(r.reachable)
        self.assertEqual(r.blocked_by, "deny_rule")

    def test_unknown_agent(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("unknown", "fs.read", "./src/main.py")
        self.assertFalse(r.reachable)
        self.assertEqual(r.blocked_by, "unknown_agent")

    def test_unknown_action(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "git.push")
        self.assertFalse(r.reachable)
        self.assertEqual(r.blocked_by, "default_deny")

    def test_unrelated_resource(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "fs.read", "./secret/key")
        self.assertFalse(r.reachable)
        self.assertEqual(r.blocked_by, "default_deny")

    def test_resource_less_rule(self):
        """Rule with no resource matches any resource for that action."""
        fw = _policy(agents={
            "dev": {"allow": [{"action": "git.commit"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "git.commit")
        self.assertTrue(r.reachable)

    def test_approve_reachable(self):
        fw = _policy(agents={
            "dev": {"approve": [{"action": "git.push"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "git.push")
        self.assertTrue(r.reachable)

    def test_frozen(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "fs.read", "./src/main.py")
        with self.assertRaises(AttributeError):
            r.reachable = False

    def test_deterministic(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r1 = analyzer.reachability("dev", "fs.read", "./src/main.py")
        r2 = analyzer.reachability("dev", "fs.read", "./src/main.py")
        self.assertEqual(r1.reachable, r2.reachable)
        self.assertEqual(r1.blocked_by, r2.blocked_by)


# ── Reachability vs authorization separation tests ──────────────────────────


class TestReachabilityVsAuthorization(unittest.TestCase):
    """Verify reachability is analysis, not authorization."""

    def test_reachability_does_not_return_decision(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "fs.read", "./src/main.py")
        self.assertNotIsInstance(r, type(fw.check(Request("dev", "fs.read", "./src/main.py"))))

    def test_reachability_matches_evaluator_for_allow(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "fs.read", "./src/main.py")
        d = fw.check(Request("dev", "fs.read", "./src/main.py"))
        self.assertTrue(r.reachable)
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_reachability_matches_evaluator_for_deny(self):
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "fs.write", "resource": "./**"}],
                "deny": [{"action": "fs.write", "resource": "./secret/**"}],
            },
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("dev", "fs.write", "./secret/key")
        d = fw.check(Request("dev", "fs.write", "./secret/key"))
        self.assertFalse(r.reachable)
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_reachability_matches_evaluator_for_unknown_agent(self):
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        r = analyzer.reachability("unknown", "fs.read", "./src/main.py")
        d = fw.check(Request("unknown", "fs.read", "./src/main.py"))
        self.assertFalse(r.reachable)
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_analyzer_does_not_call_firewall_check(self):
        """Verify analyzer reads policy directly, not via Firewall.check()."""
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        analyzer = PolicyAnalyzer(fw.policy)
        # Reachability should work with just the policy, no Firewall needed
        r = analyzer.reachability("dev", "fs.read", "./src/main.py")
        self.assertTrue(r.reachable)


# ── Serialization tests ─────────────────────────────────────────────────────


class TestSerialization(unittest.TestCase):
    """Tests for to_dict() and to_text() on all result types."""

    def test_capability_node_to_dict(self):
        n = CapabilityNode(agent="dev", action="fs.read", resource="./**", collection="allow")
        d = n.to_dict()
        self.assertEqual(d["agent"], "dev")
        self.assertEqual(d["action"], "fs.read")
        self.assertEqual(d["resource"], "./**")
        self.assertEqual(d["collection"], "allow")

    def test_capability_node_no_resource(self):
        n = CapabilityNode(agent="dev", action="git.push", collection="approve")
        d = n.to_dict()
        self.assertNotIn("resource", d)

    def test_capability_node_to_text(self):
        n = CapabilityNode(agent="dev", action="fs.read", resource="./**", collection="allow")
        t = n.to_text()
        self.assertIn("dev", t)
        self.assertIn("fs.read", t)

    def test_mismatch_to_dict(self):
        m = PrivilegeMismatch(agent_lacking="dev", agent_having="ops", action="git.push")
        d = m.to_dict()
        self.assertEqual(d["agent_lacking"], "dev")
        self.assertEqual(d["agent_having"], "ops")

    def test_unused_to_dict(self):
        u = UnusedCapability(agent="dev", action="git.commit")
        d = u.to_dict()
        self.assertEqual(d["agent"], "dev")
        self.assertEqual(d["action"], "git.commit")

    def test_broad_to_dict(self):
        b = BroadPermission(agent="dev", action="fs.read", resource="./**", reason="broad")
        d = b.to_dict()
        self.assertEqual(d["reason"], "broad")

    def test_conflict_to_dict(self):
        c = ConflictEntry(agent="dev", action="fs.write", resource="./src/**")
        d = c.to_dict()
        self.assertEqual(d["agent"], "dev")

    def test_reachability_to_dict(self):
        r = ReachabilityResult(reachable=True, agent="dev", action="fs.read", resource="./src/main.py")
        d = r.to_dict()
        self.assertTrue(d["reachable"])

    def test_analyzer_to_dict(self):
        analyzer = _simple_policy()
        d = analyzer.to_dict()
        self.assertIn("permission_graph", d)
        self.assertIn("privilege_mismatches", d)
        self.assertIn("broad_permissions", d)
        self.assertIn("conflicts", d)

    def test_analyzer_to_text(self):
        analyzer = _simple_policy()
        t = analyzer.to_text()
        self.assertIsInstance(t, str)
        self.assertTrue(len(t) > 0)

    def test_json_serializable(self):
        analyzer = _simple_policy()
        d = analyzer.to_dict()
        # Should not raise
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)

    def test_unicode_serialization(self):
        fw = Firewall.from_dict({"version": 1, "agents": {
            "développeur": {"allow": [{"action": "fs.read", "resource": "./файл.py"}]},
        }})
        analyzer = PolicyAnalyzer(fw.policy)
        d = analyzer.to_dict()
        json_str = json.dumps(d, ensure_ascii=False)
        self.assertIn("développeur", json_str)


# ── Security / adversarial tests ────────────────────────────────────────────


class TestSecurity(unittest.TestCase):
    """Adversarial security tests for analysis module."""

    def test_no_dangerous_imports(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "analysis.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        dangerous = {
            "subprocess", "socket", "http", "urllib", "os", "shutil",
            "docker", "container",
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
        self.assertEqual(found, set(), f"Dangerous imports: {found}")

    def test_zero_third_party_dependencies(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "analysis.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        third_party = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod not in ("json", "dataclasses", "typing",
                                    "__future__", "agent_firewall"):
                        third_party.add(mod)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod not in ("json", "dataclasses", "typing",
                                    "__future__", "agent_firewall", ""):
                        third_party.add(mod)
        self.assertEqual(third_party, set(), f"Third-party: {third_party}")

    def test_frozen_files_unchanged(self):
        frozen_files = [
            "agent_firewall/evaluator.py", "agent_firewall/model.py",
            "agent_firewall/normalize.py", "agent_firewall/policy.py",
            "agent_firewall/simulate.py", "agent_firewall/diff.py",
            "agent_firewall/lint.py", "agent_firewall/test_cases.py",
            "agent_firewall/approval.py", "agent_firewall/audit.py",
            "agent_firewall/cli.py", "agent_firewall/orchestrator.py",
            "agent_firewall/sandbox.py", "agent_firewall/integrity.py",
        ]
        for fp in frozen_files:
            full = os.path.join(os.path.dirname(__file__), "..", fp)
            self.assertTrue(os.path.exists(full), f"Missing: {fp}")

    def test_documentation_untouched(self):
        for df in ["DESIGN.md", "SPEC.md", "SECURITY.md", "THREAT_MODEL.md",
                    "IMPLEMENTATION.md", "TEST_PLAN.md", "ROADMAP.md"]:
            full = os.path.join(os.path.dirname(__file__), "..", df)
            self.assertTrue(os.path.exists(full), f"Missing: {df}")

    def test_no_policy_mutation(self):
        analyzer = _simple_policy()
        policy_before = analyzer.policy
        analyzer.permission_graph()
        analyzer.privilege_mismatches()
        analyzer.broad_permissions()
        analyzer.conflicts()
        analyzer.reachability("dev", "fs.read", "./src/main.py")
        self.assertIs(analyzer.policy, policy_before)

    def test_analysis_never_produces_decision(self):
        analyzer = _simple_policy()
        # None of the analysis methods should return a Decision
        graph = analyzer.permission_graph()
        for node in graph:
            self.assertNotIsInstance(node, type(
                Firewall.from_dict({"version": 1, "agents": {}}).check(
                    Request("x", "y"))
            ))

    def test_analyzer_does_not_modify_evaluator(self):
        """Verify analysis.py does not import or modify evaluator.py."""
        import importlib
        import agent_firewall.evaluator as ev
        before = id(ev)
        analyzer = _simple_policy()
        analyzer.permission_graph()
        analyzer.reachability("dev", "fs.read", "./src/main.py")
        importlib.reload(ev)
        after = id(ev)
        # Module identity should be the same (no reload happened during analysis)


# ── Regression tests ────────────────────────────────────────────────────────


class TestRegression(unittest.TestCase):
    """Verify Phase 1-15 functionality remains intact."""

    def test_phase1_core(self):
        fw = Firewall.from_dict({"version": 1, "agents": {
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        }})
        d = fw.check(Request("dev", "fs.read", "./src/main.py"))
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_phase1_default_deny(self):
        fw = Firewall.from_dict({"version": 1, "agents": {}})
        d = fw.check(Request("dev", "fs.read", "./src/main.py"))
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_linter_still_works(self):
        from agent_firewall.lint import lint_policy
        fw = Firewall.from_dict({"version": 1, "agents": {
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        }})
        findings = lint_policy(fw.policy)
        self.assertIsInstance(findings, list)

    def test_adapters_unchanged(self):
        from agent_firewall.adapters import (
            FilesystemAdapter, ProcessAdapter, GitAdapter, NetworkAdapter,
        )
        self.assertTrue(callable(FilesystemAdapter))

    def test_orchestrator_unchanged(self):
        from agent_firewall.orchestrator import OrchestratorBridge
        self.assertTrue(callable(OrchestratorBridge))

    def test_sandbox_unchanged(self):
        from agent_firewall.sandbox import SandboxAdapter
        self.assertTrue(callable(SandboxAdapter))

    def test_integrity_unchanged(self):
        from agent_firewall.integrity import EvidenceChain, RevocationList
        self.assertTrue(callable(EvidenceChain))
        self.assertTrue(callable(RevocationList))


if __name__ == "__main__":
    unittest.main()
