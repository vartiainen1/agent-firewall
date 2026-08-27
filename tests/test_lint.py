"""Tests for the policy linter (Phase 3, DESIGN 39).

Verifies all lint checks:

    duplicate_rule     — same action+resource in same collection
    conflicting_rule   — allow and deny for same action+resource
    unreachable_rule   — allow shadowed by more-specific deny
    broad_wildcard     — ``**`` in allow rules
    no_resource        — action without resource constraint
    empty_agent        — agent with no rules

Also verifies:
    clean policy → empty findings
    deterministic output
    no side effects
    no ALLOW ever produced
"""

import unittest

from agent_firewall.lint import LintFinding, LintSeverity, lint_policy
from agent_firewall.policy import Policy, AgentPolicy, policy_from_dict
from types import MappingProxyType


def _make_policy(agents: dict) -> Policy:
    """Shorthand to build a Policy from a dict of agent configs."""
    return policy_from_dict({"version": 1, "agents": agents})


class CleanPolicyTests(unittest.TestCase):
    """A well-formed policy produces no findings."""

    def test_clean_policy_no_findings(self):
        p = _make_policy({
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./src/*.py"}],
                "deny": [{"action": "fs.write", "resource": "./.env"}],
            },
        })
        findings = lint_policy(p)
        self.assertEqual(findings, [])

    def test_empty_agents_no_findings(self):
        p = _make_policy({})
        findings = lint_policy(p)
        self.assertEqual(findings, [])


class DuplicateRuleTests(unittest.TestCase):
    """Detect duplicate rules within the same collection."""

    def test_duplicate_in_allow(self):
        p = _make_policy({
            "dev": {
                "allow": [
                    {"action": "fs.read", "resource": "./src/**"},
                    {"action": "fs.read", "resource": "./src/**"},
                ],
            },
        })
        findings = lint_policy(p)
        self.assertTrue(any(f.code == "duplicate_rule" for f in findings))

    def test_duplicate_in_deny(self):
        p = _make_policy({
            "dev": {
                "deny": [
                    {"action": "fs.write", "resource": "./.env"},
                    {"action": "fs.write", "resource": "./.env"},
                ],
            },
        })
        findings = lint_policy(p)
        self.assertTrue(any(f.code == "duplicate_rule" for f in findings))

    def test_no_duplicate_across_collections(self):
        """Same rule in allow and deny is a conflict, not a duplicate."""
        p = _make_policy({
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./src"}],
                "deny": [{"action": "fs.read", "resource": "./src"}],
            },
        })
        findings = lint_policy(p)
        codes = [f.code for f in findings]
        self.assertIn("conflicting_rule", codes)
        self.assertNotIn("duplicate_rule", codes)


class ConflictingRuleTests(unittest.TestCase):
    """Detect same action+resource in both allow and deny."""

    def test_exact_conflict(self):
        p = _make_policy({
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./src"}],
                "deny": [{"action": "fs.read", "resource": "./src"}],
            },
        })
        findings = lint_policy(p)
        conflicts = [f for f in findings if f.code == "conflicting_rule"]
        self.assertEqual(len(conflicts), 1)
        self.assertIn("deny takes precedence", conflicts[0].message)

    def test_no_conflict_different_resources(self):
        p = _make_policy({
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./src/**"}],
                "deny": [{"action": "fs.read", "resource": "./.env"}],
            },
        })
        findings = lint_policy(p)
        self.assertFalse(any(f.code == "conflicting_rule" for f in findings))


class UnreachableRuleTests(unittest.TestCase):
    """Detect allow rules shadowed by more-specific deny rules."""

    def test_unreachable_broad_allow(self):
        """Allow ``./**`` shadowed by deny ``./secret``."""
        p = _make_policy({
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./**"}],
                "deny": [{"action": "fs.read", "resource": "./secret"}],
            },
        })
        findings = lint_policy(p)
        self.assertTrue(any(f.code == "unreachable_rule" for f in findings))

    def test_no_unreachable_different_actions(self):
        p = _make_policy({
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./**"}],
                "deny": [{"action": "fs.write", "resource": "./secret"}],
            },
        })
        findings = lint_policy(p)
        self.assertFalse(any(f.code == "unreachable_rule" for f in findings))


class BroadWildcardTests(unittest.TestCase):
    """Detect ``**`` wildcard patterns in allow rules."""

    def test_broad_wildcard_detected(self):
        p = _make_policy({
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./**"}],
            },
        })
        findings = lint_policy(p)
        self.assertTrue(any(f.code == "broad_wildcard" for f in findings))

    def test_no_broad_wildcard_for_specific(self):
        p = _make_policy({
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./src/*.py"}],
            },
        })
        findings = lint_policy(p)
        self.assertFalse(any(f.code == "broad_wildcard" for f in findings))


class NoResourceTests(unittest.TestCase):
    """Detect actions without a resource constraint."""

    def test_no_resource_detected(self):
        p = _make_policy({
            "dev": {
                "allow": [{"action": "git.commit"}],
            },
        })
        findings = lint_policy(p)
        self.assertTrue(any(f.code == "no_resource" for f in findings))

    def test_no_resource_in_deny(self):
        p = _make_policy({
            "dev": {
                "deny": [{"action": "network.connect"}],
            },
        })
        findings = lint_policy(p)
        self.assertTrue(any(
            f.code == "no_resource" and f.agent == "dev"
            for f in findings
        ))


class EmptyAgentTests(unittest.TestCase):
    """Detect agents defined with no rules."""

    def test_empty_agent_detected(self):
        p = _make_policy({
            "dev": {
                "allow": [{"action": "fs.read"}],
            },
            "ghost": {},
        })
        findings = lint_policy(p)
        self.assertTrue(any(
            f.code == "empty_agent" and f.agent == "ghost"
            for f in findings
        ))


class LintDeterminismTests(unittest.TestCase):
    """Lint output must be deterministic."""

    def test_same_input_same_output(self):
        p = _make_policy({
            "dev": {
                "allow": [
                    {"action": "fs.read", "resource": "./**"},
                    {"action": "fs.read", "resource": "./**"},
                ],
                "deny": [{"action": "fs.read", "resource": "./secret"}],
            },
        })
        r1 = lint_policy(p)
        r2 = lint_policy(p)
        self.assertEqual(len(r1), len(r2))
        for f1, f2 in zip(r1, r2):
            self.assertEqual(f1.severity, f2.severity)
            self.assertEqual(f1.code, f2.code)
            self.assertEqual(f1.message, f2.message)


class LintSeverityTests(unittest.TestCase):
    """Verify severity levels are correctly assigned."""

    def test_duplicate_is_warning(self):
        p = _make_policy({
            "dev": {
                "allow": [
                    {"action": "fs.read", "resource": "./x"},
                    {"action": "fs.read", "resource": "./x"},
                ],
            },
        })
        findings = lint_policy(p)
        dup = [f for f in findings if f.code == "duplicate_rule"]
        self.assertTrue(all(f.severity == LintSeverity.WARNING for f in dup))

    def test_empty_agent_is_info(self):
        p = _make_policy({"ghost": {}})
        findings = lint_policy(p)
        self.assertTrue(all(f.severity == LintSeverity.INFO for f in findings))


class LintNeverProducesALLOW(unittest.TestCase):
    """Security invariant: lint must never produce an ALLOW decision."""

    def test_lint_returns_findings_not_decisions(self):
        """lint_policy returns LintFinding objects, not Decision objects."""
        p = _make_policy({
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./**"}],
            },
        })
        findings = lint_policy(p)
        for f in findings:
            self.assertIsInstance(f, LintFinding)
            self.assertNotEqual(f.severity, "ALLOW")


class LintSideEffectFreedomTests(unittest.TestCase):
    """Lint must not create files, modify state, or access network."""

    def test_lint_writes_nothing(self):
        import os
        before = set(os.listdir(os.getcwd()))
        p = _make_policy({"dev": {"allow": [{"action": "x"}]}})
        lint_policy(p)
        after = set(os.listdir(os.getcwd()))
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
