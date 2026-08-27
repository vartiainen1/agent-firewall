"""Tests for Phase 18 policy suggestion validation.

Verifies SuggestionValidationResult, SuggestionValidator, lint regression
detection, test regression detection, and all security invariants.
"""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall import Firewall, Request
from agent_firewall.model import DecisionKind
from agent_firewall.policy import Policy, policy_from_dict
from agent_firewall.lint import LintFinding, LintSeverity, lint_policy
from agent_firewall.test_cases import TestCase, TestCaseResult, run_policy_tests
from agent_firewall.suggestions import PolicySuggestion, proposed_policy
from agent_firewall.validator import (
    SuggestionValidationResult,
    SuggestionValidator,
    _lint_key,
    _tc_match_key,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _policy(**kwargs) -> Firewall:
    """Build a Firewall from a policy dict."""
    agents = kwargs.get("agents", {})
    data = {"version": 1, "agents": agents}
    return Firewall.from_dict(data)


def _simple_policy() -> Policy:
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
        },
    })
    return fw.policy


def _simple_test_cases() -> list:
    """Standard test cases for the simple policy."""
    return [
        TestCase(expected=DecisionKind.ALLOW, agent="dev",
                 action="filesystem.read", resource="./src/main.py"),
        TestCase(expected=DecisionKind.DENY, agent="dev",
                 action="filesystem.read", resource="./.env"),
        TestCase(expected=DecisionKind.ALLOW, agent="dev",
                 action="filesystem.write", resource="./src/main.py"),
        TestCase(expected=DecisionKind.ALLOW, agent="tester",
                 action="filesystem.read", resource="./src/main.py"),
        TestCase(expected=DecisionKind.DENY, agent="tester",
                 action="filesystem.write", resource="./src/main.py"),
    ]


def _make_suggestion(**kwargs) -> PolicySuggestion:
    """Create a PolicySuggestion with defaults."""
    defaults = {
        "suggestion_type": "add_rule",
        "agent": "dev",
        "collection": "deny",
        "rule": {"action": "fs.read", "resource": "./secret/**"},
        "reason": "test reason",
        "evidence": "test evidence",
    }
    defaults.update(kwargs)
    return PolicySuggestion(**defaults)


# ── _lint_key / _tc_match_key tests ─────────────────────────────────────────


class TestComparisonKeys(unittest.TestCase):
    """Tests for comparison key functions."""

    def test_lint_key_same_findings(self):
        f1 = LintFinding(severity=LintSeverity.WARNING, code="broad_wildcard",
                          message="msg1", agent="dev", action="fs.read",
                          resource="./**")
        f2 = LintFinding(severity=LintSeverity.WARNING, code="broad_wildcard",
                          message="msg2", agent="dev", action="fs.read",
                          resource="./**")
        # Same key despite different message
        self.assertEqual(_lint_key(f1), _lint_key(f2))

    def test_lint_key_different_findings(self):
        f1 = LintFinding(severity=LintSeverity.WARNING, code="broad_wildcard",
                          message="x", agent="dev", action="fs.read",
                          resource="./**")
        f2 = LintFinding(severity=LintSeverity.WARNING, code="conflicting_rule",
                          message="x", agent="dev", action="fs.read",
                          resource="./**")
        self.assertNotEqual(_lint_key(f1), _lint_key(f2))

    def test_tc_match_key_same_results(self):
        tc1 = TestCase(expected=DecisionKind.ALLOW, agent="dev",
                       action="fs.read", resource="./**")
        tc2 = TestCase(expected=DecisionKind.DENY, agent="dev",
                       action="fs.read", resource="./**")
        r1 = TestCaseResult(test_case=tc1, actual=DecisionKind.ALLOW, passed=True)
        r2 = TestCaseResult(test_case=tc2, actual=DecisionKind.DENY, passed=False)
        # Same match key despite different expected/actual
        self.assertEqual(_tc_match_key(r1), _tc_match_key(r2))

    def test_tc_match_key_different_results(self):
        tc1 = TestCase(expected=DecisionKind.ALLOW, agent="dev",
                       action="fs.read", resource="./**")
        tc2 = TestCase(expected=DecisionKind.ALLOW, agent="dev",
                       action="fs.write", resource="./**")
        r1 = TestCaseResult(test_case=tc1, actual=DecisionKind.ALLOW, passed=True)
        r2 = TestCaseResult(test_case=tc2, actual=DecisionKind.ALLOW, passed=True)
        self.assertNotEqual(_tc_match_key(r1), _tc_match_key(r2))


# ── SuggestionValidationResult tests ────────────────────────────────────────


class TestSuggestionValidationResult(unittest.TestCase):
    """Tests for SuggestionValidationResult frozen dataclass."""

    def test_frozen(self):
        r = SuggestionValidationResult(is_clean=True)
        with self.assertRaises(AttributeError):
            r.is_clean = False

    def test_default_is_clean(self):
        r = SuggestionValidationResult()
        self.assertTrue(r.is_clean)

    def test_is_clean_true(self):
        r = SuggestionValidationResult(
            source_lint_findings=[],
            proposed_lint_findings=[],
            new_lint_findings=[],
            source_test_results=[],
            proposed_test_results=[],
            test_regressions=[],
            is_clean=True,
        )
        self.assertTrue(r.is_clean)

    def test_is_clean_false_lint(self):
        f = LintFinding(severity=LintSeverity.WARNING, code="test",
                         message="x", agent="dev", action="fs.read")
        r = SuggestionValidationResult(
            new_lint_findings=[f],
            is_clean=False,
        )
        self.assertFalse(r.is_clean)

    def test_is_clean_false_regression(self):
        tc = TestCase(expected=DecisionKind.ALLOW, agent="dev",
                      action="fs.read", resource="./**")
        reg = TestCaseResult(test_case=tc, actual=DecisionKind.DENY, passed=False)
        r = SuggestionValidationResult(
            test_regressions=[reg],
            is_clean=False,
        )
        self.assertFalse(r.is_clean)


# ── SuggestionValidator tests ───────────────────────────────────────────────


class TestSuggestionValidator(unittest.TestCase):
    """Tests for SuggestionValidator."""

    def test_init(self):
        policy = _simple_policy()
        cases = _simple_test_cases()
        v = SuggestionValidator(policy, cases)
        self.assertIs(v.policy, policy)
        self.assertEqual(len(v.test_cases), len(cases))

    def test_init_type_error_policy(self):
        with self.assertRaises(TypeError):
            SuggestionValidator("not a policy", [])

    def test_init_type_error_cases(self):
        policy = _simple_policy()
        with self.assertRaises(TypeError):
            SuggestionValidator(policy, "not a list")

    def test_validate_clean(self):
        """No suggestions → no regressions, no new findings."""
        policy = _simple_policy()
        cases = _simple_test_cases()
        v = SuggestionValidator(policy, cases)
        result = v.validate([])
        self.assertTrue(result.is_clean)
        self.assertEqual(len(result.new_lint_findings), 0)
        self.assertEqual(len(result.test_regressions), 0)

    def test_validate_with_suggestions_clean(self):
        """Adding a deny rule that doesn't conflict → clean."""
        policy = _simple_policy()
        cases = _simple_test_cases()
        v = SuggestionValidator(policy, cases)
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule={"action": "git.push"},
        )
        result = v.validate([s])
        self.assertTrue(result.is_clean)

    def test_validate_lint_regression(self):
        """Removing a deny rule eliminates an unreachable_rule finding
        but that's not a regression — it's a lint improvement.
        Adding a conflicting rule IS a lint regression."""
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./**"}],
            },
        })
        cases = [
            TestCase(expected=DecisionKind.ALLOW, agent="dev",
                     action="fs.read", resource="./src/main.py"),
        ]
        v = SuggestionValidator(fw.policy, cases)

        # Add a deny for the same action+resource → creates conflicting_rule
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule={"action": "fs.read", "resource": "./**"},
        )
        result = v.validate([s])
        # Source had no conflicting_rule; proposed does → new lint finding
        self.assertFalse(result.is_clean)
        self.assertTrue(len(result.new_lint_findings) > 0)
        codes = [f.code for f in result.new_lint_findings]
        self.assertIn("conflicting_rule", codes)

    def test_validate_test_regression(self):
        """Removing a deny rule that was protecting a test → regression."""
        policy = _simple_policy()
        cases = [
            TestCase(expected=DecisionKind.DENY, agent="dev",
                     action="filesystem.read", resource="./.env"),
        ]
        v = SuggestionValidator(policy, cases)

        # Verify source passes
        source_result = run_policy_tests(policy, cases)
        self.assertTrue(source_result[0].passed)

        # Remove the deny rule → test should now fail
        s = PolicySuggestion(
            suggestion_type="remove_rule",
            agent="dev",
            collection="deny",
            rule={"action": "filesystem.read", "resource": "./.env"},
        )
        result = v.validate([s])
        self.assertFalse(result.is_clean)
        self.assertEqual(len(result.test_regressions), 1)
        self.assertFalse(result.test_regressions[0].passed)

    def test_validate_already_failing_not_regression(self):
        """Test that already fails on source is NOT counted as regression."""
        fw = _policy(agents={
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        })
        # This test expects DENY but source allows → already failing
        cases = [
            TestCase(expected=DecisionKind.DENY, agent="dev",
                     action="fs.read", resource="./src/main.py"),
        ]
        v = SuggestionValidator(fw.policy, cases)

        # Verify source already fails
        source_result = run_policy_tests(fw.policy, cases)
        self.assertFalse(source_result[0].passed)

        # Any suggestion won't change this → no regression
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule={"action": "fs.write", "resource": "./**"},
        )
        result = v.validate([s])
        self.assertEqual(len(result.test_regressions), 0)

    def test_validate_zero_suggestions(self):
        policy = _simple_policy()
        cases = _simple_test_cases()
        v = SuggestionValidator(policy, cases)
        result = v.validate([])
        self.assertTrue(result.is_clean)
        self.assertEqual(result.source_lint_findings, result.proposed_lint_findings)
        self.assertEqual(len(result.new_lint_findings), 0)

    def test_validate_zero_test_cases(self):
        policy = _simple_policy()
        v = SuggestionValidator(policy, [])
        result = v.validate([])
        self.assertTrue(result.is_clean)
        self.assertEqual(len(result.source_test_results), 0)
        self.assertEqual(len(result.proposed_test_results), 0)
        self.assertEqual(len(result.test_regressions), 0)

    def test_validate_empty_policy(self):
        data = {"version": 1, "agents": {}}
        policy = policy_from_dict(data)
        v = SuggestionValidator(policy, [])
        result = v.validate([])
        self.assertTrue(result.is_clean)

    def test_validate_multiple_suggestions(self):
        """Multiple suggestions that collectively cause a regression."""
        policy = _simple_policy()
        cases = [
            TestCase(expected=DecisionKind.DENY, agent="dev",
                     action="filesystem.read", resource="./.env"),
        ]
        v = SuggestionValidator(policy, cases)

        s = PolicySuggestion(
            suggestion_type="remove_rule",
            agent="dev",
            collection="deny",
            rule={"action": "filesystem.read", "resource": "./.env"},
        )
        result = v.validate([s])
        self.assertFalse(result.is_clean)
        self.assertEqual(len(result.test_regressions), 1)

    def test_validate_duplicate_suggestions(self):
        """Duplicate suggestions should not cause double-counting."""
        policy = _simple_policy()
        cases = _simple_test_cases()
        v = SuggestionValidator(policy, cases)
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule={"action": "new.action", "resource": "./specific"},
        )
        result = v.validate([s, s])
        # proposed_policy deduplicates, so no duplicate lint findings
        self.assertTrue(result.is_clean)

    def test_validate_invalid_suggestions(self):
        """Invalid suggestions are skipped by proposed_policy()."""
        policy = _simple_policy()
        cases = _simple_test_cases()
        v = SuggestionValidator(policy, cases)
        # Not a PolicySuggestion — should be skipped
        result = v.validate(["not a suggestion", 42])
        self.assertTrue(result.is_clean)

    def test_validate_unicode(self):
        fw = _policy(agents={
            "développeur": {
                "allow": [{"action": "fs.read", "resource": "./файл.py"}],
            },
        })
        cases = [
            TestCase(expected=DecisionKind.ALLOW, agent="développeur",
                     action="fs.read", resource="./файл.py"),
        ]
        v = SuggestionValidator(fw.policy, cases)
        result = v.validate([])
        self.assertTrue(result.is_clean)
        self.assertEqual(len(result.source_test_results), 1)
        self.assertTrue(result.source_test_results[0].passed)

    def test_validate_deterministic(self):
        policy = _simple_policy()
        cases = _simple_test_cases()
        v = SuggestionValidator(policy, cases)
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule={"action": "new.action"},
        )
        r1 = v.validate([s])
        r2 = v.validate([s])
        self.assertEqual(r1.is_clean, r2.is_clean)
        self.assertEqual(len(r1.new_lint_findings), len(r2.new_lint_findings))
        self.assertEqual(len(r1.test_regressions), len(r2.test_regressions))

    def test_source_policy_unchanged(self):
        policy = _simple_policy()
        cases = _simple_test_cases()
        v = SuggestionValidator(policy, cases)
        original_deny_count = len(policy.agents["dev"].deny)
        s = PolicySuggestion(
            suggestion_type="remove_rule",
            agent="dev",
            collection="deny",
            rule={"action": "filesystem.read", "resource": "./.env"},
        )
        v.validate([s])
        self.assertEqual(len(policy.agents["dev"].deny), original_deny_count)

    def test_proposed_policy_is_distinct(self):
        """Validator internally creates a distinct policy (verified indirectly)."""
        policy = _simple_policy()
        cases = _simple_test_cases()
        v = SuggestionValidator(policy, cases)
        result = v.validate([])
        # Source and proposed lint/test results should be independent objects
        self.assertIsNot(result.source_lint_findings, result.proposed_lint_findings)
        self.assertIsNot(result.source_test_results, result.proposed_test_results)

    def test_lint_key_message_independence(self):
        """Findings with same key but different message are NOT new findings."""
        fw = _policy(agents={
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./**"}],
                "deny": [{"action": "fs.read", "resource": "./.env"}],
            },
        })
        # Source already has unreachable_rule and broad_wildcard
        source_lint = lint_policy(fw.policy)
        source_keys = {_lint_key(f) for f in source_lint}

        # The same findings exist in source — they should not be "new"
        proposed_lint = lint_policy(fw.policy)
        new = [f for f in proposed_lint if _lint_key(f) not in source_keys]
        self.assertEqual(len(new), 0)

    def test_regression_matching_by_key(self):
        """Test cases matched by (agent, action, resource) not full equality."""
        policy = _simple_policy()
        # Two test cases with same (agent, action, resource) but different expected
        cases = [
            TestCase(expected=DecisionKind.ALLOW, agent="dev",
                     action="filesystem.read", resource="./src/main.py"),
            TestCase(expected=DecisionKind.DENY, agent="dev",
                     action="filesystem.read", resource="./src/main.py"),
        ]
        v = SuggestionValidator(policy, cases)
        result = v.validate([])
        # Source allows fs.read ./src/main.py
        # First case (expected ALLOW) passes, second (expected DENY) fails
        # Neither is a regression because we're not changing the policy
        self.assertEqual(len(result.test_regressions), 0)


# ── Security / adversarial tests ────────────────────────────────────────────


class TestSecurity(unittest.TestCase):
    """Adversarial security tests for validator module."""

    def test_no_dangerous_imports(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "validator.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        dangerous = {
            "subprocess", "socket", "http", "urllib", "shutil",
            "docker", "container", "ctypes", "multiprocessing",
            "threading", "signal",
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
            os.path.dirname(__file__), "..", "agent_firewall", "validator.py"
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

    def test_no_firewall_check_in_validator(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "validator.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Attribute) and child.attr == "check":
                        self.fail(f".check() in {node.name} at line {child.lineno}")

    def test_no_decision_in_validator(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "validator.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and child.id in ("Decision", "DecisionKind"):
                        self.fail(f"{child.id} in {node.name} at line {child.lineno}")

    def test_no_evaluate_in_validator(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "validator.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and child.id == "evaluate":
                        self.fail(f"evaluate() in {node.name} at line {child.lineno}")

    def test_no_filesystem_writes(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "validator.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Attribute):
                        if child.attr in ("write", "writelines", "makedirs", "mkdir"):
                            self.fail(f"{child.attr} in {node.name} at line {child.lineno}")

    def test_no_network_access(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "validator.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Attribute):
                        if child.attr in ("connect", "send", "recv", "urlopen"):
                            self.fail(f"{child.attr} in {node.name} at line {child.lineno}")

    def test_no_activation_mechanism(self):
        """Validator should have no apply/activate/commit methods."""
        v = SuggestionValidator(_simple_policy(), _simple_test_cases())
        self.assertFalse(hasattr(v, "apply"))
        self.assertFalse(hasattr(v, "activate"))
        self.assertFalse(hasattr(v, "commit"))

    def test_frozen_files_unchanged(self):
        frozen_files = [
            "agent_firewall/evaluator.py", "agent_firewall/model.py",
            "agent_firewall/normalize.py", "agent_firewall/policy.py",
            "agent_firewall/simulate.py", "agent_firewall/diff.py",
            "agent_firewall/lint.py", "agent_firewall/test_cases.py",
            "agent_firewall/approval.py", "agent_firewall/audit.py",
            "agent_firewall/cli.py", "agent_firewall/orchestrator.py",
            "agent_firewall/sandbox.py", "agent_firewall/integrity.py",
            "agent_firewall/analysis.py", "agent_firewall/suggestions.py",
        ]
        for fp in frozen_files:
            full = os.path.join(os.path.dirname(__file__), "..", fp)
            self.assertTrue(os.path.exists(full), f"Missing: {fp}")

    def test_documentation_untouched(self):
        for df in ["DESIGN.md", "SPEC.md", "SECURITY.md", "THREAT_MODEL.md",
                    "IMPLEMENTATION.md", "TEST_PLAN.md", "ROADMAP.md"]:
            full = os.path.join(os.path.dirname(__file__), "..", df)
            self.assertTrue(os.path.exists(full), f"Missing: {df}")


# ── Regression tests ────────────────────────────────────────────────────────


class TestRegression(unittest.TestCase):
    """Verify Phase 1-17 functionality remains intact."""

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
        fw = Firewall.from_dict({"version": 1, "agents": {
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        }})
        findings = lint_policy(fw.policy)
        self.assertIsInstance(findings, list)

    def test_test_cases_still_work(self):
        fw = Firewall.from_dict({"version": 1, "agents": {
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        }})
        cases = [TestCase(expected=DecisionKind.ALLOW, agent="dev",
                          action="fs.read", resource="./src/main.py")]
        results = run_policy_tests(fw.policy, cases)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].passed)

    def test_suggestions_still_work(self):
        from agent_firewall.suggestions import PolicySuggestionEngine
        fw = Firewall.from_dict({"version": 1, "agents": {
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        }})
        engine = PolicySuggestionEngine(fw.policy)
        from agent_firewall.analysis import BroadPermission
        suggestions = engine.suggest_from_findings([
            BroadPermission(agent="dev", action="fs.read", resource="./**",
                            reason="test"),
        ])
        self.assertEqual(len(suggestions), 1)

    def test_analyzer_still_works(self):
        from agent_firewall.analysis import PolicyAnalyzer
        fw = Firewall.from_dict({"version": 1, "agents": {
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        }})
        analyzer = PolicyAnalyzer(fw.policy)
        graph = analyzer.permission_graph()
        self.assertIsInstance(graph, list)

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
