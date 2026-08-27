"""Tests for policy test-case evaluation (Phase 3, DESIGN 40).

Verifies:

    parsing — PASS/FAIL/APPROVE verbs, blank lines, comments
    evaluation — PASS → ALLOW, FAIL → DENY, APPROVE → APPROVE
    mismatched expected vs actual → test failure
    malformed test cases → error
    default-deny cases through policy tests
    precedence cases through policy tests
    invalid requests → treated as DENY
    deterministic results
    no side effects
"""

import os
import tempfile
import unittest

from agent_firewall.test_cases import (
    TestCase,
    TestCaseResult,
    parse_test_file,
    parse_test_file_from_path,
    run_policy_tests,
)
from agent_firewall.model import DecisionKind
from agent_firewall.policy import policy_from_dict


def _policy(agents: dict):
    return policy_from_dict({"version": 1, "agents": agents})


# ── Parsing tests ─────────────────────────────────────────────────────────────

class ParseTestFileTests(unittest.TestCase):
    """Verify test-file parsing."""

    def test_parse_pass(self):
        cases = parse_test_file("PASS dev fs.read ./src\n")
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].expected, DecisionKind.ALLOW)
        self.assertEqual(cases[0].agent, "dev")
        self.assertEqual(cases[0].action, "fs.read")
        self.assertEqual(cases[0].resource, "./src")

    def test_parse_fail(self):
        cases = parse_test_file("FAIL dev fs.read ./secret\n")
        self.assertEqual(cases[0].expected, DecisionKind.DENY)

    def test_parse_approve(self):
        cases = parse_test_file("APPROVE ops deploy\n")
        self.assertEqual(cases[0].expected, DecisionKind.APPROVE)
        self.assertIsNone(cases[0].resource)

    def test_parse_blank_lines_ignored(self):
        cases = parse_test_file("\n\nPASS dev fs.read ./x\n\n\n")
        self.assertEqual(len(cases), 1)

    def test_parse_comments_ignored(self):
        cases = parse_test_file("# this is a comment\nPASS dev fs.read ./x\n")
        self.assertEqual(len(cases), 1)

    def test_parse_too_few_tokens(self):
        with self.assertRaises(ValueError):
            parse_test_file("PASS dev\n")

    def test_parse_unknown_verb(self):
        with self.assertRaises(ValueError):
            parse_test_file("MAYBE dev fs.read ./x\n")

    def test_parse_line_numbers(self):
        cases = parse_test_file("# comment\nPASS dev fs.read ./x\nFAIL dev fs.write ./y\n")
        self.assertEqual(cases[0].line_number, 2)
        self.assertEqual(cases[1].line_number, 3)


class ParseTestFileFromPathTests(unittest.TestCase):
    """Verify file-based parsing."""

    def test_reads_file(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("PASS dev fs.read ./x\n")
        try:
            cases = parse_test_file_from_path(path)
            self.assertEqual(len(cases), 1)
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        with self.assertRaises(Exception):
            parse_test_file_from_path("/nonexistent/path.txt")


# ── Evaluation tests ──────────────────────────────────────────────────────────

class RunPolicyTestsTests(unittest.TestCase):
    """Verify test-case evaluation against a policy."""

    def test_pass_when_allowed(self):
        p = _policy({"dev": {"allow": [{"action": "fs.read", "resource": "./src"}]}})
        cases = [TestCase(DecisionKind.ALLOW, "dev", "fs.read", "./src")]
        results = run_policy_tests(p, cases)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].passed)
        self.assertEqual(results[0].actual, DecisionKind.ALLOW)

    def test_fail_when_denied(self):
        p = _policy({"dev": {"deny": [{"action": "fs.write", "resource": "./.env"}]}})
        cases = [TestCase(DecisionKind.DENY, "dev", "fs.write", "./.env")]
        results = run_policy_tests(p, cases)
        self.assertTrue(results[0].passed)
        self.assertEqual(results[0].actual, DecisionKind.DENY)

    def test_approve_when_approved(self):
        p = _policy({"ops": {"approve": [{"action": "deploy"}]}})
        cases = [TestCase(DecisionKind.APPROVE, "ops", "deploy")]
        results = run_policy_tests(p, cases)
        self.assertTrue(results[0].passed)
        self.assertEqual(results[0].actual, DecisionKind.APPROVE)

    def test_mismatched_expected_deny_vs_actual_allow(self):
        p = _policy({"dev": {"allow": [{"action": "fs.read", "resource": "./src"}]}})
        # Expect DENY but policy says ALLOW
        cases = [TestCase(DecisionKind.DENY, "dev", "fs.read", "./src")]
        results = run_policy_tests(p, cases)
        self.assertFalse(results[0].passed)
        self.assertEqual(results[0].actual, DecisionKind.ALLOW)

    def test_mismatched_expected_allow_vs_actual_deny(self):
        p = _policy({})
        # Expect ALLOW but unknown agent → DENY
        cases = [TestCase(DecisionKind.ALLOW, "ghost", "fs.read", "./x")]
        results = run_policy_tests(p, cases)
        self.assertFalse(results[0].passed)
        self.assertEqual(results[0].actual, DecisionKind.DENY)

    def test_unknown_agent_produces_deny(self):
        p = _policy({"dev": {"allow": [{"action": "fs.read"}]}})
        cases = [TestCase(DecisionKind.DENY, "ghost", "fs.read")]
        results = run_policy_tests(p, cases)
        self.assertTrue(results[0].passed)

    def test_empty_policy_default_deny(self):
        p = _policy({})
        cases = [TestCase(DecisionKind.DENY, "any", "any.action")]
        results = run_policy_tests(p, cases)
        self.assertTrue(results[0].passed)

    def test_invalid_request_treated_as_deny(self):
        """Absolute path → InvalidRequestError → treated as DENY."""
        p = _policy({"dev": {"allow": [{"action": "filesystem.read", "resource": "./**"}]}})
        cases = [TestCase(DecisionKind.DENY, "dev", "filesystem.read", "/etc/passwd")]
        results = run_policy_tests(p, cases)
        self.assertTrue(results[0].passed)
        self.assertEqual(results[0].actual, DecisionKind.DENY)

    def test_multiple_cases(self):
        p = _policy({
            "dev": {
                "allow": [{"action": "fs.read", "resource": "./src/**"}],
                "deny": [{"action": "fs.read", "resource": "./.env"}],
            },
        })
        cases = [
            TestCase(DecisionKind.ALLOW, "dev", "fs.read", "./src/main.py"),
            TestCase(DecisionKind.DENY, "dev", "fs.read", "./.env"),
        ]
        results = run_policy_tests(p, cases)
        self.assertTrue(results[0].passed)
        self.assertTrue(results[1].passed)


class TestDeterminism(unittest.TestCase):
    """Policy test results must be deterministic."""

    def test_same_input_same_output(self):
        p = _policy({"dev": {"allow": [{"action": "fs.read", "resource": "./src"}]}})
        cases = [TestCase(DecisionKind.ALLOW, "dev", "fs.read", "./src")]
        r1 = run_policy_tests(p, cases)
        r2 = run_policy_tests(p, cases)
        self.assertEqual(r1[0].passed, r2[0].passed)
        self.assertEqual(r1[0].actual, r2[0].actual)


class TestSideEffectFreedom(unittest.TestCase):
    """Policy test evaluation must not create files or modify state."""

    def test_writes_nothing(self):
        before = set(os.listdir(os.getcwd()))
        p = _policy({"dev": {"allow": [{"action": "x"}]}})
        run_policy_tests(p, [TestCase(DecisionKind.ALLOW, "dev", "x")])
        after = set(os.listdir(os.getcwd()))
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
