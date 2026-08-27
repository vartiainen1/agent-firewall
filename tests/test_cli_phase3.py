"""CLI integration tests for Phase 3 commands (lint, test, capabilities).

Verifies:

    lint — clean policy, dirty policy, invalid policy, JSON output, exit codes
    test — passing tests, failing tests, invalid test file, JSON output, exit codes
    capabilities — text output, JSON output, --agent filter, unknown agent, exit codes
    all error paths fail closed
    no authorization logic in CLI
    no side effects
"""

import json
import os
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall.cli import (
    EXIT_ALLOW,
    EXIT_DENY,
    EXIT_INVALID_POLICY,
    EXIT_INVALID_REQUEST,
    main,
)


def _write_policy(data: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


def _write_text(text: str, suffix: str = ".txt") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def _run(args: list[str]) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
        code = main(args)
    return code, stdout.getvalue().strip(), stderr.getvalue().strip()


# ═════════════════════════════════════════════════════════════════════════════
#  LINT command
# ═════════════════════════════════════════════════════════════════════════════

class LintCleanPolicyTests(unittest.TestCase):
    """Lint a clean policy → exit 0, no findings."""

    def test_clean_policy(self):
        path = _write_policy({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [{"action": "fs.read", "resource": "./src/*.py"}],
                    "deny": [{"action": "fs.write", "resource": "./.env"}],
                },
            },
        })
        code, out, err = _run(["lint", "--policy", path])
        os.unlink(path)
        self.assertEqual(code, EXIT_ALLOW)
        self.assertEqual(out, "")


class LintDirtyPolicyTests(unittest.TestCase):
    """Lint a policy with findings → exit 1."""

    def test_duplicate_rule(self):
        path = _write_policy({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [
                        {"action": "fs.read", "resource": "./x"},
                        {"action": "fs.read", "resource": "./x"},
                    ],
                },
            },
        })
        code, out, err = _run(["lint", "--policy", path])
        os.unlink(path)
        self.assertEqual(code, EXIT_DENY)
        self.assertIn("duplicate_rule", out)

    def test_conflicting_rule(self):
        path = _write_policy({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [{"action": "fs.read", "resource": "./src"}],
                    "deny": [{"action": "fs.read", "resource": "./src"}],
                },
            },
        })
        code, out, err = _run(["lint", "--policy", path])
        os.unlink(path)
        self.assertEqual(code, EXIT_DENY)
        self.assertIn("conflicting_rule", out)


class LintInvalidPolicyTests(unittest.TestCase):
    """Lint with invalid policy → exit 4."""

    def test_missing_file(self):
        code, out, err = _run(["lint", "--policy", "/nonexistent.json"])
        self.assertEqual(code, EXIT_INVALID_POLICY)
        self.assertIn("error", err.lower())

    def test_invalid_json(self):
        path = _write_text("{bad json", ".json")
        code, out, err = _run(["lint", "--policy", path])
        os.unlink(path)
        self.assertEqual(code, EXIT_INVALID_POLICY)


class LintJSONOutputTests(unittest.TestCase):
    """Lint --json outputs valid JSON."""

    def test_json_clean(self):
        path = _write_policy({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.read", "resource": "./src/*.py"}]}},
        })
        code, out, err = _run(["lint", "--policy", path, "--json"])
        os.unlink(path)
        data = json.loads(out)
        self.assertEqual(data, [])

    def test_json_with_findings(self):
        path = _write_policy({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [
                        {"action": "fs.read", "resource": "./x"},
                        {"action": "fs.read", "resource": "./x"},
                    ],
                },
            },
        })
        code, out, err = _run(["lint", "--policy", path, "--json"])
        os.unlink(path)
        data = json.loads(out)
        self.assertIsInstance(data, list)
        self.assertTrue(len(data) > 0)
        self.assertIn("severity", data[0])
        self.assertIn("code", data[0])
        self.assertIn("message", data[0])


# ═════════════════════════════════════════════════════════════════════════════
#  TEST command
# ═════════════════════════════════════════════════════════════════════════════

class TestPassingTests(unittest.TestCase):
    """All test cases pass → exit 0."""

    def test_all_pass(self):
        policy_path = _write_policy({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [{"action": "fs.read", "resource": "./src/**"}],
                    "deny": [{"action": "fs.read", "resource": "./.env"}],
                },
            },
        })
        test_path = _write_text(
            "PASS dev fs.read ./src/main.py\n"
            "FAIL dev fs.read ./.env\n"
        )
        code, out, err = _run(["test", "--policy", policy_path, test_path])
        os.unlink(policy_path)
        os.unlink(test_path)
        self.assertEqual(code, EXIT_ALLOW)
        self.assertIn("PASS", out)
        self.assertNotIn("FAIL", out.split("\n")[0])  # first line is PASS


class TestFailingTests(unittest.TestCase):
    """At least one test case fails → exit 1."""

    def test_one_fail(self):
        policy_path = _write_policy({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [{"action": "fs.read", "resource": "./src"}],
                },
            },
        })
        # Expect DENY but policy allows this
        test_path = _write_text("FAIL dev fs.read ./src\n")
        code, out, err = _run(["test", "--policy", policy_path, test_path])
        os.unlink(policy_path)
        os.unlink(test_path)
        self.assertEqual(code, EXIT_DENY)
        self.assertIn("FAIL", out)
        self.assertIn("expected DENY, got ALLOW", out)


class TestInvalidTestFileTests(unittest.TestCase):
    """Invalid test file → exit 4."""

    def test_missing_test_file(self):
        policy_path = _write_policy({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "x"}]}},
        })
        code, out, err = _run([
            "test", "--policy", policy_path, "/nonexistent.txt",
        ])
        os.unlink(policy_path)
        self.assertEqual(code, EXIT_INVALID_POLICY)

    def test_malformed_test_line(self):
        policy_path = _write_policy({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "x"}]}},
        })
        test_path = _write_text("BADLINE\n")
        code, out, err = _run(["test", "--policy", policy_path, test_path])
        os.unlink(policy_path)
        os.unlink(test_path)
        self.assertEqual(code, EXIT_INVALID_POLICY)


class TestEmptyTestFile(unittest.TestCase):
    """Empty test file → warning, exit 0."""

    def test_empty_file(self):
        policy_path = _write_policy({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "x"}]}},
        })
        test_path = _write_text("# just a comment\n")
        code, out, err = _run(["test", "--policy", policy_path, test_path])
        os.unlink(policy_path)
        os.unlink(test_path)
        self.assertEqual(code, EXIT_ALLOW)


class TestJSONOutputTests(unittest.TestCase):
    """Test --json outputs valid JSON."""

    def test_json_passing(self):
        policy_path = _write_policy({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "x"}]}},
        })
        test_path = _write_text("PASS dev x\n")
        code, out, err = _run(["test", "--policy", policy_path, test_path, "--json"])
        os.unlink(policy_path)
        os.unlink(test_path)
        data = json.loads(out)
        self.assertEqual(len(data), 1)
        self.assertTrue(data[0]["passed"])
        self.assertEqual(data[0]["expected"], "ALLOW")
        self.assertEqual(data[0]["actual"], "ALLOW")


class TestInvalidPolicyForTest(unittest.TestCase):
    """Invalid policy for test command → exit 4."""

    def test_missing_policy(self):
        test_path = _write_text("PASS dev x\n")
        code, out, err = _run([
            "test", "--policy", "/nonexistent.json", test_path,
        ])
        os.unlink(test_path)
        self.assertEqual(code, EXIT_INVALID_POLICY)


# ═════════════════════════════════════════════════════════════════════════════
#  CAPABILITIES command
# ═════════════════════════════════════════════════════════════════════════════

class CapabilitiesTextTests(unittest.TestCase):
    """Capabilities text output."""

    def test_all_agents(self):
        path = _write_policy({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [{"action": "fs.read", "resource": "./src/**"}],
                },
                "ops": {
                    "approve": [{"action": "deploy"}],
                },
            },
        })
        code, out, err = _run(["capabilities", "--policy", path])
        os.unlink(path)
        self.assertEqual(code, EXIT_ALLOW)
        self.assertIn("Agent: dev", out)
        self.assertIn("Agent: ops", out)
        self.assertIn("allow fs.read ./src/**", out)
        self.assertIn("approve deploy", out)

    def test_empty_agent(self):
        path = _write_policy({
            "version": 1,
            "agents": {"ghost": {}},
        })
        code, out, err = _run(["capabilities", "--policy", path])
        os.unlink(path)
        self.assertEqual(code, EXIT_ALLOW)
        self.assertIn("(no rules)", out)


class CapabilitiesAgentFilterTests(unittest.TestCase):
    """Capabilities --agent filters to one agent."""

    def test_filter_known_agent(self):
        path = _write_policy({
            "version": 1,
            "agents": {
                "dev": {"allow": [{"action": "fs.read"}]},
                "ops": {"approve": [{"action": "deploy"}]},
            },
        })
        code, out, err = _run(["capabilities", "--policy", path, "--agent", "dev"])
        os.unlink(path)
        self.assertEqual(code, EXIT_ALLOW)
        self.assertIn("Agent: dev", out)
        self.assertNotIn("Agent: ops", out)

    def test_filter_unknown_agent(self):
        path = _write_policy({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "x"}]}},
        })
        code, out, err = _run(["capabilities", "--policy", path, "--agent", "ghost"])
        os.unlink(path)
        self.assertEqual(code, EXIT_INVALID_REQUEST)
        self.assertIn("error", err.lower())


class CapabilitiesJSONOutputTests(unittest.TestCase):
    """Capabilities --json outputs valid JSON."""

    def test_json_output(self):
        path = _write_policy({
            "version": 1,
            "agents": {
                "dev": {"allow": [{"action": "fs.read", "resource": "./src"}]},
            },
        })
        code, out, err = _run(["capabilities", "--policy", path, "--json"])
        os.unlink(path)
        data = json.loads(out)
        self.assertEqual(data["version"], 1)
        self.assertIn("dev", data["agents"])
        self.assertEqual(data["agents"]["dev"]["allow"][0]["action"], "fs.read")


class CapabilitiesInvalidPolicyTests(unittest.TestCase):
    """Capabilities with invalid policy → exit 4."""

    def test_missing_policy(self):
        code, out, err = _run(["capabilities", "--policy", "/nonexistent.json"])
        self.assertEqual(code, EXIT_INVALID_POLICY)


# ═════════════════════════════════════════════════════════════════════════════
#  Phase 1/2 regression: existing commands still work
# ═════════════════════════════════════════════════════════════════════════════

class Phase12RegressionTests(unittest.TestCase):
    """Phase 1/2 commands are unaffected by Phase 3 additions."""

    def test_check_still_works(self):
        path = _write_policy({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.read"}]}},
        })
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read",
        ])
        os.unlink(path)
        self.assertEqual(code, EXIT_ALLOW)
        self.assertEqual(out, "ALLOW")

    def test_explain_still_works(self):
        path = _write_policy({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.read"}]}},
        })
        code, out, err = _run([
            "explain", "--policy", path,
            "--agent", "dev", "--action", "fs.read",
        ])
        os.unlink(path)
        self.assertEqual(code, EXIT_ALLOW)
        self.assertIn("Decision: ALLOW", out)


if __name__ == "__main__":
    unittest.main()
