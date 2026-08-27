"""Tests for the agent-firewall CLI (Phase 2).

Covers every Phase 2 behavioral contract:

    * check command — text and JSON output, correct exit codes
    * explain command — text and JSON output, correct exit codes
    * unknown agent / unknown action / unknown resource → DENY (exit 1)
    * empty policy → default deny
    * malformed / missing / unsupported policy → exit 4 (fail closed)
    * missing agent / action / absolute resource → exit 3 (fail closed)
    * no authorization logic in cli.py (separation of concerns)
    * JSON output is valid and contains required fields

Exit codes (SPEC 22):
    0 = ALLOW
    1 = DENY
    2 = APPROVE
    3 = INVALID_REQUEST
    4 = INVALID_POLICY
    5 = INTERNAL_ERROR
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
    EXIT_APPROVE,
    EXIT_DENY,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_POLICY,
    EXIT_INVALID_REQUEST,
    _build_parser,
    _decision_to_dict,
    main,
)
from agent_firewall import (
    DecisionKind,
    Firewall,
    InvalidPolicyError,
    InvalidRequestError,
    Request,
    Rule,
)
from agent_firewall.model import Decision
from agent_firewall.evaluator import evaluate
from agent_firewall.policy import policy_from_dict


# ── Helpers ───────────────────────────────────────────────────────────────────

_POLICIES_DIR = os.path.join(os.path.dirname(__file__), "..", "policies")


def _write_policy(data: dict) -> str:
    """Write *data* as a temporary JSON policy file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


def _run(args: list[str]) -> tuple[int, str, str]:
    """Run ``main(args)`` and capture stdout/stderr.  Returns (exit, stdout, stderr)."""
    stdout = StringIO()
    stderr = StringIO()
    with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
        code = main(args)
    return code, stdout.getvalue().strip(), stderr.getvalue().strip()


# ── Policy fixtures ───────────────────────────────────────────────────────────

_POLICY_CHECK = {
    "version": 1,
    "agents": {
        "dev": {
            "allow": [
                {"action": "fs.read", "resource": "./src/**"},
            ],
            "deny": [
                {"action": "fs.read", "resource": "./.env"},
            ],
        },
        "ops": {
            "approve": [
                {"action": "deploy"},
            ],
        },
    },
}


class _CLIHelperMixin:
    """Shared helpers for CLI test classes."""

    def _policy_file(self, data=None) -> str:
        return _write_policy(data or _POLICY_CHECK)


# ═════════════════════════════════════════════════════════════════════════════
#  CHECK command — exit codes and output
# ═════════════════════════════════════════════════════════════════════════════

class TestCheckAllow(_CLIHelperMixin, unittest.TestCase):
    """Check command: ALLOW → exit 0, prints 'ALLOW'."""

    def test_exit_code_allow(self):
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read", "--resource", "./src/main.py",
        ])
        self.assertEqual(code, EXIT_ALLOW)
        self.assertEqual(out, "ALLOW")

    def test_json_allow(self):
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read", "--resource", "./src/main.py",
            "--json",
        ])
        self.assertEqual(code, EXIT_ALLOW)
        data = json.loads(out)
        self.assertEqual(data["decision"], "ALLOW")
        self.assertEqual(data["agent"], "dev")
        self.assertEqual(data["action"], "fs.read")
        self.assertEqual(data["resource"], "./src/main.py")
        self.assertIn("rule", data)
        self.assertIn("policy_version", data)


class TestCheckDeny(_CLIHelperMixin, unittest.TestCase):
    """Check command: DENY → exit 1."""

    def test_exit_code_deny_explicit(self):
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read", "--resource", "./.env",
        ])
        self.assertEqual(code, EXIT_DENY)
        self.assertEqual(out, "DENY")

    def test_exit_code_deny_default(self):
        """Unknown resource without matching rule → default DENY."""
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read", "--resource", "./other/x",
        ])
        self.assertEqual(code, EXIT_DENY)

    def test_unknown_agent(self):
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "ghost", "--action", "fs.read",
        ])
        self.assertEqual(code, EXIT_DENY)
        self.assertEqual(out, "DENY")


class TestCheckApprove(_CLIHelperMixin, unittest.TestCase):
    """Check command: APPROVE → exit 2."""

    def test_exit_code_approve(self):
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "ops", "--action", "deploy",
        ])
        self.assertEqual(code, EXIT_APPROVE)
        self.assertEqual(out, "APPROVE")

    def test_json_approve(self):
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "ops", "--action", "deploy", "--json",
        ])
        self.assertEqual(code, EXIT_APPROVE)
        data = json.loads(out)
        self.assertEqual(data["decision"], "APPROVE")


class TestCheckNoResource(_CLIHelperMixin, unittest.TestCase):
    """Check command: resource is optional (SPEC 5/10)."""

    def test_check_without_resource(self):
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "ops", "--action", "deploy",
        ])
        self.assertEqual(code, EXIT_APPROVE)


# ═════════════════════════════════════════════════════════════════════════════
#  EXPLAIN command — exit codes and output
# ═════════════════════════════════════════════════════════════════════════════

class TestExplainAllow(_CLIHelperMixin, unittest.TestCase):
    """Explain command: prints full explanation, same exit code."""

    def test_exit_code_allow(self):
        path = self._policy_file()
        code, out, err = _run([
            "explain", "--policy", path,
            "--agent", "dev", "--action", "fs.read", "--resource", "./src/main.py",
        ])
        self.assertEqual(code, EXIT_ALLOW)
        self.assertIn("Decision: ALLOW", out)
        self.assertIn("Agent:", out)
        self.assertIn("dev", out)
        self.assertIn("Action:", out)
        self.assertIn("fs.read", out)
        self.assertIn("Resource:", out)
        self.assertIn("./src/main.py", out)
        self.assertIn("Matched rule:", out)
        self.assertIn("Reason:", out)

    def test_json_explain_allow(self):
        path = self._policy_file()
        code, out, err = _run([
            "explain", "--policy", path,
            "--agent", "dev", "--action", "fs.read", "--resource", "./src/main.py",
            "--json",
        ])
        self.assertEqual(code, EXIT_ALLOW)
        data = json.loads(out)
        self.assertEqual(data["decision"], "ALLOW")


class TestExplainDeny(_CLIHelperMixin, unittest.TestCase):
    """Explain command: DENY shows reason."""

    def test_exit_code_deny(self):
        path = self._policy_file()
        code, out, err = _run([
            "explain", "--policy", path,
            "--agent", "dev", "--action", "fs.read", "--resource", "./.env",
        ])
        self.assertEqual(code, EXIT_DENY)
        self.assertIn("Decision: DENY", out)
        self.assertIn("Reason:", out)
        self.assertIn("denied", out)


class TestExplainApprove(_CLIHelperMixin, unittest.TestCase):
    """Explain command: APPROVE shows matched rule."""

    def test_exit_code_approve(self):
        path = self._policy_file()
        code, out, err = _run([
            "explain", "--policy", path,
            "--agent", "ops", "--action", "deploy",
        ])
        self.assertEqual(code, EXIT_APPROVE)
        self.assertIn("Decision: APPROVE", out)
        self.assertIn("Matched rule:", out)
        self.assertIn("approval required", out)


# ═════════════════════════════════════════════════════════════════════════════
#  Error handling — fail closed
# ═════════════════════════════════════════════════════════════════════════════

class TestCheckMissingPolicy(_CLIHelperMixin, unittest.TestCase):
    """Non-existent policy file → exit 4, not exit 0."""

    def test_missing_policy_file(self):
        code, out, err = _run([
            "check", "--policy", "/nonexistent/path/policy.json",
            "--agent", "dev", "--action", "fs.read",
        ])
        self.assertEqual(code, EXIT_INVALID_POLICY)
        self.assertNotEqual(code, EXIT_ALLOW)
        self.assertIn("error", err.lower())


class TestCheckInvalidPolicyJSON(_CLIHelperMixin, unittest.TestCase):
    """Malformed JSON in policy → exit 4."""

    def test_invalid_json(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            fh.write("{broken json!")
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read",
        ])
        os.unlink(path)
        self.assertEqual(code, EXIT_INVALID_POLICY)
        self.assertIn("error", err.lower())


class TestCheckMalformedPolicyStructure(_CLIHelperMixin, unittest.TestCase):
    """Missing required fields → exit 4."""

    def test_missing_version(self):
        path = _write_policy({"agents": {"dev": {"allow": []}}})
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read",
        ])
        os.unlink(path)
        self.assertEqual(code, EXIT_INVALID_POLICY)


class TestCheckUnsupportedVersion(_CLIHelperMixin, unittest.TestCase):
    """Unsupported policy version → exit 4."""

    def test_version_99(self):
        path = _write_policy({"version": 99, "agents": {}})
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read",
        ])
        os.unlink(path)
        self.assertEqual(code, EXIT_INVALID_POLICY)


class TestCheckInvalidRequest(_CLIHelperMixin, unittest.TestCase):
    """Malformed request (absolute path) → exit 3, fail closed."""

    def test_absolute_resource(self):
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "filesystem.read", "--resource", "/etc/passwd",
        ])
        self.assertEqual(code, EXIT_INVALID_REQUEST)
        self.assertNotEqual(code, EXIT_ALLOW)
        self.assertIn("error", err.lower())


class TestExplainInvalidRequest(_CLIHelperMixin, unittest.TestCase):
    """Explain with invalid request → same exit code as check."""

    def test_absolute_resource(self):
        path = self._policy_file()
        code, out, err = _run([
            "explain", "--policy", path,
            "--agent", "dev", "--action", "filesystem.read", "--resource", "/etc/passwd",
        ])
        self.assertEqual(code, EXIT_INVALID_REQUEST)
        self.assertNotEqual(code, EXIT_ALLOW)


class TestNoSubcommand(_CLIHelperMixin, unittest.TestCase):
    """No command → exit 3 (INVALID_REQUEST, fail closed)."""

    def test_no_command(self):
        code, out, err = _run([])
        self.assertEqual(code, EXIT_INVALID_REQUEST)


# ═════════════════════════════════════════════════════════════════════════════
#  JSON output structural contract
# ═════════════════════════════════════════════════════════════════════════════

class TestJSONOutputStructure(_CLIHelperMixin, unittest.TestCase):
    """JSON output is valid, parseable, and contains the required fields."""

    def test_json_valid_parseable_allow(self):
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read", "--resource", "./src/main.py",
            "--json",
        ])
        data = json.loads(out)
        self.assertIn("decision", data)
        self.assertIn("agent", data)
        self.assertIn("action", data)
        self.assertEqual(data["decision"], "ALLOW")

    def test_json_valid_parseable_deny(self):
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read", "--resource", "./.env",
            "--json",
        ])
        data = json.loads(out)
        self.assertEqual(data["decision"], "DENY")

    def test_json_decision_values_only(self):
        """The 'decision' field is one of the three allowed values (SPEC 24)."""
        for expected in ("ALLOW", "DENY", "APPROVE"):
            if expected == "ALLOW":
                args = ["--agent", "dev", "--action", "fs.read", "--resource", "./src/main.py"]
            elif expected == "DENY":
                args = ["--agent", "dev", "--action", "fs.read", "--resource", "./.env"]
            elif expected == "APPROVE":
                args = ["--agent", "ops", "--action", "deploy"]
            else:
                continue
            path = self._policy_file()
            code, out, err = _run(
                ["check", "--policy", path, "--json"] + args
            )
            data = json.loads(out)
            self.assertIn(data["decision"], ("ALLOW", "DENY", "APPROVE"),
                          f"Unexpected decision: {data['decision']}")


# ═════════════════════════════════════════════════════════════════════════════
#  Security: no authorization logic in CLI
# ═════════════════════════════════════════════════════════════════════════════

class TestCLISeparationOfConcerns(unittest.TestCase):
    """The CLI module must not contain authorization logic.

    All decisions must come from Firewall.check() / evaluate().
    """

    def test_cli_imports_core_api(self):
        """Verify cli.py imports the core API — it delegates, not decides."""
        import inspect
        import agent_firewall.cli as cli_mod
        source = inspect.getsource(cli_mod)
        self.assertIn("firewall.check(request)", source)
        self.assertIn("Firewall.from_file", source)

    def test_cli_has_no_evaluate_direct_call(self):
        """cli.py must not call evaluate() directly — it goes through Firewall."""
        import inspect
        import agent_firewall.cli as cli_mod
        source = inspect.getsource(cli_mod)
        # The only call to evaluate must be inside Firewall.check() in __init__.py,
        # not in cli.py itself.
        self.assertNotIn("evaluate(request", source)


# ═════════════════════════════════════════════════════════════════════════════
#  Edge cases and adversarial checks
# ═════════════════════════════════════════════════════════════════════════════

class TestCLIEdgeCases(_CLIHelperMixin, unittest.TestCase):
    """Edge cases through the CLI interface."""

    def test_root_escape_resource_through_cli(self):
        """Root-escape resource → exit 3, never ALLOW."""
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "filesystem.read",
            "--resource", "../../etc/passwd",
        ])
        self.assertEqual(code, EXIT_INVALID_REQUEST)
        self.assertNotEqual(code, EXIT_ALLOW)

    def test_empty_policy_default_deny(self):
        """Empty policy → default DENY through CLI."""
        path = _write_policy({"version": 1, "agents": {}})
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "unknown", "--action", "any",
        ])
        os.unlink(path)
        self.assertEqual(code, EXIT_DENY)
        self.assertEqual(out, "DENY")

    def test_unknown_action_through_cli(self):
        """Unknown action → DENY through CLI."""
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "totally.unknown",
        ])
        self.assertEqual(code, EXIT_DENY)

    def test_resource_is_optional(self):
        """No --resource flag → still works if action doesn't need one."""
        path = self._policy_file()
        code, out, err = _run([
            "check", "--policy", path,
            "--agent", "ops", "--action", "deploy",
        ])
        self.assertEqual(code, EXIT_APPROVE)

    def test_wildcard_policy_through_cli(self):
        """Wildcard policy works correctly through CLI."""
        path = _write_policy({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [{"action": "fs.read", "resource": "./**"}],
                    "deny": [{"action": "fs.read", "resource": "./secret"}],
                },
            },
        })
        code_allow, out_allow, _ = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read",
            "--resource", "./src/main.py",
        ])
        self.assertEqual(code_allow, EXIT_ALLOW)

        code_deny, out_deny, _ = _run([
            "check", "--policy", path,
            "--agent", "dev", "--action", "fs.read",
            "--resource", "./secret",
        ])
        self.assertEqual(code_deny, EXIT_DENY)
        os.unlink(path)


# ═════════════════════════════════════════════════════════════════════════════
#  Existing Phase 1 tests remain passing (import check)
# ═════════════════════════════════════════════════════════════════════════════

class TestPhase1Unchanged(unittest.TestCase):
    """Phase 1 core API is unchanged and accessible."""

    def test_import_core(self):
        from agent_firewall import Firewall, Request, Decision, DecisionKind
        self.assertIsNotNone(Firewall)
        self.assertIsNotNone(Request)
        self.assertIsNotNone(Decision)
        self.assertIsNotNone(DecisionKind)

    def test_phase1_decision_kind_values(self):
        self.assertEqual(DecisionKind.ALLOW.value, "ALLOW")
        self.assertEqual(DecisionKind.DENY.value, "DENY")
        self.assertEqual(DecisionKind.APPROVE.value, "APPROVE")

    def test_core_evaluate_still_works(self):
        """Direct evaluate() call through core API still works."""
        from agent_firewall import Request, evaluate
        policy = policy_from_dict({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "read"}]}},
        })
        d = evaluate(Request("dev", "read"), policy)
        self.assertEqual(d.kind, DecisionKind.ALLOW)


if __name__ == "__main__":
    unittest.main()
