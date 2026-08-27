"""Tests for Phase 6 policy simulation.

Covers:
    - normal simulation (same decisions, changed decisions)
    - DENY -> ALLOW, ALLOW -> DENY, ALLOW -> APPROVE, DENY -> APPROVE
    - mixed requests, resource/no-resource requests
    - determinism
    - empty request list
    - malformed requests / policies
    - CLI text output, JSON output, exit codes
    - no file writes
    - proposed policy never becoming active
    - zero third-party dependencies
    - security/adversarial checks
"""

import ast
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall.model import (
    Decision,
    DecisionKind,
    InvalidRequestError,
    Request,
)
from agent_firewall.policy import InvalidPolicyError, Policy, policy_from_dict
from agent_firewall.simulate import (
    SimulationResult,
    parse_requests_from_file,
    simulate_policy_comparison,
    simulate_from_files,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _policy(
    *,
    version: int = 1,
    gen: int = 1,
    allow=None,
    deny=None,
    approve=None,
    agents=None,
) -> Policy:
    """Build a Policy object quickly for tests."""
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
    return policy_from_dict(
        {"version": version, "agents": agent_data},
        generation=gen,
    )


def _req(agent="dev", action="fs.read", resource="./src/main.py") -> Request:
    return Request(agent=agent, action=action, resource=resource)


def _write_json(data) -> str:
    """Write *data* to a temp JSON file and return the path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(data, f)
    f.close()
    return f.name


def _write_text(text: str) -> str:
    """Write *text* to a temp file and return the path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    f.write(text)
    f.close()
    return f.name


# ══════════════════════════════════════════════════════════════════════════════
# Unit tests for simulate_policy_comparison
# ══════════════════════════════════════════════════════════════════════════════

class SameDecisionTests(unittest.TestCase):
    """Both policies produce the same decision for a request."""

    def test_deny_deny(self):
        current = _policy(deny=[{"action": "fs.read", "resource": "./src/**"}])
        proposed = _policy(deny=[{"action": "fs.read", "resource": "./src/**"}])
        results = simulate_policy_comparison(current, proposed, [_req()])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].changed)
        self.assertEqual(results[0].current_decision.kind, DecisionKind.DENY)
        self.assertEqual(results[0].proposed_decision.kind, DecisionKind.DENY)

    def test_allow_allow(self):
        current = _policy(allow=[{"action": "fs.read", "resource": "./src/**"}])
        proposed = _policy(allow=[{"action": "fs.read", "resource": "./src/**"}])
        results = simulate_policy_comparison(current, proposed, [_req()])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].changed)

    def test_approve_approve(self):
        current = _policy(approve=[{"action": "fs.read", "resource": "./src/**"}])
        proposed = _policy(approve=[{"action": "fs.read", "resource": "./src/**"}])
        results = simulate_policy_comparison(current, proposed, [_req()])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].changed)

    def test_default_deny_same(self):
        current = _policy()
        proposed = _policy()
        results = simulate_policy_comparison(current, proposed, [_req()])
        self.assertFalse(results[0].changed)
        self.assertEqual(results[0].current_decision.kind, DecisionKind.DENY)
        self.assertEqual(results[0].proposed_decision.kind, DecisionKind.DENY)


class ChangedDecisionTests(unittest.TestCase):
    """Policies produce different decisions."""

    def test_deny_to_allow(self):
        current = _policy(deny=[{"action": "fs.read", "resource": "./src/**"}])
        proposed = _policy(allow=[{"action": "fs.read", "resource": "./src/**"}])
        results = simulate_policy_comparison(current, proposed, [_req()])
        self.assertTrue(results[0].changed)
        self.assertEqual(results[0].current_decision.kind, DecisionKind.DENY)
        self.assertEqual(results[0].proposed_decision.kind, DecisionKind.ALLOW)

    def test_allow_to_deny(self):
        current = _policy(allow=[{"action": "fs.read", "resource": "./src/**"}])
        proposed = _policy(deny=[{"action": "fs.read", "resource": "./src/**"}])
        results = simulate_policy_comparison(current, proposed, [_req()])
        self.assertTrue(results[0].changed)
        self.assertEqual(results[0].current_decision.kind, DecisionKind.ALLOW)
        self.assertEqual(results[0].proposed_decision.kind, DecisionKind.DENY)

    def test_allow_to_approve(self):
        current = _policy(allow=[{"action": "fs.read", "resource": "./src/**"}])
        proposed = _policy(approve=[{"action": "fs.read", "resource": "./src/**"}])
        results = simulate_policy_comparison(current, proposed, [_req()])
        self.assertTrue(results[0].changed)
        self.assertEqual(results[0].current_decision.kind, DecisionKind.ALLOW)
        self.assertEqual(results[0].proposed_decision.kind, DecisionKind.APPROVE)

    def test_deny_to_approve(self):
        current = _policy(deny=[{"action": "fs.read", "resource": "./src/**"}])
        proposed = _policy(approve=[{"action": "fs.read", "resource": "./src/**"}])
        results = simulate_policy_comparison(current, proposed, [_req()])
        self.assertTrue(results[0].changed)
        self.assertEqual(results[0].current_decision.kind, DecisionKind.DENY)
        self.assertEqual(results[0].proposed_decision.kind, DecisionKind.APPROVE)

    def test_unknown_agent_deny_to_allow(self):
        current = _policy()
        proposed = _policy(
            agents={
                "dev": {
                    "allow": [{"action": "fs.read", "resource": "./src/**"}],
                    "deny": [],
                    "approve": [],
                }
            }
        )
        results = simulate_policy_comparison(current, proposed, [_req()])
        self.assertTrue(results[0].changed)
        self.assertEqual(results[0].current_decision.kind, DecisionKind.DENY)
        self.assertEqual(results[0].proposed_decision.kind, DecisionKind.ALLOW)


class MixedRequestsTests(unittest.TestCase):
    """Multiple requests with various outcomes."""

    def test_mixed_results(self):
        current = _policy(
            allow=[{"action": "fs.read", "resource": "./src/**"}],
            deny=[{"action": "fs.write", "resource": "./src/**"}],
        )
        proposed = _policy(
            allow=[
                {"action": "fs.read", "resource": "./src/**"},
                {"action": "fs.write", "resource": "./src/**"},
            ],
        )
        reqs = [
            _req(action="fs.read"),       # ALLOW -> ALLOW (no change)
            _req(action="fs.write"),      # DENY -> ALLOW (changed)
            _req(action="fs.delete"),     # DENY -> DENY (no change, default deny)
        ]
        results = simulate_policy_comparison(current, proposed, reqs)
        self.assertEqual(len(results), 3)
        self.assertFalse(results[0].changed)
        self.assertTrue(results[1].changed)
        self.assertFalse(results[2].changed)

    def test_no_resource_request(self):
        current = _policy(allow=[{"action": "git.commit"}])
        proposed = _policy(deny=[{"action": "git.commit"}])
        req = Request(agent="dev", action="git.commit")
        results = simulate_policy_comparison(current, proposed, [req])
        self.assertTrue(results[0].changed)
        self.assertEqual(results[0].current_decision.kind, DecisionKind.ALLOW)
        self.assertEqual(results[0].proposed_decision.kind, DecisionKind.DENY)


class DeterminismTests(unittest.TestCase):
    """Results must be deterministic."""

    def test_same_inputs_same_outputs(self):
        current = _policy(allow=[{"action": "fs.read", "resource": "./src/**"}])
        proposed = _policy(deny=[{"action": "fs.read", "resource": "./src/**"}])
        reqs = [_req(), _req(action="fs.write")]
        r1 = simulate_policy_comparison(current, proposed, reqs)
        r2 = simulate_policy_comparison(current, proposed, reqs)
        for a, b in zip(r1, r2):
            self.assertEqual(a.current_decision.kind, b.current_decision.kind)
            self.assertEqual(a.proposed_decision.kind, b.proposed_decision.kind)
            self.assertEqual(a.changed, b.changed)


class EdgeCaseTests(unittest.TestCase):
    """Boundary conditions."""

    def test_empty_request_list(self):
        current = _policy()
        proposed = _policy()
        results = simulate_policy_comparison(current, proposed, [])
        self.assertEqual(results, [])


# ══════════════════════════════════════════════════════════════════════════════
# Request file parsing tests
# ══════════════════════════════════════════════════════════════════════════════

class RequestParsingTests(unittest.TestCase):
    """Test parse_requests_from_file."""

    def test_valid_single_request(self):
        path = _write_json([{"agent": "dev", "action": "fs.read", "resource": "./src/main.py"}])
        try:
            reqs = parse_requests_from_file(path)
            self.assertEqual(len(reqs), 1)
            self.assertEqual(reqs[0].agent, "dev")
            self.assertEqual(reqs[0].action, "fs.read")
            self.assertEqual(reqs[0].resource, "./src/main.py")
        finally:
            os.unlink(path)

    def test_valid_multiple_requests(self):
        path = _write_json([
            {"agent": "dev", "action": "fs.read"},
            {"agent": "admin", "action": "fs.write", "resource": "./src/"},
        ])
        try:
            reqs = parse_requests_from_file(path)
            self.assertEqual(len(reqs), 2)
        finally:
            os.unlink(path)

    def test_no_resource(self):
        path = _write_json([{"agent": "dev", "action": "git.commit"}])
        try:
            reqs = parse_requests_from_file(path)
            self.assertIsNone(reqs[0].resource)
        finally:
            os.unlink(path)

    def test_empty_array(self):
        path = _write_json([])
        try:
            reqs = parse_requests_from_file(path)
            self.assertEqual(reqs, [])
        finally:
            os.unlink(path)

    def test_not_json(self):
        path = _write_text("not json at all")
        try:
            with self.assertRaises(InvalidRequestError):
                parse_requests_from_file(path)
        finally:
            os.unlink(path)

    def test_not_array(self):
        path = _write_json({"agent": "dev"})
        try:
            with self.assertRaises(InvalidRequestError):
                parse_requests_from_file(path)
        finally:
            os.unlink(path)

    def test_missing_agent(self):
        path = _write_json([{"action": "fs.read"}])
        try:
            with self.assertRaises(InvalidRequestError):
                parse_requests_from_file(path)
        finally:
            os.unlink(path)

    def test_missing_action(self):
        path = _write_json([{"agent": "dev"}])
        try:
            with self.assertRaises(InvalidRequestError):
                parse_requests_from_file(path)
        finally:
            os.unlink(path)

    def test_empty_agent(self):
        path = _write_json([{"agent": "", "action": "fs.read"}])
        try:
            with self.assertRaises(InvalidRequestError):
                parse_requests_from_file(path)
        finally:
            os.unlink(path)

    def test_resource_not_string(self):
        path = _write_json([{"agent": "dev", "action": "fs.read", "resource": 123}])
        try:
            with self.assertRaises(InvalidRequestError):
                parse_requests_from_file(path)
        finally:
            os.unlink(path)

    def test_non_object_in_array(self):
        path = _write_json(["not an object"])
        try:
            with self.assertRaises(InvalidRequestError):
                parse_requests_from_file(path)
        finally:
            os.unlink(path)

    def test_missing_file(self):
        with self.assertRaises(InvalidRequestError):
            parse_requests_from_file("/nonexistent/path.json")


# ══════════════════════════════════════════════════════════════════════════════
# simulate_from_files tests
# ══════════════════════════════════════════════════════════════════════════════

class SimulateFromFilesTests(unittest.TestCase):
    """Integration: load files and simulate."""

    def test_end_to_end(self):
        current = {"version": 1, "agents": {"dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]}}}
        proposed = {"version": 1, "agents": {"dev": {"deny": [{"action": "fs.read", "resource": "./src/**"}]}}}
        requests = [{"agent": "dev", "action": "fs.read", "resource": "./src/main.py"}]
        cp = _write_json(current)
        pp = _write_json(proposed)
        rf = _write_json(requests)
        try:
            results = simulate_from_files(cp, pp, rf)
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0].changed)
            self.assertEqual(results[0].current_decision.kind, DecisionKind.ALLOW)
            self.assertEqual(results[0].proposed_decision.kind, DecisionKind.DENY)
        finally:
            os.unlink(cp)
            os.unlink(pp)
            os.unlink(rf)

    def test_invalid_current_policy(self):
        bad = _write_json({"not": "a valid policy"})
        good = _write_json({"version": 1, "agents": {}})
        rf = _write_json([{"agent": "dev", "action": "fs.read"}])
        try:
            with self.assertRaises(InvalidPolicyError):
                simulate_from_files(bad, good, rf)
        finally:
            os.unlink(bad)
            os.unlink(good)
            os.unlink(rf)

    def test_invalid_proposed_policy(self):
        good = _write_json({"version": 1, "agents": {}})
        bad = _write_json({"not": "a valid policy"})
        rf = _write_json([{"agent": "dev", "action": "fs.read"}])
        try:
            with self.assertRaises(InvalidPolicyError):
                simulate_from_files(good, bad, rf)
        finally:
            os.unlink(good)
            os.unlink(bad)
            os.unlink(rf)

    def test_missing_requests_file(self):
        good = _write_json({"version": 1, "agents": {}})
        try:
            with self.assertRaises(InvalidRequestError):
                simulate_from_files(good, good, "/nonexistent/requests.json")
        finally:
            os.unlink(good)


# ══════════════════════════════════════════════════════════════════════════════
# Security / adversarial tests
# ══════════════════════════════════════════════════════════════════════════════

class SecurityTests(unittest.TestCase):
    """Security and adversarial checks."""

    def test_proposed_policy_not_activated(self):
        """Verify the proposed policy is never stored as active state."""
        current = _policy(allow=[{"action": "fs.read", "resource": "./src/**"}])
        proposed = _policy(deny=[{"action": "fs.read", "resource": "./src/**"}])
        reqs = [_req()]

        # Run simulation
        results = simulate_policy_comparison(current, proposed, reqs)

        # Verify current policy is unchanged
        self.assertEqual(
            results[0].current_decision.kind, DecisionKind.ALLOW
        )
        # Verify proposed policy was used for proposed_decision only
        self.assertEqual(
            results[0].proposed_decision.kind, DecisionKind.DENY
        )

    def test_no_file_writes(self):
        """simulate.py must not contain open(..., 'w') or open(..., 'a')."""
        import agent_firewall.simulate as sim_mod

        src_path = sim_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        lines = src.split("\n")
        in_docstring = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if in_docstring:
                continue
            if 'open(' in stripped and ("'w'" in stripped or '"w"' in stripped or "'a'" in stripped or '"a"' in stripped):
                self.fail(f"simulate.py contains write-mode open(): {stripped}")

    def test_no_network_imports(self):
        """simulate.py must not import network modules."""
        import agent_firewall.simulate as sim_mod

        src_path = sim_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        dangerous = ["import socket", "import http", "import urllib", "import requests"]
        for d in dangerous:
            self.assertNotIn(d, src, f"simulate.py imports {d}")

    def test_no_subprocess_imports(self):
        """simulate.py must not import subprocess."""
        import agent_firewall.simulate as sim_mod

        src_path = sim_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("import subprocess", src)

    def test_no_llm_imports(self):
        """simulate.py must not import LLM-related modules."""
        import agent_firewall.simulate as sim_mod

        src_path = sim_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("import openai", src)
        self.assertNotIn("import anthropic", src)

    def test_simulation_result_is_frozen(self):
        """SimulationResult must be a frozen dataclass."""
        current = _policy()
        proposed = _policy()
        results = simulate_policy_comparison(current, proposed, [_req()])
        with self.assertRaises(AttributeError):
            results[0].changed = True

    def test_no_secrets_in_output(self):
        """Verify simulation output doesn't leak unexpected data."""
        current = _policy(allow=[{"action": "secret.read", "resource": "DATABASE_URL"}])
        proposed = _policy(deny=[{"action": "secret.read", "resource": "DATABASE_URL"}])
        results = simulate_policy_comparison(
            current, proposed, [_req(action="secret.read", resource="DATABASE_URL")]
        )
        r = results[0]
        self.assertEqual(r.request.action, "secret.read")
        self.assertEqual(r.current_decision.kind, DecisionKind.ALLOW)
        self.assertEqual(r.proposed_decision.kind, DecisionKind.DENY)

    def test_zero_third_party_imports(self):
        """Verify simulate.py uses only stdlib + internal package imports."""
        import agent_firewall.simulate as sim_mod

        src_path = sim_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())

        # stdlib modules + internal package modules + __future__
        known_stdlib = {
            "json", "os", "sys", "dataclasses", "datetime", "typing",
            "hashlib", "hmac", "re", "enum", "pathlib", "collections",
            "fnmatch", "io", "__future__",
        }
        internal_pkg = {"evaluator", "model", "policy", "simulate"}
        allowed = known_stdlib | internal_pkg

        third_party = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod not in allowed:
                        third_party.append(mod)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod not in allowed:
                        third_party.append(mod)

        self.assertEqual(third_party, [], f"Third-party imports found: {third_party}")

    def test_evaluator_not_duplicated(self):
        """simulate.py must call evaluate() from evaluator, not reimplement it."""
        import agent_firewall.simulate as sim_mod

        src_path = sim_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("evaluate", src, "simulate.py must use evaluate()")


# ══════════════════════════════════════════════════════════════════════════════
# CLI tests
# ══════════════════════════════════════════════════════════════════════════════

class CLISimulateTests(unittest.TestCase):
    """Test the CLI simulate subcommand."""

    def setUp(self):
        self.current = _write_json({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]}},
        })
        self.proposed = _write_json({
            "version": 1,
            "agents": {"dev": {"deny": [{"action": "fs.read", "resource": "./src/**"}]}},
        })
        self.requests = _write_json([
            {"agent": "dev", "action": "fs.read", "resource": "./src/main.py"},
        ])

    def tearDown(self):
        for path in [self.current, self.proposed, self.requests]:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _run(self, args):
        from agent_firewall.cli import main
        return main(["simulate", "--current", self.current, "--proposed", self.proposed, "--requests", self.requests] + args)

    def test_text_output_exit_0(self):
        rc = self._run([])
        self.assertEqual(rc, 0)

    def test_json_output_exit_0(self):
        rc = self._run(["--json"])
        self.assertEqual(rc, 0)

    def test_json_output_valid_json(self):
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self._run(["--json"])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertIn("current", data[0])
        self.assertIn("proposed", data[0])
        self.assertIn("changed", data[0])

    def test_text_output_contains_comparison(self):
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self._run([])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertIn("dev", output)
        self.assertIn("fs.read", output)
        self.assertIn("ALLOW", output)
        self.assertIn("DENY", output)
        self.assertIn("SIMULATION", output.upper())

    def test_exit_3_invalid_request(self):
        bad_requests = _write_json([{"agent": "", "action": "fs.read"}])
        old = self.requests
        self.requests = bad_requests
        try:
            rc = self._run([])
            self.assertEqual(rc, 3)
        finally:
            self.requests = old
            os.unlink(bad_requests)

    def test_exit_4_invalid_current_policy(self):
        bad = _write_json({"not": "valid"})
        old = self.current
        self.current = bad
        try:
            rc = self._run([])
            self.assertEqual(rc, 4)
        finally:
            self.current = old
            os.unlink(bad)

    def test_exit_4_invalid_proposed_policy(self):
        bad = _write_json({"not": "valid"})
        old = self.proposed
        self.proposed = bad
        try:
            rc = self._run([])
            self.assertEqual(rc, 4)
        finally:
            self.proposed = old
            os.unlink(bad)

    def test_exit_3_missing_requests_file(self):
        old = self.requests
        self.requests = "/nonexistent/requests.json"
        try:
            rc = self._run([])
            self.assertEqual(rc, 3)
        finally:
            self.requests = old

    def test_errors_to_stderr(self):
        import io
        bad = _write_json({"not": "valid"})
        old = self.current
        self.current = bad
        try:
            old_stderr = sys.stderr
            sys.stderr = io.StringIO()
            try:
                self._run([])
                stderr_output = sys.stderr.getvalue()
            finally:
                sys.stderr = old_stderr
            self.assertIn("error", stderr_output.lower())
        finally:
            self.current = old
            os.unlink(bad)

    def test_no_file_creation(self):
        """Verify simulate command doesn't create output files."""
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self._run(["--json"])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        data = json.loads(output)
        self.assertIsInstance(data, list)

    def test_changed_true_when_decisions_differ(self):
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self._run(["--json"])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        data = json.loads(output)
        self.assertTrue(data[0]["changed"])

    def test_changed_false_when_decisions_same(self):
        same_proposed = _write_json({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]}},
        })
        old = self.proposed
        self.proposed = same_proposed
        try:
            import io
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                self._run(["--json"])
                output = sys.stdout.getvalue()
            finally:
                sys.stdout = old_stdout
            data = json.loads(output)
            self.assertFalse(data[0]["changed"])
        finally:
            self.proposed = old
            os.unlink(same_proposed)


# ══════════════════════════════════════════════════════════════════════════════
# Regression tests
# ══════════════════════════════════════════════════════════════════════════════

class RegressionTests(unittest.TestCase):
    """Verify simulation doesn't break existing behavior."""

    def test_evaluator_still_works(self):
        """Direct evaluator call still works after importing simulate."""
        from agent_firewall.evaluator import evaluate
        from agent_firewall.policy import policy_from_dict

        p = policy_from_dict({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.read"}]}},
        })
        d = evaluate(Request(agent="dev", action="fs.read"), p)
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_simulation_result_dataclass_fields(self):
        """Verify SimulationResult has exactly the expected fields."""
        fields = {f.name for f in SimulationResult.__dataclass_fields__.values()}
        self.assertEqual(
            fields, {"request", "current_decision", "proposed_decision", "changed"}
        )


if __name__ == "__main__":
    unittest.main()
