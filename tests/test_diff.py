"""Tests for Phase 7 policy diff.

Covers:
    - structural diff (added, removed, changed_resource)
    - empty policies, identical policies
    - multiple agents, multiple collections
    - determinism
    - invalid policies / missing files
    - CLI text output, JSON output, exit codes
    - no file writes
    - no evaluate() calls
    - zero third-party dependencies
    - security/adversarial checks
    - regression coverage
"""

import ast
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall.model import Rule
from agent_firewall.policy import InvalidPolicyError, Policy, policy_from_dict
from agent_firewall.diff import RuleDiff, diff_policies


# ── Helpers ───────────────────────────────────────────────────────────────────

def _policy(*, version=1, gen=1, agents=None) -> Policy:
    if agents is None:
        agents = {}
    return policy_from_dict({"version": version, "agents": agents}, generation=gen)


def _write_json(data) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(data, f)
    f.close()
    return f.name


# ══════════════════════════════════════════════════════════════════════════════
# Unit tests for diff_policies
# ══════════════════════════════════════════════════════════════════════════════

class IdenticalPoliciesTests(unittest.TestCase):
    """Identical policies produce no diffs."""

    def test_both_empty(self):
        old = _policy()
        new = _policy()
        self.assertEqual(diff_policies(old, new), [])

    def test_both_same_rules(self):
        data = {"allow": [{"action": "fs.read", "resource": "./src/**"}]}
        old = _policy(agents={"dev": data})
        new = _policy(agents={"dev": data})
        self.assertEqual(diff_policies(old, new), [])

    def test_same_rules_different_generation(self):
        old = _policy(gen=1, agents={"dev": {"allow": [{"action": "fs.read"}]}})
        new = _policy(gen=99, agents={"dev": {"allow": [{"action": "fs.read"}]}})
        self.assertEqual(diff_policies(old, new), [])


class AddedRuleTests(unittest.TestCase):
    """Rules that exist in new but not old."""

    def test_single_added_rule(self):
        old = _policy()
        new = _policy(agents={"dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]}})
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].kind, "added")
        self.assertEqual(diffs[0].agent, "dev")
        self.assertEqual(diffs[0].collection, "allow")
        self.assertIsNone(diffs[0].old_rule)
        self.assertIsNotNone(diffs[0].new_rule)

    def test_added_to_existing_agent(self):
        old = _policy(agents={"dev": {"allow": [{"action": "fs.read"}]}})
        new = _policy(agents={"dev": {
            "allow": [{"action": "fs.read"}, {"action": "fs.write", "resource": "./src/**"}],
        }})
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].kind, "added")
        self.assertEqual(diffs[0].new_rule.action, "fs.write")


class RemovedRuleTests(unittest.TestCase):
    """Rules that exist in old but not new."""

    def test_single_removed_rule(self):
        old = _policy(agents={"dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]}})
        new = _policy()
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].kind, "removed")
        self.assertEqual(diffs[0].agent, "dev")
        self.assertIsNotNone(diffs[0].old_rule)
        self.assertIsNone(diffs[0].new_rule)


class ChangedResourceTests(unittest.TestCase):
    """Same action, different resource → old removed + new added."""

    def test_resource_changed(self):
        old = _policy(agents={"dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]}})
        new = _policy(agents={"dev": {"allow": [{"action": "fs.read", "resource": "./docs/**"}]}})
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 2)
        kinds = sorted(d.kind for d in diffs)
        self.assertEqual(kinds, ["added", "removed"])

    def test_resource_added_to_bare_action(self):
        old = _policy(agents={"dev": {"allow": [{"action": "fs.read"}]}})
        new = _policy(agents={"dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]}})
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 2)
        kinds = sorted(d.kind for d in diffs)
        self.assertEqual(kinds, ["added", "removed"])

    def test_resource_removed_from_action(self):
        old = _policy(agents={"dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]}})
        new = _policy(agents={"dev": {"allow": [{"action": "fs.read"}]}})
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 2)
        kinds = sorted(d.kind for d in diffs)
        self.assertEqual(kinds, ["added", "removed"])


class AgentChangesTests(unittest.TestCase):
    """Agents added or removed entirely."""

    def test_agent_added(self):
        old = _policy()
        new = _policy(agents={"dev": {"allow": [{"action": "fs.read"}]}})
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].kind, "added")
        self.assertEqual(diffs[0].agent, "dev")

    def test_agent_removed(self):
        old = _policy(agents={"dev": {"allow": [{"action": "fs.read"}]}})
        new = _policy()
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].kind, "removed")
        self.assertEqual(diffs[0].agent, "dev")

    def test_agent_replaced(self):
        old = _policy(agents={"dev": {"allow": [{"action": "fs.read"}]}})
        new = _policy(agents={"admin": {"deny": [{"action": "fs.write"}]}})
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 2)
        kinds = sorted(d.kind for d in diffs)
        self.assertEqual(kinds, ["added", "removed"])


class CollectionTests(unittest.TestCase):
    """Differences across allow/deny/approve collections."""

    def test_added_to_deny(self):
        old = _policy()
        new = _policy(agents={"dev": {"deny": [{"action": "fs.write"}]}})
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].collection, "deny")

    def test_added_to_approve(self):
        old = _policy()
        new = _policy(agents={"dev": {"approve": [{"action": "prod.deploy"}]}})
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].collection, "approve")

    def test_mixed_collections(self):
        old = _policy(agents={"dev": {"allow": [{"action": "fs.read"}]}})
        new = _policy(agents={"dev": {
            "allow": [{"action": "fs.read"}, {"action": "fs.write"}],
            "deny": [{"action": "fs.delete"}],
        }})
        diffs = diff_policies(old, new)
        self.assertEqual(len(diffs), 2)
        collections = sorted(d.collection for d in diffs)
        self.assertEqual(collections, ["allow", "deny"])


class MultiAgentTests(unittest.TestCase):
    """Multiple agents with various changes."""

    def test_multiple_agents(self):
        old = _policy(agents={
            "dev": {"allow": [{"action": "fs.read"}]},
            "admin": {"deny": [{"action": "fs.write"}]},
        })
        new = _policy(agents={
            "dev": {"allow": [{"action": "fs.read"}, {"action": "fs.write"}]},
            "tester": {"allow": [{"action": "fs.read"}]},
        })
        diffs = diff_policies(old, new)
        # dev: 1 added, admin: 1 removed, tester: 1 added = 3 total
        self.assertEqual(len(diffs), 3)
        agents = sorted(set(d.agent for d in diffs))
        self.assertEqual(agents, ["admin", "dev", "tester"])


class DeterminismTests(unittest.TestCase):
    """Results must be deterministic."""

    def test_same_inputs_same_outputs(self):
        old = _policy(agents={"dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]}})
        new = _policy(agents={"dev": {"allow": [{"action": "fs.write", "resource": "./src/**"}]}})
        r1 = diff_policies(old, new)
        r2 = diff_policies(old, new)
        self.assertEqual(len(r1), len(r2))
        for a, b in zip(r1, r2):
            self.assertEqual(a.agent, b.agent)
            self.assertEqual(a.collection, b.collection)
            self.assertEqual(a.kind, b.kind)


class SecurityTests(unittest.TestCase):
    """Security and adversarial checks."""

    def test_no_evaluate_call_in_code(self):
        """diff_policies must not call evaluate() in actual code."""
        import agent_firewall.diff as diff_mod
        src_path = diff_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        in_docstring = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if in_docstring:
                continue
            if "evaluate(" in stripped:
                self.fail(f"diff.py calls evaluate() in code: {stripped}")

    def test_no_file_writes(self):
        """diff.py must not contain write-mode file opens."""
        import agent_firewall.diff as diff_mod
        src_path = diff_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        lines = src.split("\n")
        in_docstring = False
        for line in lines:
            s = line.strip()
            if s.startswith('"""') or s.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if in_docstring:
                continue
            if 'open(' in s and ("'w'" in s or '"w"' in s or "'a'" in s or '"a"' in s):
                self.fail(f"diff.py contains write-mode open(): {s}")

    def test_no_network_imports(self):
        import agent_firewall.diff as diff_mod
        src_path = diff_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        for d in ["import socket", "import http", "import urllib", "import requests"]:
            self.assertNotIn(d, src)

    def test_no_subprocess_imports(self):
        import agent_firewall.diff as diff_mod
        src_path = diff_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("import subprocess", src)

    def test_no_llm_imports(self):
        import agent_firewall.diff as diff_mod
        src_path = diff_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("import openai", src)
        self.assertNotIn("import anthropic", src)

    def test_rulediff_is_frozen(self):
        self.assertTrue(RuleDiff.__dataclass_params__.frozen)

    def test_zero_third_party_imports(self):
        import agent_firewall.diff as diff_mod
        src_path = diff_mod.__file__
        with open(src_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        known = {
            "json", "os", "sys", "dataclasses", "datetime", "typing",
            "hashlib", "hmac", "re", "enum", "pathlib", "collections",
            "fnmatch", "io", "__future__",
        }
        internal = {"evaluator", "model", "policy", "diff", "normalize"}
        allowed = known | internal
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
        self.assertEqual(third_party, [], f"Third-party imports: {third_party}")

    def test_diff_output_is_informational(self):
        """Verify diff doesn't produce decisions."""
        old = _policy(agents={"dev": {"allow": [{"action": "fs.read"}]}})
        new = _policy(agents={"dev": {"deny": [{"action": "fs.read"}]}})
        diffs = diff_policies(old, new)
        for d in diffs:
            self.assertIsInstance(d, RuleDiff)
            self.assertIn(d.kind, ("added", "removed", "changed_resource"))


# ══════════════════════════════════════════════════════════════════════════════
# CLI tests
# ══════════════════════════════════════════════════════════════════════════════

class CLIDiffTests(unittest.TestCase):
    """Test the CLI diff subcommand."""

    def setUp(self):
        self.old = _write_json({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.read", "resource": "./src/**"}]}},
        })
        self.new = _write_json({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.write", "resource": "./src/**"}]}},
        })

    def tearDown(self):
        for path in [self.old, self.new]:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _run(self, args):
        from agent_firewall.cli import main
        return main(["diff", "--old", self.old, "--new", self.new] + args)

    def test_text_output_exit_0(self):
        rc = self._run([])
        self.assertEqual(rc, 0)

    def test_json_output_exit_0(self):
        rc = self._run(["--json"])
        self.assertEqual(rc, 0)

    def test_json_output_valid(self):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self._run(["--json"])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_json_has_expected_fields(self):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self._run(["--json"])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        data = json.loads(output)
        for item in data:
            self.assertIn("agent", item)
            self.assertIn("collection", item)
            self.assertIn("kind", item)
            self.assertIn("action", item)

    def test_text_output_shows_diff(self):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self._run([])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertIn("dev", output)
        self.assertIn("fs.read", output)
        self.assertIn("fs.write", output)

    def test_identical_policies_no_output(self):
        self.new = self.old  # same file
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = self._run([])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        self.assertEqual(output.strip(), "")

    def test_exit_4_invalid_old_policy(self):
        bad = _write_json({"not": "valid"})
        old = self.old
        self.old = bad
        try:
            rc = self._run([])
            self.assertEqual(rc, 4)
        finally:
            self.old = old
            os.unlink(bad)

    def test_exit_4_invalid_new_policy(self):
        bad = _write_json({"not": "valid"})
        old = self.new
        self.new = bad
        try:
            rc = self._run([])
            self.assertEqual(rc, 4)
        finally:
            self.new = old
            os.unlink(bad)

    def test_exit_4_missing_old_file(self):
        old = self.old
        self.old = "/nonexistent/old.json"
        try:
            rc = self._run([])
            self.assertEqual(rc, 4)
        finally:
            self.old = old

    def test_exit_4_missing_new_file(self):
        old = self.new
        self.new = "/nonexistent/new.json"
        try:
            rc = self._run([])
            self.assertEqual(rc, 4)
        finally:
            self.new = old

    def test_errors_to_stderr(self):
        bad = _write_json({"not": "valid"})
        old = self.old
        self.old = bad
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
            self.old = old
            os.unlink(bad)

    def test_json_empty_when_identical(self):
        self.new = self.old
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self._run(["--json"])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        data = json.loads(output)
        self.assertEqual(data, [])


# ══════════════════════════════════════════════════════════════════════════════
# Regression tests
# ══════════════════════════════════════════════════════════════════════════════

class RegressionTests(unittest.TestCase):
    """Verify diff doesn't break existing behavior."""

    def test_evaluator_still_works(self):
        from agent_firewall.evaluator import evaluate
        from agent_firewall.model import DecisionKind, Request
        from agent_firewall.policy import policy_from_dict

        p = policy_from_dict({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.read"}]}},
        })
        d = evaluate(Request(agent="dev", action="fs.read"), p)
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_rulediff_dataclass_fields(self):
        fields = {f.name for f in RuleDiff.__dataclass_fields__.values()}
        self.assertEqual(fields, {"agent", "collection", "kind", "old_rule", "new_rule"})


if __name__ == "__main__":
    unittest.main()
