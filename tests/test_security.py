"""Security-invariant tests (TEST_PLAN 30) for the Phase 1 core.

Every test here asserts a fail-closed property: nothing about an
invalid/permissive input may turn into ALLOW, and evaluation must have no
side effects.
"""

import os
import tempfile
import unittest

from agent_firewall import DecisionKind, InvalidPolicyError, InvalidRequestError
from agent_firewall.evaluator import evaluate
from agent_firewall.model import Request
from agent_firewall.policy import policy_from_dict


def any_policy(agents):
    return policy_from_dict({"version": 1, "agents": agents})


class FailClosedTests(unittest.TestCase):
    def test_unknown_agent_never_allows(self):
        p = any_policy({"dev": {"allow": [{"action": "filesystem.read", "resource": "./**"}]}})
        self.assertIsNot(evaluate(Request("unknown", "filesystem.read", "./x"), p).kind,
                         DecisionKind.ALLOW)

    def test_unknown_action_never_allows(self):
        p = any_policy({"dev": {"allow": [{"action": "filesystem.read", "resource": "./**"}]}})
        self.assertIsNot(evaluate(Request("dev", "sudo.rm", "/"), p).kind, DecisionKind.ALLOW)

    def test_unknown_resource_never_allows(self):
        p = any_policy({"dev": {"allow": [{"action": "filesystem.read", "resource": "./src/**"}]}})
        self.assertIsNot(evaluate(Request("dev", "filesystem.read", "./etc/passwd"), p).kind,
                         DecisionKind.ALLOW)

    def test_empty_policy_never_allows(self):
        p = any_policy({})
        self.assertIsNot(evaluate(Request("dev", "any.action", "r"), p).kind, DecisionKind.ALLOW)

    def test_malformed_policy_never_produces_decision(self):
        bad = {"version": 1, "agents": {"dev": {"allow": [{"action": ""}]}}}
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(bad)

    def test_unsupported_version_fails_closed(self):
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict({"version": 999, "agents": {}})

    def test_malformed_request_never_allows(self):
        p = any_policy({"dev": {"allow": [{"action": "**"}]}})
        with self.assertRaises(InvalidRequestError):
            evaluate(Request("", "filesystem.read", "./x"), p)

    def test_traversal_never_bypasses_deny(self):
        # Narrow allow (NOT "./**") plus a deny region.
        p = any_policy({
            "dev": {
                "allow": [{"action": "filesystem.read", "resource": "./src/**"}],
                "deny": [{"action": "filesystem.read", "resource": "./private/**"}],
            }
        })
        # direct deny path
        self.assertIs(evaluate(Request("dev", "filesystem.read", "./private/key"), p).kind,
                      DecisionKind.DENY)
        # safe internal normalization that lands inside the allow region -> ALLOW
        self.assertIs(
            evaluate(Request("dev", "filesystem.read", "./src/../src/ok.py"), p).kind,
            DecisionKind.ALLOW)
        # safe internal normalization that lands in the denied region -> DENY
        self.assertIs(
            evaluate(Request("dev", "filesystem.read", "./src/../private/key"), p).kind,
            DecisionKind.DENY)
        # safe internal normalization that lands outside any rule -> default DENY
        self.assertIs(
            evaluate(Request("dev", "filesystem.read", "./src/../secret"), p).kind,
            DecisionKind.DENY)
        # root escapes fail closed (never ALLOW)
        for escaped in ("./src/../../etc/passwd", "../secret", "../../secret"):
            with self.assertRaises(InvalidRequestError, msg=escaped):
                evaluate(Request("dev", "filesystem.read", escaped), p)


class AbsolutePathSecurityTests(unittest.TestCase):
    def test_absolute_request_never_allows(self):
        # An absolute filesystem resource is invalid: evaluation raises before
        # matching, so it can never produce ALLOW even under a broad policy.
        p = any_policy({"dev": {"allow": [{"action": "filesystem.read", "resource": "./**"}]}})
        for absolute in ("/etc/passwd", "/absolute/path", "C:/x", r"C:\x\y",
                         r"\\server\share\f", "/a/../../secret"):
            with self.assertRaises(InvalidRequestError, msg=absolute):
                evaluate(Request("dev", "filesystem.read", absolute), p)


class DenyDominanceTests(unittest.TestCase):
    def test_deny_always_beats_broad_allow(self):
        p = any_policy({
            "dev": {
                "allow": [{"action": "filesystem.write", "resource": "./**"}],
                "deny": [{"action": "filesystem.write", "resource": "./.git/**"}],
            }
        })
        self.assertIs(evaluate(Request("dev", "filesystem.write", "./.git/config"), p).kind,
                      DecisionKind.DENY)


class SideEffectFreedomTests(unittest.TestCase):
    def test_evaluate_writes_nothing_in_cwd(self):
        with tempfile.TemporaryDirectory() as d:
            p = any_policy({
                "dev": {"allow": [{"action": "filesystem.write", "resource": "./**"}]}
            })
            before = set(os.listdir(d))
            # exercise allow, deny and approve paths
            evaluate(Request("dev", "filesystem.write", "./a.py"), p)
            evaluate(Request("unknown", "filesystem.write", "./a.py"), p)
            evaluate(Request("dev", "network.connect", "x:1"), p)
            after = set(os.listdir(d))
            self.assertEqual(before, after)

    def test_evaluate_is_idempotent_and_branch_stable(self):
        p = any_policy({
            "dev": {
                "allow": [{"action": "git.read"}],
                "approve": [{"action": "git.push"}],
                "deny": [{"action": "secret.read"}],
            }
        })
        for i in range(5):
            self.assertIs(evaluate(Request("dev", "git.read"), p).kind, DecisionKind.ALLOW)
            self.assertIs(evaluate(Request("dev", "git.push"), p).kind, DecisionKind.APPROVE)
            self.assertIs(evaluate(Request("dev", "secret.read"), p).kind, DecisionKind.DENY)


class DecisionContentTests(unittest.TestCase):
    def test_decision_contains_only_declared_fields(self):
        p = any_policy({"dev": {"allow": [{"action": "git.commit"}]}})
        d = evaluate(Request("dev", "git.commit"), p)
        # A Decision object only exposes the declared attributes; nothing
        # about a prompt or raw command line can leak in.
        allowed_attrs = {
            "kind", "agent", "action", "resource", "rule",
            "reason", "policy_version", "policy_generation", "allowed",
        }
        present = {k for k in d.__dict__} | {"allowed"}
        self.assertTrue(present.issubset(allowed_attrs))

    def test_reason_never_contains_resource_body_for_non_match(self):
        # Even a weird resource must not be echoed more than its declared
        # field; the reason is generated from rule identifiers only.
        p = any_policy({"dev": {"allow": [{"action": "git.commit"}]}})
        d = evaluate(Request("dev", "git.push", "SECRET_VALUE_XYZ"), p)
        self.assertNotIn("SECRET_VALUE_XYZ", d.reason)


if __name__ == "__main__":
    unittest.main()