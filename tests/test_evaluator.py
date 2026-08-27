"""Tests for the deterministic evaluator: decisions, precedence, matching."""

import unittest

from agent_firewall import policy_from_dict
from agent_firewall.evaluator import evaluate
from agent_firewall.model import (
    DecisionKind,
    InvalidRequestError,
    Request,
)


def policy(**agents):
    return policy_from_dict({"version": 1, "agents": agents})


DEVELOPER = {
    "allow": [
        {"action": "filesystem.read", "resource": "./**"},
        {"action": "filesystem.write", "resource": "./src/**"},
        {"action": "git.commit"},
    ],
    "deny": [
        {"action": "filesystem.read", "resource": "./.env"},
        {"action": "filesystem.write", "resource": "./src/secrets/**"},
    ],
    "approve": [
        {"action": "git.push"},
    ],
}


class CoreDecisionTests(unittest.TestCase):
    def setUp(self):
        self.p = policy(developer=DEVELOPER)

    def test_explicit_allow(self):
        d = evaluate(Request("developer", "filesystem.read", "./src/auth.py"), self.p)
        self.assertIs(d.kind, DecisionKind.ALLOW)
        self.assertTrue(d.allowed)

    def test_explicit_deny(self):
        d = evaluate(Request("developer", "filesystem.read", "./.env"), self.p)
        self.assertIs(d.kind, DecisionKind.DENY)
        self.assertFalse(d.allowed)

    def test_explicit_approve(self):
        d = evaluate(Request("developer", "git.push"), self.p)
        self.assertIs(d.kind, DecisionKind.APPROVE)
        self.assertFalse(d.allowed)

    def test_no_matching_rule_default_deny(self):
        d = evaluate(Request("developer", "network.connect", "x:443"), self.p)
        self.assertIs(d.kind, DecisionKind.DENY)

    def test_general_rule_matches_without_resource(self):
        d = evaluate(Request("developer", "git.commit"), self.p)
        self.assertIs(d.kind, DecisionKind.ALLOW)


class DefaultDenyTests(unittest.TestCase):
    def test_unknown_agent_denied(self):
        p = policy(developer=DEVELOPER)
        d = evaluate(Request("attacker", "filesystem.read", "./x"), p)
        self.assertIs(d.kind, DecisionKind.DENY)
        self.assertIn("unknown agent", d.reason)

    def test_unknown_action_denied(self):
        p = policy(developer=DEVELOPER)
        d = evaluate(Request("developer", "filesystem.delete", "./src/a"), p)
        self.assertIs(d.kind, DecisionKind.DENY)

    def test_unknown_resource_denied(self):
        p = {"allow": [{"action": "filesystem.read", "resource": "./src/**"}]}
        d = evaluate(Request("developer", "filesystem.read", "./other/x"), policy(developer=p))
        self.assertIs(d.kind, DecisionKind.DENY)

    def test_empty_policy_denied(self):
        d = evaluate(Request("developer", "filesystem.read", "./x"), policy(developer={}))
        self.assertIs(d.kind, DecisionKind.DENY)

    def test_empty_agents_denied(self):
        d = evaluate(Request("developer", "filesystem.read", "./x"), policy())
        self.assertIs(d.kind, DecisionKind.DENY)


class PrecedenceTests(unittest.TestCase):
    def test_deny_overrides_allow(self):
        p = policy(dev={
            "allow": [{"action": "filesystem.write", "resource": "./**"}],
            "deny": [{"action": "filesystem.write", "resource": "./secret/**"}],
        })
        self.assertIs(
            evaluate(Request("dev", "filesystem.write", "./secret/key"), p).kind,
            DecisionKind.DENY,
        )
        self.assertIs(
            evaluate(Request("dev", "filesystem.write", "./src/main.py"), p).kind,
            DecisionKind.ALLOW,
        )

    def test_deny_overrides_approve(self):
        p = policy(dev={
            "approve": [{"action": "git.push"}],
            "deny": [{"action": "git.push", "resource": "production"}],
        })
        self.assertIs(
            evaluate(Request("dev", "git.push", "production"), p).kind,
            DecisionKind.DENY,
        )
        self.assertIs(
            evaluate(Request("dev", "git.push", "staging"), p).kind,
            DecisionKind.APPROVE,
        )

    def test_approve_overrides_allow(self):
        p = policy(dev={
            "allow": [{"action": "production.deploy"}],
            "approve": [{"action": "production.deploy"}],
        })
        self.assertIs(
            evaluate(Request("dev", "production.deploy"), p).kind,
            DecisionKind.APPROVE,
        )

    def test_deny_beats_broad_allow_for_specific_resource(self):
        p = policy(dev={
            "allow": [{"action": "filesystem.read", "resource": "./**"}],
            "deny": [{"action": "filesystem.read", "resource": "./src/secrets/**"}],
        })
        self.assertIs(
            evaluate(Request("dev", "filesystem.read", "./src/secrets/config.py"), p).kind,
            DecisionKind.DENY,
        )


class ActionMatchingTests(unittest.TestCase):
    def test_exact_action_match(self):
        p = policy(dev={"allow": [{"action": "filesystem.read"}]})
        self.assertIs(evaluate(Request("dev", "filesystem.read"), p).kind, DecisionKind.ALLOW)

    def test_similar_action_is_not_implicitly_allowed(self):
        p = policy(dev={"allow": [{"action": "filesystem.read"}]})
        self.assertIs(evaluate(Request("dev", "filesystem.write"), p).kind, DecisionKind.DENY)


class ResourceMatchingTests(unittest.TestCase):
    def test_exact_resource(self):
        p = policy(dev={"allow": [{"action": "filesystem.read", "resource": "./src/auth.py"}]})
        self.assertIs(
            evaluate(Request("dev", "filesystem.read", "./src/auth.py"), p).kind,
            DecisionKind.ALLOW,
        )

    def test_wildcard_nested(self):
        p = policy(dev={"allow": [{"action": "filesystem.read", "resource": "./src/**"}]})
        self.assertIs(
            evaluate(Request("dev", "filesystem.read", "./src/deep/file.py"), p).kind,
            DecisionKind.ALLOW,
        )

    def test_nonmatching_resource(self):
        p = policy(dev={"allow": [{"action": "filesystem.read", "resource": "./src/**"}]})
        self.assertIs(
            evaluate(Request("dev", "filesystem.read", "./tests/a.py"), p).kind,
            DecisionKind.DENY,
        )

    def test_resource_less_action(self):
        p = policy(dev={"allow": [{"action": "git.commit"}]})
        self.assertIs(evaluate(Request("dev", "git.commit"), p).kind, DecisionKind.ALLOW)

    def test_general_rule_matches_request_with_unexpected_resource(self):
        # rule without resource applies generally, even if request has one
        p = policy(dev={"allow": [{"action": "git.commit"}]})
        self.assertIs(
            evaluate(Request("dev", "git.commit", "anything"), p).kind,
            DecisionKind.ALLOW,
        )


class TraversalTests(unittest.TestCase):
    def test_traversal_cannot_bypass_deny(self):
        p = policy(dev={
            "allow": [{"action": "filesystem.read", "resource": "./src/**"}],
            "deny": [{"action": "filesystem.read", "resource": "./.env"}],
        })
        # Paths that normalize safely back inside the root are evaluated and
        # must hit the deny (.env is denied).
        for resource in ("./src/../.env", "././.env", "src/../.env"):
            d = evaluate(Request("dev", "filesystem.read", resource), p)
            self.assertIs(d.kind, DecisionKind.DENY, resource)

    def test_root_escape_request_fails_closed(self):
        # An escape attempt may raise (which is never ALLOW) or be evaluated
        # only when it normalizes inside the root; it must never become ALLOW.
        p = policy(dev={"allow": [{"action": "filesystem.read", "resource": "./**"}]})
        for resource in ("./src/../../secret", "../../etc/passwd",
                         "../../../secret", "./../../secret", "../.env"):
            with self.assertRaises(InvalidRequestError, msg=resource):
                evaluate(Request("dev", "filesystem.read", resource), p)

    def test_traversal_cannot_reach_an_allowed_path_that_is_not_granted(self):
        p = policy(dev={"allow": [{"action": "filesystem.read", "resource": "./src/**"}]})
        # ./src/../../secret tries to leave the root -> fail closed.
        with self.assertRaises(InvalidRequestError):
            evaluate(Request("dev", "filesystem.read", "./src/../../secret"), p)

    def test_absolute_resource_never_allowed(self):
        # An absolute filesystem resource is invalid at the evaluator, so it
        # can never reach the matcher and can never produce ALLOW.
        p = policy(dev={"allow": [{"action": "filesystem.read", "resource": "./**"}]})
        for absolute in ("/etc/passwd", "/absolute/path", "/tmp/file",
                         "/a/../a/b", "/a/../../secret",
                         "C:/x/y", r"C:\x\y", r"\\server\share\file"):
            with self.assertRaises(InvalidRequestError, msg=absolute):
                evaluate(Request("dev", "filesystem.read", absolute), p)


class MalformedRequestTests(unittest.TestCase):
    def setUp(self):
        self.p = policy(developer=DEVELOPER)

    def test_missing_agent_raises(self):
        with self.assertRaises(InvalidRequestError):
            evaluate(Request("", "filesystem.read", "./x"), self.p)

    def test_missing_action_raises(self):
        with self.assertRaises(InvalidRequestError):
            evaluate(Request("developer", "", "./x"), self.p)

    def test_non_string_resource_raises(self):
        with self.assertRaises(InvalidRequestError):
            evaluate(Request("developer", "filesystem.read", 42), self.p)


class DeterminismTests(unittest.TestCase):
    def test_same_request_same_decision(self):
        p = policy(developer=DEVELOPER)
        req = Request("developer", "filesystem.write", "./src/a.py")
        d1 = evaluate(req, p)
        d2 = evaluate(req, p)
        self.assertEqual(d1.kind, d2.kind)
        self.assertEqual(d1.reason, d2.reason)
        self.assertEqual(d1.rule, d2.rule)

    def test_rule_order_within_collection_does_not_change_decision(self):
        allowed = [{"action": "filesystem.read", "resource": "./**"},
                   {"action": "filesystem.read", "resource": "./**"}]
        a = policy(dev={"allow": allowed, "deny": [], "approve": []})
        b = policy(dev={"allow": list(reversed(allowed)), "deny": [], "approve": []})
        self.assertEqual(
            evaluate(Request("dev", "filesystem.read", "./x"), a).kind,
            evaluate(Request("dev", "filesystem.read", "./x"), b).kind,
        )


if __name__ == "__main__":
    unittest.main()