"""Tests for policy parsing, validation and fail-closed loading."""

import json
import os
import tempfile
import unittest

from agent_firewall.model import (
    InvalidPolicyError,
    UnsupportedPolicyVersionError,
)
from agent_firewall.policy import policy_from_dict, policy_from_file


def valid_policy(**overrides):
    data = {
        "version": 1,
        "agents": {
            "dev": {
                "allow": [{"action": "filesystem.read", "resource": "./**"}],
                "deny": [],
                "approve": [],
            }
        },
    }
    data.update(overrides)
    return data


class PolicyFromDictTests(unittest.TestCase):
    def test_valid_policy_loads(self):
        p = policy_from_dict(valid_policy())
        self.assertEqual(p.version, 1)
        self.assertIn("dev", p.agents)

    def test_empty_agents_allowed(self):
        p = policy_from_dict({"version": 1, "agents": {}})
        self.assertEqual(p.agents, {})

    def test_agent_with_no_rules_allowed(self):
        p = policy_from_dict({"version": 1, "agents": {"dev": {}}})
        self.assertEqual(p.agents["dev"].allow, ())
        self.assertEqual(p.agents["dev"].deny, ())
        self.assertEqual(p.agents["dev"].approve, ())


class MissingVersionTests(unittest.TestCase):
    def test_missing_version_fails(self):
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict({"agents": {}})

    def test_non_integer_version_fails(self):
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(valid_policy(version="1"))
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(valid_policy(version=True))
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(valid_policy(version=1.0))


class UnsupportedVersionTests(unittest.TestCase):
    def test_unknown_version_fails_closed(self):
        with self.assertRaises(UnsupportedPolicyVersionError):
            policy_from_dict(valid_policy(version=99))
        with self.assertRaises(UnsupportedPolicyVersionError):
            policy_from_dict(valid_policy(version=0))


class MalformedPolicyTests(unittest.TestCase):
    def test_not_an_object(self):
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict([])
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict("nope")
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(None)

    def test_missing_agents(self):
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict({"version": 1})

    def test_agents_not_an_object(self):
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict({"version": 1, "agents": []})

    def test_agent_not_an_object(self):
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict({"version": 1, "agents": {"dev": []}})

    def test_rule_not_an_object(self):
        bad = valid_policy()
        bad["agents"]["dev"]["allow"] = ["x"]
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(bad)

    def test_rule_missing_action(self):
        bad = valid_policy()
        bad["agents"]["dev"]["allow"] = [{"resource": "./**"}]
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(bad)

    def test_rule_empty_action(self):
        bad = valid_policy()
        bad["agents"]["dev"]["allow"] = [{"action": ""}]
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(bad)

    def test_rule_bad_resource_type(self):
        bad = valid_policy()
        bad["agents"]["dev"]["allow"] = [{"action": "x", "resource": 42}]
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(bad)

    def test_allow_not_a_list(self):
        bad = valid_policy()
        bad["agents"]["dev"]["allow"] = {"action": "x"}
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(bad)

    def test_rule_pattern_escaping_root_fails_as_invalid_policy(self):
        # A policy whose resource pattern tries to rise above the workspace
        # base is an invalid policy, never an active permissive one.
        for escaped in ("./../../secret", "../../etc/passwd", "../x"):
            bad = valid_policy()
            bad["agents"]["dev"]["allow"] = [
                {"action": "filesystem.read", "resource": escaped}
            ]
            with self.assertRaises(InvalidPolicyError):
                policy_from_dict(bad)

    def test_absolute_rule_pattern_fails_as_invalid_policy(self):
        # Absolute resource patterns must never be silently converted to a
        # relative pattern; the policy is rejected and never becomes active.
        for absolute in ("/etc/passwd", "/absolute/path", "/a/../../secret",
                         "C:/x/y", r"C:\x\y", r"\\server\share\f"):
            bad = valid_policy()
            bad["agents"]["dev"]["allow"] = [
                {"action": "filesystem.read", "resource": absolute}
            ]
            with self.assertRaises(InvalidPolicyError, msg=absolute):
                policy_from_dict(bad)


class UnknownFieldTests(unittest.TestCase):
    def test_unknown_top_level_field_rejected(self):
        bad = valid_policy()
        bad["sercer"] = {}
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(bad)

    def test_unknown_agent_field_rejected(self):
        bad = valid_policy()
        bad["agents"]["dev"]["alow"] = []
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(bad)

    def test_unknown_rule_field_rejected(self):
        bad = valid_policy()
        bad["agents"]["dev"]["allow"] = [{"action": "x", "resurce": "./**"}]
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(bad)


class PartiallyInvalidTests(unittest.TestCase):
    def test_partially_valid_policy_never_becomes_active(self):
        # One good agent, one malformed agent - the whole policy must fail.
        data = {
            "version": 1,
            "agents": {
                "good": {"allow": [{"action": "git.read"}]},
                "bad": {"allow": [{"action": ""}]},
            },
        }
        with self.assertRaises(InvalidPolicyError):
            policy_from_dict(data)


class PolicyFromFileTests(unittest.TestCase):
    def test_reads_valid_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "policy.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(valid_policy(), fh)
            p = policy_from_file(path)
            self.assertEqual(p.version, 1)
            self.assertIn("dev", p.agents)

    def test_missing_file_fails_closed(self):
        with self.assertRaises(InvalidPolicyError):
            policy_from_file("does-not-exist.json")

    def test_malformed_json_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{ not json ")
            with self.assertRaises(InvalidPolicyError):
                policy_from_file(path)

    def test_invalid_semantics_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "unsup.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(valid_policy(version=7), fh)
            with self.assertRaises(InvalidPolicyError):
                policy_from_file(path)


if __name__ == "__main__":
    unittest.main()