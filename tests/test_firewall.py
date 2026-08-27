"""Tests for the Firewall facade and immutable policy snapshots."""

import json
import os
import tempfile
import unittest

from agent_firewall import (
    DecisionKind,
    Firewall,
    Request,
    policy_from_dict,
)


class FirewallFacadeTests(unittest.TestCase):
    def test_from_dict_and_check(self):
        fw = Firewall.from_dict({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "git.read"}]}},
        })
        self.assertIs(fw.check(Request("dev", "git.read")).kind, DecisionKind.ALLOW)
        self.assertTrue(fw.is_allowed(Request("dev", "git.read")))

    def test_from_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "agents": {"dev": {"allow": [{"action": "git.read"}]}}}, fh)
            fw = Firewall.from_file(path)
            self.assertIs(fw.check(Request("dev", "git.read")).kind, DecisionKind.ALLOW)

    def test_policy_properties_expose_snapshot(self):
        p = policy_from_dict({"version": 1, "agents": {}})
        fw = Firewall(p)
        self.assertIs(fw.policy, p)
        self.assertIs(fw.snapshot, p)


class ImmutableSnapshotTests(unittest.TestCase):
    def test_policy_is_immutable(self):
        p = policy_from_dict({"version": 1, "agents": {"dev": {"allow": [{"action": "git.read"}]}}})
        with self.assertRaises(Exception):
            p.agents["dev"].allow = ()  # dataclass frozen -> read-only

    def test_mutating_source_dict_does_not_change_snapshot(self):
        source = {"version": 1, "agents": {"dev": {"allow": [{"action": "git.read"}]}}}
        fw = Firewall.from_dict(source)
        assert fw.check(Request("dev", "git.read")).kind == DecisionKind.ALLOW
        # mutate the caller's dict deeply
        source["agents"]["dev"]["allow"] = []
        self.assertIs(fw.check(Request("dev", "git.read")).kind, DecisionKind.ALLOW)
        self.assertIs(fw.check(Request("dev", "unknown.action")).kind, DecisionKind.DENY)

    def test_two_snapshots_are_independent(self):
        a = Firewall.from_dict({"version": 1, "agents": {"dev": {"allow": [{"action": "git.read"}]}}})
        b = Firewall.from_dict({"version": 1, "agents": {"dev": {"allow": [{"action": "git.write"}]}}})
        self.assertIs(a.check(Request("dev", "git.read")).kind, DecisionKind.ALLOW)
        self.assertIs(b.check(Request("dev", "git.read")).kind, DecisionKind.DENY)
        self.assertIs(a.check(Request("dev", "git.write")).kind, DecisionKind.DENY)
        self.assertIs(b.check(Request("dev", "git.write")).kind, DecisionKind.ALLOW)


if __name__ == "__main__":
    unittest.main()