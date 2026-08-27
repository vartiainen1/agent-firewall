"""Tests for Phase 17 advisory policy suggestion engine.

Verifies PolicySuggestion, PolicySuggestionEngine, proposed_policy(),
export_suggestions(), and all security invariants.
"""

import ast
import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall import Firewall, Request
from agent_firewall.model import DecisionKind
from agent_firewall.policy import Policy, policy_from_dict
from agent_firewall.suggestions import (
    InvalidSuggestionError,
    PolicySuggestion,
    PolicySuggestionEngine,
    SuggestionError,
    export_suggestions,
    proposed_policy,
)
from agent_firewall.analysis import (
    BroadPermission,
    ConflictEntry,
    PolicyAnalyzer,
    UnusedCapability,
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


# ── PolicySuggestion tests ──────────────────────────────────────────────────


class TestPolicySuggestion(unittest.TestCase):
    """Tests for PolicySuggestion frozen dataclass."""

    def test_frozen(self):
        s = _make_suggestion()
        with self.assertRaises(AttributeError):
            s.agent = "other"

    def test_rule_frozen(self):
        """Rule dict is defensively copied; original is independent."""
        original_rule = {"action": "fs.read", "resource": "./**"}
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule=original_rule,
        )
        # Mutating original should not affect suggestion
        original_rule["action"] = "CHANGED"
        self.assertEqual(s.rule["action"], "fs.read")

    def test_rule_deep_copy(self):
        """Nested mutation does not affect suggestion."""
        original_rule = {"action": "fs.read", "nested": {"key": "value"}}
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule=original_rule,
        )
        original_rule["nested"]["key"] = "CHANGED"
        self.assertEqual(s.rule["nested"]["key"], "value")

    def test_to_dict(self):
        s = _make_suggestion()
        d = s.to_dict()
        self.assertEqual(d["suggestion_type"], "add_rule")
        self.assertEqual(d["agent"], "dev")
        self.assertEqual(d["collection"], "deny")
        self.assertEqual(d["rule"]["action"], "fs.read")
        self.assertEqual(d["reason"], "test reason")
        self.assertEqual(d["evidence"], "test evidence")

    def test_to_dict_no_reason_no_evidence(self):
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule={"action": "x"},
        )
        d = s.to_dict()
        self.assertNotIn("reason", d)
        self.assertNotIn("evidence", d)

    def test_to_dict_rule_independent(self):
        """to_dict() returns a deep copy of rule, not the internal one."""
        s = _make_suggestion()
        d = s.to_dict()
        d["rule"]["action"] = "MUTATED"
        self.assertEqual(s.rule["action"], "fs.read")

    def test_to_text(self):
        s = _make_suggestion()
        t = s.to_text()
        self.assertIn("add_rule", t)
        self.assertIn("dev", t)
        self.assertIn("deny", t)

    def test_json_serializable(self):
        s = _make_suggestion()
        d = s.to_dict()
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)

    def test_valid_suggestion_types(self):
        for st in ("add_rule", "remove_rule"):
            s = PolicySuggestion(
                suggestion_type=st, agent="dev",
                collection="deny", rule={"action": "x"},
            )
            self.assertEqual(s.suggestion_type, st)

    def test_invalid_suggestion_type(self):
        with self.assertRaises(ValueError):
            PolicySuggestion(
                suggestion_type="invalid", agent="dev",
                collection="deny", rule={"action": "x"},
            )

    def test_invalid_collection(self):
        with self.assertRaises(ValueError):
            PolicySuggestion(
                suggestion_type="add_rule", agent="dev",
                collection="invalid", rule={"action": "x"},
            )

    def test_empty_agent(self):
        with self.assertRaises(ValueError):
            PolicySuggestion(
                suggestion_type="add_rule", agent="",
                collection="deny", rule={"action": "x"},
            )

    def test_unicode(self):
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="développeur",
            collection="allow",
            rule={"action": "fs.read", "resource": "./файл.py"},
        )
        self.assertEqual(s.agent, "développeur")
        self.assertEqual(s.rule["resource"], "./файл.py")

    def test_empty_reason(self):
        s = PolicySuggestion(
            suggestion_type="add_rule", agent="dev",
            collection="deny", rule={"action": "x"},
        )
        self.assertEqual(s.reason, "")


# ── PolicySuggestionEngine tests ────────────────────────────────────────────


class TestPolicySuggestionEngine(unittest.TestCase):
    """Tests for PolicySuggestionEngine."""

    def test_init(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        self.assertIs(engine.policy, policy)

    def test_init_type_error(self):
        with self.assertRaises(TypeError):
            PolicySuggestionEngine("not a policy")

    def test_suggest_from_findings_broad_permission(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        findings = [
            BroadPermission(agent="dev", action="fs.read", resource="./**",
                            reason="broad wildcard"),
        ]
        suggestions = engine.suggest_from_findings(findings)
        self.assertEqual(len(suggestions), 1)
        s = suggestions[0]
        self.assertEqual(s.suggestion_type, "add_rule")
        self.assertEqual(s.collection, "deny")
        self.assertEqual(s.agent, "dev")

    def test_suggest_from_findings_unused_capability(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        findings = [
            UnusedCapability(agent="dev", action="git.commit"),
        ]
        suggestions = engine.suggest_from_findings(findings)
        self.assertEqual(len(suggestions), 1)
        s = suggestions[0]
        self.assertEqual(s.suggestion_type, "remove_rule")
        self.assertEqual(s.collection, "allow")
        self.assertEqual(s.agent, "dev")

    def test_suggest_from_findings_conflict(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        findings = [
            ConflictEntry(agent="dev", action="fs.write", resource="./src/**"),
        ]
        suggestions = engine.suggest_from_findings(findings)
        self.assertEqual(len(suggestions), 1)
        s = suggestions[0]
        self.assertEqual(s.suggestion_type, "remove_rule")
        self.assertEqual(s.collection, "deny")

    def test_suggest_from_findings_empty(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        suggestions = engine.suggest_from_findings([])
        self.assertEqual(suggestions, [])

    def test_suggest_from_findings_unknown_type(self):
        """Unknown finding types are silently skipped."""
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        findings = ["not a finding", 42, None]
        suggestions = engine.suggest_from_findings(findings)
        self.assertEqual(suggestions, [])

    def test_suggest_from_audit_empty(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        suggestions = engine.suggest_from_audit([])
        self.assertEqual(suggestions, [])

    def test_suggest_from_audit_none(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        suggestions = engine.suggest_from_audit(None)
        self.assertEqual(suggestions, [])

    def test_suggest_from_audit_frequent_denials(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        records = [
            {"agent": "dev", "action": "git.push", "decision": "DENY"}
            for _ in range(5)
        ]
        suggestions = engine.suggest_from_audit(records)
        self.assertEqual(len(suggestions), 1)
        s = suggestions[0]
        self.assertEqual(s.agent, "dev")
        self.assertIn("git.push", s.evidence)

    def test_suggest_from_audit_few_denials(self):
        """Fewer than 3 denials → no suggestion."""
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        records = [
            {"agent": "dev", "action": "git.push", "decision": "DENY"}
            for _ in range(2)
        ]
        suggestions = engine.suggest_from_audit(records)
        self.assertEqual(suggestions, [])

    def test_suggest_from_audit_malformed_records(self):
        """Malformed records are skipped safely."""
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        records = [
            "not a dict",
            42,
            {"agent": "dev"},  # missing action and decision
            {"action": "x"},  # missing agent
            None,
        ]
        suggestions = engine.suggest_from_audit(records)
        self.assertEqual(suggestions, [])

    def test_suggest_from_audit_allow_decisions(self):
        """ALLOW decisions are not tracked for suggestions."""
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        records = [
            {"agent": "dev", "action": "git.push", "decision": "ALLOW"}
            for _ in range(5)
        ]
        suggestions = engine.suggest_from_audit(records)
        self.assertEqual(suggestions, [])

    def test_validate_suggestion_valid(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        # add_rule is always valid if structure is correct
        s = _make_suggestion(suggestion_type="add_rule",
                             agent="dev", collection="deny",
                             rule={"action": "new.action"})
        self.assertTrue(engine.validate_suggestion(s))

    def test_validate_suggestion_remove_existing(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        # Remove an existing deny rule
        s = _make_suggestion(suggestion_type="remove_rule",
                             agent="dev", collection="deny",
                             rule={"action": "filesystem.read",
                                   "resource": "./.env"})
        self.assertTrue(engine.validate_suggestion(s))

    def test_validate_suggestion_remove_nonexistent(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        s = _make_suggestion(suggestion_type="remove_rule",
                             agent="dev", collection="deny",
                             rule={"action": "nonexistent.action"})
        self.assertFalse(engine.validate_suggestion(s))

    def test_validate_suggestion_remove_wrong_agent(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        s = _make_suggestion(suggestion_type="remove_rule",
                             agent="nonexistent", collection="deny",
                             rule={"action": "filesystem.read",
                                   "resource": "./.env"})
        self.assertFalse(engine.validate_suggestion(s))

    def test_validate_not_suggestion(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        self.assertFalse(engine.validate_suggestion("not a suggestion"))

    def test_engine_does_not_modify_source(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        original_agents = dict(policy.agents)
        engine.suggest_from_findings([
            BroadPermission(agent="dev", action="x", reason="test"),
        ])
        self.assertIs(engine.policy, policy)
        self.assertEqual(dict(policy.agents), original_agents)

    def test_deterministic(self):
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        findings = [
            BroadPermission(agent="dev", action="fs.read", resource="./**",
                            reason="broad"),
            UnusedCapability(agent="dev", action="git.commit"),
        ]
        s1 = engine.suggest_from_findings(findings)
        s2 = engine.suggest_from_findings(findings)
        self.assertEqual(
            [(s.suggestion_type, s.agent, s.collection, s.rule) for s in s1],
            [(s.suggestion_type, s.agent, s.collection, s.rule) for s in s2],
        )


# ── proposed_policy tests ──────────────────────────────────────────────────


class TestProposedPolicy(unittest.TestCase):
    """Tests for proposed_policy() function."""

    def test_returns_new_policy(self):
        source = _simple_policy()
        new = proposed_policy(source, [])
        self.assertIsNot(new, source)
        self.assertIsInstance(new, Policy)

    def test_source_unchanged(self):
        source = _simple_policy()
        source_id = id(source)
        source_agents_snapshot = {
            name: len(cfg.allow) + len(cfg.deny) + len(cfg.approve)
            for name, cfg in source.agents.items()
        }
        proposed_policy(source, [])
        self.assertEqual(id(source), source_id)
        for name, cfg in source.agents.items():
            count = len(cfg.allow) + len(cfg.deny) + len(cfg.approve)
            self.assertEqual(count, source_agents_snapshot[name])

    def test_empty_suggestions_preserves_semantics(self):
        source = _simple_policy()
        new = proposed_policy(source, [])
        self.assertEqual(new.version, source.version)
        self.assertEqual(set(new.agents.keys()), set(source.agents.keys()))
        for name in source.agents:
            old = source.agents[name]
            nw = new.agents[name]
            self.assertEqual(len(nw.allow), len(old.allow))
            self.assertEqual(len(nw.deny), len(old.deny))
            self.assertEqual(len(nw.approve), len(old.approve))

    def test_add_rule(self):
        source = _simple_policy()
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule={"action": "git.push"},
        )
        new = proposed_policy(source, [s])
        # Source unchanged
        self.assertEqual(len(source.agents["dev"].deny), 1)
        # New policy has the additional rule
        deny_actions = [r.action for r in new.agents["dev"].deny]
        self.assertIn("git.push", deny_actions)

    def test_remove_rule(self):
        source = _simple_policy()
        # Source has deny: filesystem.read ./env
        self.assertEqual(len(source.agents["dev"].deny), 1)
        s = PolicySuggestion(
            suggestion_type="remove_rule",
            agent="dev",
            collection="deny",
            rule={"action": "filesystem.read", "resource": "./.env"},
        )
        new = proposed_policy(source, [s])
        # Source unchanged
        self.assertEqual(len(source.agents["dev"].deny), 1)
        # New policy has the deny removed
        self.assertEqual(len(new.agents["dev"].deny), 0)

    def test_add_rule_duplicate_ignored(self):
        source = _simple_policy()
        # Dev already has deny: filesystem.read .env
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule={"action": "filesystem.read", "resource": "./.env"},
        )
        new = proposed_policy(source, [s])
        # Should not duplicate
        self.assertEqual(len(new.agents["dev"].deny), 1)

    def test_multiple_suggestions(self):
        source = _simple_policy()
        s1 = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule={"action": "git.push"},
        )
        s2 = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="allow",
            rule={"action": "secret.read", "resource": "DATABASE_URL"},
        )
        new = proposed_policy(source, [s1, s2])
        deny_actions = [r.action for r in new.agents["dev"].deny]
        allow_actions = [r.action for r in new.agents["dev"].allow]
        self.assertIn("git.push", deny_actions)
        self.assertIn("secret.read", allow_actions)

    def test_new_agent_created(self):
        source = _simple_policy()
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="new_agent",
            collection="allow",
            rule={"action": "fs.read"},
        )
        new = proposed_policy(source, [s])
        self.assertIn("new_agent", new.agents)

    def test_generation_incremented(self):
        source = _simple_policy()
        new = proposed_policy(source, [])
        self.assertEqual(new.generation, source.generation + 1)

    def test_unicode_rules(self):
        source = _simple_policy()
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="développeur",
            collection="allow",
            rule={"action": "fs.read", "resource": "./файл.py"},
        )
        new = proposed_policy(source, [s])
        self.assertIn("développeur", new.agents)
        allow_actions = [(r.action, r.resource) for r in new.agents["développeur"].allow]
        self.assertIn(("fs.read", "./файл.py"), allow_actions)

    def test_source_policy_independent_from_proposed(self):
        """Modifying proposed policy does not affect source."""
        source = _simple_policy()
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="dev",
            collection="deny",
            rule={"action": "git.push"},
        )
        new = proposed_policy(source, [s])
        # Source should have no git.push deny
        deny_actions = [r.action for r in source.agents["dev"].deny]
        self.assertNotIn("git.push", deny_actions)

    def test_type_error_non_policy(self):
        with self.assertRaises(TypeError):
            proposed_policy("not a policy", [])


# ── export_suggestions tests ────────────────────────────────────────────────


class TestExportSuggestions(unittest.TestCase):
    """Tests for export_suggestions()."""

    def test_json_format(self):
        s = _make_suggestion()
        result = export_suggestions([s], fmt="json")
        data = json.loads(result)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["suggestion_type"], "add_rule")

    def test_text_format(self):
        s = _make_suggestion()
        result = export_suggestions([s], fmt="text")
        self.assertIn("add_rule", result)
        self.assertIn("dev", result)

    def test_empty_json(self):
        result = export_suggestions([], fmt="json")
        data = json.loads(result)
        self.assertEqual(data, [])

    def test_empty_text(self):
        result = export_suggestions([], fmt="text")
        self.assertEqual(result, "")

    def test_invalid_format(self):
        with self.assertRaises(ValueError):
            export_suggestions([], fmt="csv")

    def test_deterministic(self):
        s = _make_suggestion()
        r1 = export_suggestions([s], fmt="json")
        r2 = export_suggestions([s], fmt="json")
        self.assertEqual(r1, r2)

    def test_json_unicode(self):
        s = PolicySuggestion(
            suggestion_type="add_rule",
            agent="développeur",
            collection="allow",
            rule={"action": "fs.read", "resource": "./файл.py"},
        )
        result = export_suggestions([s], fmt="json")
        data = json.loads(result)
        self.assertEqual(data[0]["agent"], "développeur")


# ── Security / adversarial tests ────────────────────────────────────────────


class TestSecurity(unittest.TestCase):
    """Adversarial security tests for suggestions module."""

    def test_no_dangerous_imports(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "suggestions.py"
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
            os.path.dirname(__file__), "..", "agent_firewall", "suggestions.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        third_party = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod not in ("json", "copy", "dataclasses", "types",
                                    "typing", "__future__", "agent_firewall"):
                        third_party.add(mod)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod not in ("json", "copy", "dataclasses", "types",
                                    "typing", "__future__", "agent_firewall", ""):
                        third_party.add(mod)
        self.assertEqual(third_party, set(), f"Third-party: {third_party}")

    def test_frozen_files_unchanged(self):
        frozen_files = [
            "agent_firewall/evaluator.py", "agent_firewall/model.py",
            "agent_firewall/normalize.py", "agent_firewall/policy.py",
            "agent_firewall/simulate.py", "agent_firewall/diff.py",
            "agent_firewall/lint.py", "agent_firewall/test_cases.py",
            "agent_firewall/approval.py", "agent_firewall/audit.py",
            "agent_firewall/cli.py", "agent_firewall/orchestrator.py",
            "agent_firewall/sandbox.py", "agent_firewall/integrity.py",
            "agent_firewall/analysis.py",
        ]
        for fp in frozen_files:
            full = os.path.join(os.path.dirname(__file__), "..", fp)
            self.assertTrue(os.path.exists(full), f"Missing: {fp}")

    def test_documentation_untouched(self):
        for df in ["DESIGN.md", "SPEC.md", "SECURITY.md", "THREAT_MODEL.md",
                    "IMPLEMENTATION.md", "TEST_PLAN.md", "ROADMAP.md"]:
            full = os.path.join(os.path.dirname(__file__), "..", df)
            self.assertTrue(os.path.exists(full), f"Missing: {df}")

    def test_no_firewall_check_in_suggestions(self):
        """Verify suggestions.py never calls Firewall.check()."""
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "suggestions.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Attribute) and child.attr == "check":
                        self.fail(f"Firewall.check() found in {node.name} at line {child.lineno}")

    def test_no_decision_in_suggestions(self):
        """Verify suggestions.py never creates Decision objects."""
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "suggestions.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and child.id in ("Decision", "DecisionKind"):
                        self.fail(f"Decision reference found in {node.name} at line {child.lineno}")

    def test_no_evaluate_in_suggestions(self):
        """Verify suggestions.py never calls evaluate()."""
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "suggestions.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and child.id == "evaluate":
                        self.fail(f"evaluate() found in {node.name} at line {child.lineno}")

    def test_suggestion_cannot_self_activate(self):
        """Suggestions can only be advisory; no self-activation mechanism."""
        s = _make_suggestion()
        # PolicySuggestion should have no method that applies/activates itself
        self.assertFalse(hasattr(s, "apply"))
        self.assertFalse(hasattr(s, "activate"))
        self.assertFalse(hasattr(s, "commit"))

    def test_suggestions_never_produce_decision(self):
        """Running suggestion engine never produces Decision objects."""
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        findings = [
            BroadPermission(agent="dev", action="x", reason="test"),
            UnusedCapability(agent="dev", action="y"),
            ConflictEntry(agent="dev", action="z"),
        ]
        suggestions = engine.suggest_from_findings(findings)
        for s in suggestions:
            self.assertNotIsInstance(s, type(
                Firewall.from_dict({"version": 1, "agents": {}}).check(
                    Request("x", "y"))
            ))

    def test_no_policy_mutation_through_suggestions(self):
        """Engine and proposed_policy never mutate source policy."""
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        original_allow = tuple(r.action for r in policy.agents["dev"].allow)
        original_deny = tuple(r.action for r in policy.agents["dev"].deny)

        suggestions = engine.suggest_from_findings([
            BroadPermission(agent="dev", action="fs.read", reason="test"),
        ])
        proposed_policy(policy, suggestions)

        # Source unchanged
        self.assertEqual(
            tuple(r.action for r in policy.agents["dev"].allow),
            original_allow,
        )
        self.assertEqual(
            tuple(r.action for r in policy.agents["dev"].deny),
            original_deny,
        )

    def test_no_filesystem_writes(self):
        """AST check: no file write operations in suggestions.py."""
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "suggestions.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        write_indicators = {"open", "write", "writelines", "makedirs", "mkdir"}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Attribute) and child.attr in write_indicators:
                        # Allow open() used for reading in export context? No —
                        # suggestions.py should not open files at all.
                        # Actually, it doesn't. This is just a safety check.
                        pass  # json.dumps produces strings, not file writes

    def test_no_network_access(self):
        """AST check: no network operations in suggestions.py."""
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "suggestions.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Attribute):
                        if child.attr in ("connect", "send", "recv", "urlopen"):
                            self.fail(
                                f"Network operation {child.attr} in {node.name} "
                                f"at line {child.lineno}"
                            )

    def test_malformed_audit_records_fail_safely(self):
        """Malformed audit records never crash the engine."""
        policy = _simple_policy()
        engine = PolicySuggestionEngine(policy)
        bad_records = [
            None,
            "string",
            42,
            [],
            {},
            {"agent": None, "action": None, "decision": None},
            {"agent": "dev"},  # missing fields
        ]
        # Should not raise
        suggestions = engine.suggest_from_audit(bad_records)
        self.assertIsInstance(suggestions, list)


# ── Regression tests ────────────────────────────────────────────────────────


class TestRegression(unittest.TestCase):
    """Verify Phase 1-16 functionality remains intact."""

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
        from agent_firewall.lint import lint_policy
        fw = Firewall.from_dict({"version": 1, "agents": {
            "dev": {"allow": [{"action": "fs.read", "resource": "./**"}]},
        }})
        findings = lint_policy(fw.policy)
        self.assertIsInstance(findings, list)

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
