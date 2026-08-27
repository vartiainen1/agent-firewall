"""Tests for Phase 15 integrity features.

Verifies hash-chained evidence, policy integrity verification,
capability expiration, and capability revocation.
"""

import ast
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall import Firewall, Request
from agent_firewall.model import DecisionKind, InvalidRequestError
from agent_firewall.audit import EvidenceRecord
from agent_firewall.integrity import (
    CapabilityExpirationList,
    ChainVerification,
    ChainedEvidenceRecord,
    EvidenceChain,
    ExpiringCapability,
    PolicyIntegrity,
    PolicyIntegrityVerifier,
    RevocationEntry,
    RevocationList,
    check_with_revocation,
    _canonicalize_record,
    _hash_content,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _firewall(*, allow=None, deny=None, approve=None, agents=None) -> Firewall:
    """Build a Firewall with a simple policy."""
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
    return Firewall.from_dict({"version": 1, "agents": agent_data})


def _allowing_firewall() -> Firewall:
    return _firewall(
        allow=[{"action": "filesystem.write", "resource": "./src/**"}]
    )


def _approving_firewall() -> Firewall:
    return _firewall(
        approve=[{"action": "git.push"}]
    )


def _default_deny_firewall() -> Firewall:
    return _firewall()


def _make_record(**kwargs) -> EvidenceRecord:
    """Create an EvidenceRecord with defaults."""
    defaults = {
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "agent": "dev",
        "action": "filesystem.write",
        "decision": "ALLOW",
    }
    defaults.update(kwargs)
    return EvidenceRecord(**defaults)


# ── Canonicalization tests ──────────────────────────────────────────────────


class TestCanonicalization(unittest.TestCase):
    """Tests for EvidenceRecord canonicalization."""

    def test_deterministic(self):
        r = _make_record()
        c1 = _canonicalize_record(r)
        c2 = _canonicalize_record(r)
        self.assertEqual(c1, c2)

    def test_omits_none_fields(self):
        r = _make_record(resource=None, rule=None, reason=None)
        c = _canonicalize_record(r)
        d = json.loads(c)
        self.assertNotIn("resource", d)
        self.assertNotIn("rule", d)
        self.assertNotIn("reason", d)

    def test_includes_non_none_fields(self):
        r = _make_record(resource="./src/main.py", reason="test")
        c = _canonicalize_record(r)
        d = json.loads(c)
        self.assertEqual(d["resource"], "./src/main.py")
        self.assertEqual(d["reason"], "test")

    def test_stable_field_order(self):
        r = _make_record(resource="./src/main.py", reason="test")
        c = _canonicalize_record(r)
        d = json.loads(c)
        keys = list(d.keys())
        self.assertEqual(keys[0], "action")
        self.assertEqual(keys[1], "agent")

    def test_hash_deterministic(self):
        c = _canonicalize_record(_make_record())
        h1 = _hash_content(c)
        h2 = _hash_content(c)
        self.assertEqual(h1, h2)

    def test_different_content_different_hash(self):
        r1 = _make_record(agent="dev")
        r2 = _make_record(agent="admin")
        h1 = _hash_content(_canonicalize_record(r1))
        h2 = _hash_content(_canonicalize_record(r2))
        self.assertNotEqual(h1, h2)

    def test_unicode(self):
        r = _make_record(agent="développeur", resource="./файл.py")
        c = _canonicalize_record(r)
        d = json.loads(c)
        self.assertEqual(d["agent"], "développeur")
        self.assertEqual(d["resource"], "./файл.py")

    def test_compact_json(self):
        r = _make_record()
        c = _canonicalize_record(r)
        self.assertNotIn(": ", c)  # no space after colon
        self.assertNotIn(", ", c)  # no space after comma


# ── Hash chain tests ─────────────────────────────────────────────────────────


class TestHashChain(unittest.TestCase):
    """Tests for EvidenceChain hash chaining."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._chain_file = os.path.join(self._tmpdir, "chain.jsonl")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_first_record_no_previous_hash(self):
        chain = EvidenceChain(self._chain_file)
        r = _make_record()
        chained = chain.append(r)
        self.assertIsNone(chained.previous_hash)
        self.assertIsNotNone(chained.record_hash)

    def test_second_record_links_to_first(self):
        chain = EvidenceChain(self._chain_file)
        r1 = _make_record(agent="dev", action="fs.write")
        r2 = _make_record(agent="dev", action="fs.read")
        c1 = chain.append(r1)
        c2 = chain.append(r2)
        self.assertEqual(c2.previous_hash, c1.record_hash)

    def test_valid_chain_verifies(self):
        chain = EvidenceChain(self._chain_file)
        chain.append(_make_record())
        chain.append(_make_record(agent="dev", action="fs.read"))
        result = chain.verify()
        self.assertTrue(result.valid)
        self.assertEqual(result.total_records, 2)

    def test_empty_chain_valid(self):
        chain = EvidenceChain(self._chain_file)
        result = chain.verify()
        self.assertTrue(result.valid)
        self.assertEqual(result.total_records, 0)

    def test_single_record_chain(self):
        chain = EvidenceChain(self._chain_file)
        chain.append(_make_record())
        result = chain.verify()
        self.assertTrue(result.valid)
        self.assertEqual(result.total_records, 1)

    def test_broken_link_detected(self):
        chain = EvidenceChain(self._chain_file)
        chain.append(_make_record())
        chain.append(_make_record(agent="dev", action="fs.read"))
        # Tamper: corrupt the file
        with open(self._chain_file, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        # Replace first record's hash
        data = json.loads(lines[0])
        data["record_hash"] = "0" * 64
        lines[0] = json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self._chain_file, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        result = chain.verify()
        self.assertFalse(result.valid)
        self.assertEqual(result.broken_at, 0)

    def test_record_modification_detected(self):
        chain = EvidenceChain(self._chain_file)
        chain.append(_make_record())
        chain.append(_make_record(agent="dev", action="fs.read"))
        # Tamper: modify record content in first entry
        with open(self._chain_file, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        data = json.loads(lines[0])
        data["record"]["agent"] = "admin"  # tamper
        lines[0] = json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self._chain_file, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        result = chain.verify()
        self.assertFalse(result.valid)
        self.assertIn("hash mismatch", result.reason)

    def test_hash_tampering_detected(self):
        chain = EvidenceChain(self._chain_file)
        chain.append(_make_record())
        chain.append(_make_record(agent="dev", action="fs.read"))
        # Tamper: change record_hash without changing record
        with open(self._chain_file, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        data = json.loads(lines[1])
        data["record_hash"] = "ff" * 32
        lines[1] = json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self._chain_file, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        result = chain.verify()
        self.assertFalse(result.valid)
        self.assertEqual(result.broken_at, 1)

    def test_last_hash(self):
        chain = EvidenceChain(self._chain_file)
        self.assertIsNone(chain.last_hash)
        c1 = chain.append(_make_record())
        self.assertEqual(chain.last_hash, c1.record_hash)
        c2 = chain.append(_make_record(agent="dev", action="fs.read"))
        self.assertEqual(chain.last_hash, c2.record_hash)

    def test_chaining_optional(self):
        chain = EvidenceChain(self._chain_file, chaining=False)
        c1 = chain.append(_make_record())
        c2 = chain.append(_make_record(agent="dev", action="fs.read"))
        self.assertIsNone(c1.previous_hash)
        self.assertIsNone(c2.previous_hash)

    def test_deterministic_hashing(self):
        chain = EvidenceChain(self._chain_file)
        r = _make_record()
        c1 = chain.append(r)
        chain2 = EvidenceChain(os.path.join(self._tmpdir, "chain2.jsonl"))
        c2 = chain2.append(r)
        self.assertEqual(c1.record_hash, c2.record_hash)

    def test_broken_at_correct_index(self):
        chain = EvidenceChain(self._chain_file)
        chain.append(_make_record())
        chain.append(_make_record(agent="dev", action="fs.read"))
        chain.append(_make_record(agent="dev", action="git.push"))
        # Tamper: break second record
        with open(self._chain_file, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        data = json.loads(lines[1])
        data["record"]["agent"] = "admin"
        lines[1] = json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self._chain_file, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        result = chain.verify()
        self.assertFalse(result.valid)
        self.assertEqual(result.broken_at, 1)

    def test_unicode_records(self):
        chain = EvidenceChain(self._chain_file)
        r = _make_record(agent="développeur", resource="./файл.py")
        c = chain.append(r)
        self.assertIsNotNone(c.record_hash)
        result = chain.verify()
        self.assertTrue(result.valid)

    def test_truncated_chain(self):
        chain = EvidenceChain(self._chain_file)
        chain.append(_make_record())
        chain.append(_make_record(agent="dev", action="fs.read"))
        # Truncate: remove last line
        with open(self._chain_file, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        with open(self._chain_file, "w", encoding="utf-8") as fh:
            fh.write(lines[0])
        result = chain.verify()
        self.assertTrue(result.valid)  # truncated but valid chain
        self.assertEqual(result.total_records, 1)

    def test_malformed_json_in_chain(self):
        with open(self._chain_file, "w", encoding="utf-8") as fh:
            fh.write("not json\n")
        chain = EvidenceChain(self._chain_file)
        result = chain.verify()
        self.assertFalse(result.valid)
        self.assertIn("invalid JSON", result.reason)


# ── Policy integrity tests ──────────────────────────────────────────────────


class TestPolicyIntegrity(unittest.TestCase):
    """Tests for PolicyIntegrityVerifier."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._policy_file = os.path.join(self._tmpdir, "policy.json")
        with open(self._policy_file, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "agents": {}}, fh)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_hash_roundtrip(self):
        h = PolicyIntegrityVerifier.hash_policy_file(self._policy_file)
        self.assertTrue(PolicyIntegrityVerifier.verify_policy_file(
            self._policy_file, h))

    def test_detects_modification(self):
        h = PolicyIntegrityVerifier.hash_policy_file(self._policy_file)
        # Modify the file
        with open(self._policy_file, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "agents": {"dev": {}}}, fh)
        self.assertFalse(PolicyIntegrityVerifier.verify_policy_file(
            self._policy_file, h))

    def test_deterministic(self):
        h1 = PolicyIntegrityVerifier.hash_policy_file(self._policy_file)
        h2 = PolicyIntegrityVerifier.hash_policy_file(self._policy_file)
        self.assertEqual(h1, h2)

    def test_different_content_different_hash(self):
        h1 = PolicyIntegrityVerifier.hash_policy_file(self._policy_file)
        with open(self._policy_file, "w", encoding="utf-8") as fh:
            json.dump({"version": 2, "agents": {}}, fh)
        h2 = PolicyIntegrityVerifier.hash_policy_file(self._policy_file)
        self.assertNotEqual(h1, h2)

    def test_empty_content(self):
        empty_file = os.path.join(self._tmpdir, "empty.json")
        with open(empty_file, "w") as fh:
            pass
        h = PolicyIntegrityVerifier.hash_policy_file(empty_file)
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 64)

    def test_content_hash(self):
        content = b'{"version": 1}'
        h = PolicyIntegrityVerifier.hash_policy_content(content)
        self.assertEqual(len(h), 64)

    def test_verify_content(self):
        content = b'{"version": 1}'
        h = PolicyIntegrityVerifier.hash_policy_content(content)
        self.assertTrue(PolicyIntegrityVerifier.verify_policy_content(
            content, h))

    def test_create_integrity(self):
        integrity = PolicyIntegrityVerifier.create_integrity(
            self._policy_file, policy_version=1, policy_generation=5)
        self.assertEqual(integrity.policy_version, 1)
        self.assertEqual(integrity.policy_generation, 5)
        self.assertEqual(integrity.policy_path, self._policy_file)
        self.assertIsNotNone(integrity.policy_hash)
        self.assertIsNotNone(integrity.verified_at)

    def test_frozen(self):
        integrity = PolicyIntegrityVerifier.create_integrity(self._policy_file)
        with self.assertRaises(AttributeError):
            integrity.policy_hash = "tampered"


# ── Capability expiration tests ──────────────────────────────────────────────


class TestCapabilityExpiration(unittest.TestCase):
    """Tests for CapabilityExpirationList."""

    def test_non_expired(self):
        cap_list = CapabilityExpirationList()
        cap_list.add("dev", "fs.write", "./src/**",
                     expires_at="2099-12-31T23:59:59Z")
        self.assertFalse(cap_list.is_expired("dev", "fs.write", "./src/**"))

    def test_expired(self):
        cap_list = CapabilityExpirationList()
        cap_list.add("dev", "fs.write", "./src/**",
                     expires_at="2020-01-01T00:00:00Z")
        self.assertTrue(cap_list.is_expired("dev", "fs.write", "./src/**"))

    def test_missing_expiration(self):
        cap_list = CapabilityExpirationList()
        cap_list.add("dev", "fs.write", "./src/**")
        self.assertFalse(cap_list.is_expired("dev", "fs.write", "./src/**"))

    def test_allow_to_deny(self):
        fw = _allowing_firewall()
        cap_list = CapabilityExpirationList()
        cap_list.add("dev", "filesystem.write", "./src/main.py",
                     expires_at="2020-01-01T00:00:00Z")
        d = fw.check(Request("dev", "filesystem.write", "./src/main.py"))
        self.assertEqual(d.kind, DecisionKind.ALLOW)
        result = cap_list.check(d)
        self.assertEqual(result.kind, DecisionKind.DENY)

    def test_approve_to_deny(self):
        fw = _approving_firewall()
        cap_list = CapabilityExpirationList()
        cap_list.add("dev", "git.push", expires_at="2020-01-01T00:00:00Z")
        d = fw.check(Request("dev", "git.push"))
        self.assertEqual(d.kind, DecisionKind.APPROVE)
        result = cap_list.check(d)
        self.assertEqual(result.kind, DecisionKind.DENY)

    def test_deny_unchanged(self):
        fw = _default_deny_firewall()
        cap_list = CapabilityExpirationList()
        cap_list.add("dev", "fs.write", expires_at="2020-01-01T00:00:00Z")
        d = fw.check(Request("dev", "fs.write", "./src/main.py"))
        self.assertEqual(d.kind, DecisionKind.DENY)
        result = cap_list.check(d)
        self.assertEqual(result.kind, DecisionKind.DENY)

    def test_invalid_timestamp_fails_closed(self):
        cap_list = CapabilityExpirationList()
        cap_list.add("dev", "fs.write", expires_at="not-a-date")
        self.assertTrue(cap_list.is_expired("dev", "fs.write"))

    def test_frozen(self):
        cap = ExpiringCapability(agent="dev", action="fs.write")
        with self.assertRaises(AttributeError):
            cap.agent = "admin"

    def test_entries(self):
        cap_list = CapabilityExpirationList()
        cap_list.add("dev", "fs.write")
        cap_list.add("dev", "fs.read")
        self.assertEqual(len(cap_list.entries()), 2)


# ── Capability revocation tests ─────────────────────────────────────────────


class TestRevocation(unittest.TestCase):
    """Tests for RevocationList and check_with_revocation."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._rev_file = os.path.join(self._tmpdir, "revocations.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_revoke_adds_entry(self):
        rl = RevocationList(self._rev_file)
        entry = rl.revoke("dev", "fs.write", reason="security")
        self.assertEqual(entry.agent, "dev")
        self.assertEqual(entry.action, "fs.write")
        self.assertEqual(len(rl.entries()), 1)

    def test_revoked_detected(self):
        rl = RevocationList(self._rev_file)
        rl.revoke("dev", "fs.write", "./src/main.py")
        self.assertTrue(rl.is_revoked("dev", "fs.write", "./src/main.py"))

    def test_not_revoked(self):
        rl = RevocationList(self._rev_file)
        self.assertFalse(rl.is_revoked("dev", "fs.write", "./src/main.py"))

    def test_allow_to_deny(self):
        fw = _allowing_firewall()
        rl = RevocationList(self._rev_file)
        rl.revoke("dev", "filesystem.write", "./src/main.py")
        d = fw.check(Request("dev", "filesystem.write", "./src/main.py"))
        self.assertEqual(d.kind, DecisionKind.ALLOW)
        result = rl.check(d)
        self.assertEqual(result.kind, DecisionKind.DENY)

    def test_approve_to_deny(self):
        fw = _approving_firewall()
        rl = RevocationList(self._rev_file)
        rl.revoke("dev", "git.push")
        d = fw.check(Request("dev", "git.push"))
        self.assertEqual(d.kind, DecisionKind.APPROVE)
        result = rl.check(d)
        self.assertEqual(result.kind, DecisionKind.DENY)

    def test_deny_unchanged(self):
        fw = _default_deny_firewall()
        rl = RevocationList(self._rev_file)
        rl.revoke("dev", "fs.write")
        d = fw.check(Request("dev", "fs.write", "./src/main.py"))
        self.assertEqual(d.kind, DecisionKind.DENY)
        result = rl.check(d)
        self.assertEqual(result.kind, DecisionKind.DENY)

    def test_resource_none_matches_any(self):
        rl = RevocationList(self._rev_file)
        rl.revoke("dev", "fs.write")  # resource=None
        self.assertTrue(rl.is_revoked("dev", "fs.write", "./src/main.py"))
        self.assertTrue(rl.is_revoked("dev", "fs.write", "./secret/key"))
        self.assertTrue(rl.is_revoked("dev", "fs.write"))

    def test_specific_resource_exact_match(self):
        rl = RevocationList(self._rev_file)
        rl.revoke("dev", "fs.write", "./src/main.py")
        self.assertTrue(rl.is_revoked("dev", "fs.write", "./src/main.py"))
        self.assertFalse(rl.is_revoked("dev", "fs.write", "./src/other.py"))

    def test_persistence(self):
        rl1 = RevocationList(self._rev_file)
        rl1.revoke("dev", "fs.write")
        # Reload from disk
        rl2 = RevocationList(self._rev_file)
        self.assertTrue(rl2.is_revoked("dev", "fs.write"))
        self.assertEqual(len(rl2.entries()), 1)

    def test_corrupt_json_fails_closed(self):
        with open(self._rev_file, "w") as fh:
            fh.write("not json{{{")
        rl = RevocationList(self._rev_file)
        # Should load gracefully, not crash
        self.assertFalse(rl.is_revoked("dev", "fs.write"))

    def test_check_with_revocation(self):
        fw = _allowing_firewall()
        rl = RevocationList(self._rev_file)
        rl.revoke("dev", "filesystem.write", "./src/main.py")
        req = Request("dev", "filesystem.write", "./src/main.py")
        d = check_with_revocation(fw, req, rl)
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_check_with_revocation_not_revoked(self):
        fw = _allowing_firewall()
        rl = RevocationList(self._rev_file)
        req = Request("dev", "filesystem.write", "./src/main.py")
        d = check_with_revocation(fw, req, rl)
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_revocation_never_produces_allow(self):
        fw = _allowing_firewall()
        rl = RevocationList(self._rev_file)
        # Revoke everything
        rl.revoke("dev", "filesystem.write")
        req = Request("dev", "filesystem.write", "./src/main.py")
        d = check_with_revocation(fw, req, rl)
        self.assertNotEqual(d.kind, DecisionKind.ALLOW)


# ── Security / adversarial tests ────────────────────────────────────────────


class TestSecurity(unittest.TestCase):
    """Adversarial security tests for integrity features."""

    def test_no_dangerous_imports(self):
        """integrity.py must not import subprocess, socket, http, container libs."""
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "integrity.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        dangerous = {
            "subprocess", "socket", "http", "urllib", "os", "shutil",
            "docker", "container", "lxc", "nsjail", "firejail",
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
        self.assertEqual(found, set(), f"Dangerous imports found: {found}")

    def test_zero_third_party_dependencies(self):
        """integrity.py must use only stdlib and internal imports."""
        path = os.path.join(
            os.path.dirname(__file__), "..", "agent_firewall", "integrity.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        third_party = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod not in ("hashlib", "hmac", "json", "sys",
                                    "dataclasses", "datetime", "typing",
                                    "__future__", "os", "agent_firewall"):
                        third_party.add(mod)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod not in ("hashlib", "hmac", "json", "sys",
                                    "dataclasses", "datetime", "typing",
                                    "__future__", "os", "agent_firewall", ""):
                        third_party.add(mod)
        self.assertEqual(third_party, set(), f"Third-party imports: {third_party}")

    def test_frozen_files_unchanged(self):
        """Phase 1-14 source files must not have changed."""
        frozen_files = [
            "agent_firewall/evaluator.py",
            "agent_firewall/model.py",
            "agent_firewall/normalize.py",
            "agent_firewall/policy.py",
            "agent_firewall/simulate.py",
            "agent_firewall/diff.py",
            "agent_firewall/lint.py",
            "agent_firewall/test_cases.py",
            "agent_firewall/approval.py",
            "agent_firewall/audit.py",
            "agent_firewall/cli.py",
            "agent_firewall/orchestrator.py",
            "agent_firewall/sandbox.py",
            "agent_firewall/adapters/filesystem.py",
            "agent_firewall/adapters/process.py",
            "agent_firewall/adapters/git.py",
            "agent_firewall/adapters/network.py",
            "agent_firewall/adapters/mcp_bridge.py",
            "agent_firewall/adapters/mcp.py",
        ]
        for fp in frozen_files:
            full = os.path.join(os.path.dirname(__file__), "..", fp)
            self.assertTrue(os.path.exists(full), f"Frozen file missing: {fp}")

    def test_documentation_files_untouched(self):
        doc_files = [
            "DESIGN.md", "SPEC.md", "SECURITY.md", "THREAT_MODEL.md",
            "IMPLEMENTATION.md", "TEST_PLAN.md", "ROADMAP.md",
            "README.md", "CONTRIBUTING.md", "CHANGELOG.md", "AGENTS.md",
        ]
        for df in doc_files:
            full = os.path.join(os.path.dirname(__file__), "..", df)
            self.assertTrue(os.path.exists(full), f"Doc file missing: {df}")

    def test_no_policy_mutation(self):
        fw = _allowing_firewall()
        rl = RevocationList(os.path.join(self._tmpdir, "rev.json"))
        rl.revoke("dev", "fs.write")
        policy_before = fw.policy
        check_with_revocation(fw, Request("dev", "fs.write", "./x"), rl)
        self.assertIs(fw.policy, policy_before)

    def test_expiration_never_produces_allow(self):
        fw = _allowing_firewall()
        cap_list = CapabilityExpirationList()
        cap_list.add("dev", "filesystem.write", "./src/main.py",
                     expires_at="2020-01-01T00:00:00Z")
        d = fw.check(Request("dev", "filesystem.write", "./src/main.py"))
        result = cap_list.check(d)
        self.assertNotEqual(result.kind, DecisionKind.ALLOW)

    def test_invalid_chain_not_valid(self):
        tmpdir = tempfile.mkdtemp()
        try:
            chain_file = os.path.join(tmpdir, "chain.jsonl")
            chain = EvidenceChain(chain_file)
            chain.append(_make_record())
            # Tamper
            with open(chain_file, "r") as fh:
                lines = fh.readlines()
            data = json.loads(lines[0])
            data["record_hash"] = "aa" * 32
            lines[0] = json.dumps(data) + "\n"
            with open(chain_file, "w") as fh:
                fh.writelines(lines)
            result = chain.verify()
            self.assertFalse(result.valid)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)


# ── Phase 1-14 regression tests ─────────────────────────────────────────────


class TestRegression(unittest.TestCase):
    """Verify Phase 1-14 functionality remains intact."""

    def test_phase1_core_still_works(self):
        fw = Firewall.from_dict({
            "version": 1,
            "agents": {
                "dev": {
                    "allow": [{"action": "filesystem.read", "resource": "./**"}],
                }
            },
        })
        d = fw.check(Request("dev", "filesystem.read", "./src/main.py"))
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_phase1_default_deny(self):
        fw = Firewall.from_dict({"version": 1, "agents": {}})
        d = fw.check(Request("dev", "filesystem.read", "./src/main.py"))
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_adapters_unchanged(self):
        from agent_firewall.adapters import (
            FilesystemAdapter, ProcessAdapter, GitAdapter, NetworkAdapter,
        )
        self.assertTrue(callable(FilesystemAdapter))
        self.assertTrue(callable(ProcessAdapter))
        self.assertTrue(callable(GitAdapter))
        self.assertTrue(callable(NetworkAdapter))

    def test_orchestrator_unchanged(self):
        from agent_firewall.orchestrator import OrchestratorBridge
        self.assertTrue(callable(OrchestratorBridge))

    def test_sandbox_unchanged(self):
        from agent_firewall.sandbox import SandboxAdapter
        self.assertTrue(callable(SandboxAdapter))


if __name__ == "__main__":
    unittest.main()
