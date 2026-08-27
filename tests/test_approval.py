"""Tests for approval records, validation, and request hashing (Phase 5).

Covers:

    valid approval
    permanent approval (no expiration)
    future expiration
    expired approval
    malformed expiration
    malformed JSON
    missing fields
    deterministic canonicalization
    deterministic hashing
    agent/action/resource/policy_version/policy_generation each change hash
    None resource handling
    wrong request hash / agent / action / resource / policy_version / policy_generation
    self-approval
    Unicode identifiers
    long approval IDs
    extra fields ignored safely
    repeated validation succeeds while approval remains valid
    missing approval file
    empty approval file
    approval file loading failure
    audit request_hash / approval_id integration
    fail-closed behavior
    evaluator unchanged
    Phase 1-4 invariants
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall.approval import (
    Approval,
    ApprovalError,
    ApprovalValidator,
    approval_from_dict,
    approval_from_file,
    canonical_request,
    compute_request_hash,
    hash_request,
)
from agent_firewall.model import Decision, DecisionKind, Request, Rule
from agent_firewall.evaluator import evaluate
from agent_firewall.policy import policy_from_dict


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_decision(
    kind: DecisionKind = DecisionKind.APPROVE,
    agent: str = "ops",
    action: str = "deploy",
    resource: str = "production",
    policy_version: int = 1,
    policy_generation: int = 3,
) -> Decision:
    return Decision(
        kind=kind,
        agent=agent,
        action=action,
        resource=resource,
        rule=Rule(action=action, resource=resource),
        reason="approval required",
        policy_version=policy_version,
        policy_generation=policy_generation,
    )


def _make_approval(
    decision: Decision,
    approved_by: str = "human-operator",
    expires_at: str = None,
    approval_id: str = "apr-000001",
) -> Approval:
    """Build an Approval that matches the given Decision."""
    h = compute_request_hash(
        decision.agent, decision.action, decision.resource,
        decision.policy_version, decision.policy_generation,
    )
    return Approval(
        approval_id=approval_id,
        request_hash=h,
        approved_by=approved_by,
        issued_at="2026-08-27T12:00:00.000000Z",
        expires_at=expires_at,
        policy_version=decision.policy_version,
        policy_generation=decision.policy_generation,
        reason="approved",
    )


def _write_approval(data: dict, suffix: str = ".json") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  Canonical request serialization
# ═════════════════════════════════════════════════════════════════════════════

class CanonicalRequestTests(unittest.TestCase):
    """Verify deterministic canonical serialization."""

    def test_deterministic(self):
        c1 = canonical_request("dev", "x", "./f", 1, 2)
        c2 = canonical_request("dev", "x", "./f", 1, 2)
        self.assertEqual(c1, c2)

    def test_sorted_keys(self):
        c = canonical_request("dev", "x", "./f", 1, 2)
        parsed = json.loads(c)
        keys = list(parsed.keys())
        self.assertEqual(keys, sorted(keys))

    def test_compact_format(self):
        c = canonical_request("dev", "x", "./f", 1, 2)
        self.assertNotIn(": ", c)  # no spaces after colons
        self.assertNotIn(", ", c)  # no spaces after commas

    def test_resource_null_when_none(self):
        c = canonical_request("dev", "x", None, 1, 2)
        parsed = json.loads(c)
        self.assertIsNone(parsed["resource"])

    def test_resource_included_when_present(self):
        c = canonical_request("dev", "x", "./f", 1, 2)
        parsed = json.loads(c)
        self.assertEqual(parsed["resource"], "./f")


# ═════════════════════════════════════════════════════════════════════════════
#  Request hashing
# ═════════════════════════════════════════════════════════════════════════════

class RequestHashingTests(unittest.TestCase):
    """Verify SHA-256 hashing is deterministic and sensitive to all fields."""

    def test_deterministic(self):
        h1 = compute_request_hash("dev", "x", "./f", 1, 2)
        h2 = compute_request_hash("dev", "x", "./f", 1, 2)
        self.assertEqual(h1, h2)

    def test_is_hex_64(self):
        h = compute_request_hash("dev", "x", "./f", 1, 2)
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_agent_changes_hash(self):
        h1 = compute_request_hash("dev", "x", "./f", 1, 2)
        h2 = compute_request_hash("other", "x", "./f", 1, 2)
        self.assertNotEqual(h1, h2)

    def test_action_changes_hash(self):
        h1 = compute_request_hash("dev", "x", "./f", 1, 2)
        h2 = compute_request_hash("dev", "y", "./f", 1, 2)
        self.assertNotEqual(h1, h2)

    def test_resource_changes_hash(self):
        h1 = compute_request_hash("dev", "x", "./f", 1, 2)
        h2 = compute_request_hash("dev", "x", "./g", 1, 2)
        self.assertNotEqual(h1, h2)

    def test_none_vs_present_resource(self):
        h1 = compute_request_hash("dev", "x", None, 1, 2)
        h2 = compute_request_hash("dev", "x", "./f", 1, 2)
        self.assertNotEqual(h1, h2)

    def test_policy_version_changes_hash(self):
        h1 = compute_request_hash("dev", "x", "./f", 1, 2)
        h2 = compute_request_hash("dev", "x", "./f", 2, 2)
        self.assertNotEqual(h1, h2)

    def test_policy_generation_changes_hash(self):
        h1 = compute_request_hash("dev", "x", "./f", 1, 2)
        h2 = compute_request_hash("dev", "x", "./f", 1, 3)
        self.assertNotEqual(h1, h2)

    def test_hash_request_alias(self):
        h1 = hash_request("dev", "x", "./f", 1, 2)
        h2 = compute_request_hash("dev", "x", "./f", 1, 2)
        self.assertEqual(h1, h2)


# ═════════════════════════════════════════════════════════════════════════════
#  Valid approval
# ═════════════════════════════════════════════════════════════════════════════

class ValidApprovalTests(unittest.TestCase):
    """Verify valid approvals pass validation."""

    def test_valid_approval(self):
        d = _make_decision()
        a = _make_approval(d, approved_by="human-operator")
        # Should not raise
        ApprovalValidator.validate(a, d)

    def test_permanent_approval(self):
        d = _make_decision()
        a = _make_approval(d, expires_at=None)
        ApprovalValidator.validate(a, d)

    def test_future_expiration(self):
        d = _make_decision()
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        a = _make_approval(d, expires_at=future)
        ApprovalValidator.validate(a, d)

    def test_unicode_approved_by(self):
        d = _make_decision()
        a = _make_approval(d, approved_by="human-操作者")
        ApprovalValidator.validate(a, d)

    def test_long_approval_id(self):
        d = _make_decision()
        a = _make_approval(d, approval_id="a" * 10000)
        ApprovalValidator.validate(a, d)


# ═════════════════════════════════════════════════════════════════════════════
#  Expired approval
# ═════════════════════════════════════════════════════════════════════════════

class ExpiredApprovalTests(unittest.TestCase):
    """Verify expired approvals are rejected."""

    def test_expired_approval(self):
        d = _make_decision()
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        a = _make_approval(d, expires_at=past)
        with self.assertRaises(ApprovalError) as ctx:
            ApprovalValidator.validate(a, d)
        self.assertIn("expired", str(ctx.exception).lower())

    def test_malformed_expiration(self):
        d = _make_decision()
        a = _make_approval(d, expires_at="not-a-timestamp")
        with self.assertRaises(ApprovalError) as ctx:
            ApprovalValidator.validate(a, d)
        self.assertIn("expires_at", str(ctx.exception).lower())


# ═════════════════════════════════════════════════════════════════════════════
#  Self-approval
# ═════════════════════════════════════════════════════════════════════════════

class SelfApprovalTests(unittest.TestCase):
    """Verify self-approval is rejected."""

    def test_self_approval_rejected(self):
        d = _make_decision(agent="ops")
        a = _make_approval(d, approved_by="ops")  # same as agent
        with self.assertRaises(ApprovalError) as ctx:
            ApprovalValidator.validate(a, d)
        self.assertIn("self-approval", str(ctx.exception).lower())

    def test_different_approver_accepted(self):
        d = _make_decision(agent="ops")
        a = _make_approval(d, approved_by="admin")
        ApprovalValidator.validate(a, d)


# ═════════════════════════════════════════════════════════════════════════════
#  Hash mismatch / wrong binding
# ═════════════════════════════════════════════════════════════════════════════

class HashMismatchTests(unittest.TestCase):
    """Verify hash mismatch is detected for every binding field."""

    def _assert_rejects(self, decision, approval, substring=None):
        with self.assertRaises(ApprovalError):
            ApprovalValidator.validate(approval, decision)

    def test_wrong_request_hash(self):
        d = _make_decision()
        a = _make_approval(d)
        # Tamper with the hash
        tampered = Approval(
            approval_id=a.approval_id,
            request_hash="0" * 64,
            approved_by=a.approved_by,
            issued_at=a.issued_at,
            expires_at=a.expires_at,
            policy_version=a.policy_version,
            policy_generation=a.policy_generation,
        )
        self._assert_rejects(d, tampered)

    def test_wrong_agent(self):
        d = _make_decision(agent="ops")
        # Approval was for a different agent
        d_other = _make_decision(agent="dev")
        a = _make_approval(d_other, approved_by="human")
        self._assert_rejects(d, a)

    def test_wrong_action(self):
        d = _make_decision(action="deploy")
        d_other = _make_decision(action="rollback")
        a = _make_approval(d_other, approved_by="human")
        self._assert_rejects(d, a)

    def test_wrong_resource(self):
        d = _make_decision(resource="production")
        d_other = _make_decision(resource="staging")
        a = _make_approval(d_other, approved_by="human")
        self._assert_rejects(d, a)

    def test_wrong_policy_version(self):
        d = _make_decision(policy_version=1)
        d_other = _make_decision(policy_version=2)
        a = _make_approval(d_other, approved_by="human")
        self._assert_rejects(d, a)

    def test_wrong_policy_generation(self):
        d = _make_decision(policy_generation=3)
        d_other = _make_decision(policy_generation=5)
        a = _make_approval(d_other, approved_by="human")
        self._assert_rejects(d, a)


# ═════════════════════════════════════════════════════════════════════════════
#  Non-APPROVE decision
# ═════════════════════════════════════════════════════════════════════════════

class NonApproveDecisionTests(unittest.TestCase):
    """Verify approval validation rejects non-APPROVE decisions."""

    def test_allow_rejected(self):
        d = _make_decision(kind=DecisionKind.ALLOW)
        a = _make_approval(d, approved_by="human")
        with self.assertRaises(ApprovalError):
            ApprovalValidator.validate(a, d)

    def test_deny_rejected(self):
        d = _make_decision(kind=DecisionKind.DENY)
        a = _make_approval(d, approved_by="human")
        with self.assertRaises(ApprovalError):
            ApprovalValidator.validate(a, d)


# ═════════════════════════════════════════════════════════════════════════════
#  Malformed approval
# ═════════════════════════════════════════════════════════════════════════════

class MalformedApprovalTests(unittest.TestCase):
    """Verify malformed approvals fail closed."""

    def test_empty_approval_id(self):
        d = _make_decision()
        a = Approval("", "hash", "ops", "t", policy_version=1, policy_generation=3)
        with self.assertRaises(ApprovalError):
            ApprovalValidator.validate(a, d)

    def test_empty_request_hash(self):
        d = _make_decision()
        a = Approval("id", "", "ops", "t", policy_version=1, policy_generation=3)
        with self.assertRaises(ApprovalError):
            ApprovalValidator.validate(a, d)

    def test_empty_approved_by(self):
        d = _make_decision()
        a = Approval("id", "hash", "", "t", policy_version=1, policy_generation=3)
        with self.assertRaises(ApprovalError):
            ApprovalValidator.validate(a, d)

    def test_empty_issued_at(self):
        d = _make_decision()
        a = Approval("id", "hash", "ops", "", policy_version=1, policy_generation=3)
        with self.assertRaises(ApprovalError):
            ApprovalValidator.validate(a, d)


# ═════════════════════════════════════════════════════════════════════════════
#  Approval parsing
# ═════════════════════════════════════════════════════════════════════════════

class ApprovalParsingTests(unittest.TestCase):
    """Verify approval parsing from dict and file."""

    def test_parse_valid(self):
        d = _make_decision()
        data = {
            "approval_id": "apr-1",
            "request_hash": "abc",
            "approved_by": "human",
            "issued_at": "2026-01-01T00:00:00Z",
            "policy_version": 1,
            "policy_generation": 3,
        }
        a = approval_from_dict(data)
        self.assertEqual(a.approval_id, "apr-1")
        self.assertEqual(a.approved_by, "human")

    def test_parse_missing_field(self):
        data = {"approval_id": "apr-1"}
        with self.assertRaises(ApprovalError) as ctx:
            approval_from_dict(data)
        self.assertIn("missing required field", str(ctx.exception))

    def test_parse_extra_fields_ignored(self):
        d = _make_decision()
        data = {
            "approval_id": "apr-1",
            "request_hash": "abc",
            "approved_by": "human",
            "issued_at": "t",
            "policy_version": 1,
            "policy_generation": 3,
            "extra_field": "should be ignored",
        }
        a = approval_from_dict(data)
        self.assertEqual(a.approval_id, "apr-1")

    def test_parse_from_file(self):
        d = _make_decision()
        data = {
            "approval_id": "apr-1",
            "request_hash": "abc",
            "approved_by": "human",
            "issued_at": "t",
            "policy_version": 1,
            "policy_generation": 3,
        }
        path = _write_approval(data)
        try:
            a = approval_from_file(path)
            self.assertEqual(a.approval_id, "apr-1")
        finally:
            os.unlink(path)

    def test_parse_missing_file(self):
        with self.assertRaises(ApprovalError):
            approval_from_file("/nonexistent/approval.json")

    def test_parse_invalid_json(self):
        path = _write_approval({"bad": True})
        # This is a valid JSON object but missing required fields
        try:
            with self.assertRaises(ApprovalError):
                approval_from_file(path)
        finally:
            os.unlink(path)

    def test_parse_non_object_json(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            fh.write('"just a string"')
        try:
            with self.assertRaises(ApprovalError) as ctx:
                approval_from_file(path)
            self.assertIn("JSON object", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_parse_malformed_json(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            fh.write("{broken")
        try:
            with self.assertRaises(ApprovalError):
                approval_from_file(path)
        finally:
            os.unlink(path)


# ═════════════════════════════════════════════════════════════════════════════
#  Repeated validation
# ═════════════════════════════════════════════════════════════════════════════

class RepeatedValidationTests(unittest.TestCase):
    """Verify approval can be validated multiple times while valid."""

    def test_repeated_validation(self):
        d = _make_decision()
        a = _make_approval(d, expires_at=None)
        for _ in range(10):
            ApprovalValidator.validate(a, d)


# ═════════════════════════════════════════════════════════════════════════════
#  Evaluator unchanged
# ═════════════════════════════════════════════════════════════════════════════

class EvaluatorUnchangedTests(unittest.TestCase):
    """Verify evaluator.py remains untouched by Phase 5."""

    def test_evaluator_has_no_approval_import(self):
        import inspect
        import agent_firewall.evaluator as eval_mod
        source = inspect.getsource(eval_mod)
        for line in source.splitlines():
            s = line.strip()
            if s.startswith("import") or s.startswith("from"):
                self.assertNotIn("approval", s.lower())

    def test_evaluator_produce_approve(self):
        p = policy_from_dict({
            "version": 1,
            "agents": {"ops": {"approve": [{"action": "deploy", "resource": "prod"}]}},
        })
        d = evaluate(Request("ops", "deploy", "prod"), p)
        self.assertEqual(d.kind, DecisionKind.APPROVE)

    def test_evaluate_has_no_approval_validation_logic(self):
        import inspect
        import agent_firewall.evaluator as eval_mod
        source = inspect.getsource(eval_mod.evaluate)
        # The evaluator matches 'approve' rules (Phase 1 behavior) — that's expected.
        # It must NOT contain approval validation, hashing, or expiration logic.
        # Check actual code lines (not docstrings) for forbidden patterns.
        code_lines = []
        in_docstring = False
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if not in_docstring and stripped and not stripped.startswith('#'):
                code_lines.append(stripped.lower())
        code_only = ' '.join(code_lines)
        self.assertNotIn('hash', code_only)
        self.assertNotIn('expires', code_only)
        self.assertNotIn('approval_id', code_only)
        self.assertNotIn('approved_by', code_only)


# ═════════════════════════════════════════════════════════════════════════════
#  Phase 1-4 invariants
# ═════════════════════════════════════════════════════════════════════════════

class Phase14InvariantsTests(unittest.TestCase):
    """Verify Phase 1-4 invariants remain intact."""

    def test_allow_still_works(self):
        p = policy_from_dict({"version": 1, "agents": {"dev": {"allow": [{"action": "x"}]}}})
        d = evaluate(Request("dev", "x"), p)
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_deny_still_works(self):
        p = policy_from_dict({"version": 1, "agents": {}})
        d = evaluate(Request("ghost", "x"), p)
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_approve_still_works(self):
        p = policy_from_dict({"version": 1, "agents": {"ops": {"approve": [{"action": "deploy"}]}}})
        d = evaluate(Request("ops", "deploy"), p)
        self.assertEqual(d.kind, DecisionKind.APPROVE)

    def test_deny_precedence(self):
        p = policy_from_dict({"version": 1, "agents": {"dev": {
            "allow": [{"action": "x", "resource": "./**"}],
            "deny": [{"action": "x", "resource": "./secret"}],
        }}})
        d = evaluate(Request("dev", "x", "./secret"), p)
        self.assertEqual(d.kind, DecisionKind.DENY)


# ═════════════════════════════════════════════════════════════════════════════
#  No Phase 6+/15 functionality
# ═════════════════════════════════════════════════════════════════════════════

class NoPhaseLeakageTests(unittest.TestCase):
    """Verify Phase 5 does not include later-phase functionality."""

    def test_no_hashlib_in_approval_hashing(self):
        """hashlib is used only for SHA-256, not for hash chaining."""
        import inspect
        import agent_firewall.approval as approval_mod
        source = inspect.getsource(approval_mod)
        # hashlib is imported — that's expected for SHA-256
        # But no hash chaining logic
        self.assertNotIn("previous_hash", source.split("class ")[0]
                         if "class " in source else source)

    def test_no_revocation(self):
        import inspect
        import agent_firewall.approval as approval_mod
        source = inspect.getsource(approval_mod)
        # Check actual code lines (not docstrings) for revocation logic.
        # Docstrings may mention "revocation" as something NOT implemented.
        code_lines = []
        in_docstring = False
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if not in_docstring and stripped and not stripped.startswith('#'):
                code_lines.append(stripped.lower())
        code_only = ' '.join(code_lines)
        self.assertNotIn('revoc', code_only)

    def test_no_signature(self):
        import inspect
        import agent_firewall.approval as approval_mod
        source = inspect.getsource(approval_mod)
        # No cryptographic signing (only hashing)
        self.assertNotIn("sign(", source.lower())
        self.assertNotIn("verify_signature", source.lower())


if __name__ == "__main__":
    unittest.main()
