"""Tests for optional local audit evidence (Phase 4, DESIGN 32-33, SPEC 30).

Covers:

    EvidenceRecord creation from Decision
    JSONL serialization / deserialization
    Append-only behavior
    File creation if missing
    Required fields present
    ALLOW / DENY / APPROVE evidence
    Default-deny evidence
    Secret values never appear
    Unicode identifiers
    Audit failure cannot change decision
    No side effect when audit is absent
    Evaluator remains free of audit imports
    No request_hash / approval_id / previous_hash emitted
    Deterministic record content (excluding timestamp)
    One record per decision
    Line-oriented JSONL
"""

import json
import os
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall.audit import (
    EvidenceLogger,
    EvidenceRecord,
    _decision_to_record,
    _record_to_dict,
)
from agent_firewall.model import Decision, DecisionKind, Request, Rule
from agent_firewall.evaluator import evaluate
from agent_firewall.policy import policy_from_dict


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_decision(
    kind: DecisionKind,
    agent: str = "dev",
    action: str = "fs.read",
    resource: str = "./src",
    rule_action: str = "fs.read",
    rule_resource: str = "./src/**",
) -> Decision:
    """Build a Decision object for testing."""
    return Decision(
        kind=kind,
        agent=agent,
        action=action,
        resource=resource,
        rule=Rule(action=rule_action, resource=rule_resource),
        reason=f"test reason for {kind.value}",
        policy_version=1,
        policy_generation=1,
    )


def _make_default_deny_decision() -> Decision:
    """Build a default-deny Decision (no matched rule)."""
    return Decision(
        kind=DecisionKind.DENY,
        agent="unknown",
        action="any.action",
        reason="unknown agent",
        policy_version=1,
        policy_generation=1,
    )


def _read_jsonl(path: str):
    """Read a JSONL file and return list of parsed dicts."""
    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


# ═════════════════════════════════════════════════════════════════════════════
#  EvidenceRecord creation
# ═════════════════════════════════════════════════════════════════════════════

class EvidenceRecordCreationTests(unittest.TestCase):
    """Verify EvidenceRecord is correctly created from Decision objects."""

    def test_allow_record(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="2026-01-01T00:00:00.000000Z")
        self.assertIsInstance(r, EvidenceRecord)
        self.assertEqual(r.decision, "ALLOW")
        self.assertEqual(r.agent, "dev")
        self.assertEqual(r.action, "fs.read")
        self.assertEqual(r.resource, "./src")
        self.assertEqual(r.rule, {"action": "fs.read", "resource": "./src/**"})
        self.assertEqual(r.policy_version, 1)

    def test_deny_record(self):
        d = _make_decision(DecisionKind.DENY)
        r = _decision_to_record(d, timestamp="2026-01-01T00:00:00.000000Z")
        self.assertEqual(r.decision, "DENY")

    def test_approve_record(self):
        d = _make_decision(DecisionKind.APPROVE)
        r = _decision_to_record(d, timestamp="2026-01-01T00:00:00.000000Z")
        self.assertEqual(r.decision, "APPROVE")

    def test_default_deny_no_rule(self):
        d = _make_default_deny_decision()
        r = _decision_to_record(d, timestamp="2026-01-01T00:00:00.000000Z")
        self.assertIsNone(r.rule)
        self.assertEqual(r.decision, "DENY")
        self.assertEqual(r.reason, "unknown agent")

    def test_no_resource(self):
        d = Decision(
            kind=DecisionKind.ALLOW,
            agent="ops",
            action="deploy",
            reason="allowed",
            policy_version=1,
        )
        r = _decision_to_record(d, timestamp="t")
        self.assertIsNone(r.resource)

    def test_record_is_frozen(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="t")
        with self.assertRaises(AttributeError):
            r.agent = "changed"


# ═════════════════════════════════════════════════════════════════════════════
#  JSONL serialization
# ═════════════════════════════════════════════════════════════════════════════

class JSONLSerializationTests(unittest.TestCase):
    """Verify JSONL serialization produces valid, parseable output."""

    def test_record_to_dict_omits_none_fields(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="t")
        d_out = _record_to_dict(r)
        self.assertIn("timestamp", d_out)
        self.assertIn("agent", d_out)
        self.assertIn("action", d_out)
        self.assertIn("decision", d_out)
        # None fields omitted
        self.assertNotIn("request_hash", d_out)
        self.assertNotIn("approval_id", d_out)
        self.assertNotIn("previous_hash", d_out)

    def test_json_is_valid(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="2026-01-01T00:00:00.000000Z")
        json_str = json.dumps(_record_to_dict(r))
        parsed = json.loads(json_str)
        self.assertEqual(parsed["decision"], "ALLOW")
        self.assertEqual(parsed["agent"], "dev")

    def test_jsonl_line_is_single_line(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="t")
        line = json.dumps(_record_to_dict(r)) + "\n"
        self.assertEqual(line.count("\n"), 1)

    def test_unicode_agent_name(self):
        d = _make_decision(DecisionKind.ALLOW, agent="développeur")
        r = _decision_to_record(d, timestamp="t")
        d_out = _record_to_dict(r)
        self.assertEqual(d_out["agent"], "développeur")
        json_str = json.dumps(d_out, ensure_ascii=False)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["agent"], "développeur")


# ═════════════════════════════════════════════════════════════════════════════
#  EvidenceLogger — append and file behavior
# ═════════════════════════════════════════════════════════════════════════════

class EvidenceLoggerAppendTests(unittest.TestCase):
    """Verify EvidenceLogger append-only behavior."""

    def test_creates_file_if_missing(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        os.unlink(path)  # ensure it doesn't exist
        try:
            logger = EvidenceLogger(path)
            d = _make_decision(DecisionKind.ALLOW)
            logger.record(d)
            logger.close()
            self.assertTrue(os.path.exists(path))
            records = _read_jsonl(path)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["decision"], "ALLOW")
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_appends_multiple_records(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            logger = EvidenceLogger(path)
            for kind in (DecisionKind.ALLOW, DecisionKind.DENY, DecisionKind.APPROVE):
                logger.record(_make_decision(kind))
            logger.close()
            records = _read_jsonl(path)
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0]["decision"], "ALLOW")
            self.assertEqual(records[1]["decision"], "DENY")
            self.assertEqual(records[2]["decision"], "APPROVE")
        finally:
            os.unlink(path)

    def test_one_record_per_decision(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            logger = EvidenceLogger(path)
            d = _make_decision(DecisionKind.ALLOW)
            logger.record(d)
            logger.close()
            records = _read_jsonl(path)
            self.assertEqual(len(records), 1)
        finally:
            os.unlink(path)

    def test_append_does_not_truncate(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            # Write first record
            logger = EvidenceLogger(path)
            logger.record(_make_decision(DecisionKind.ALLOW))
            logger.close()
            # Write second record
            logger2 = EvidenceLogger(path)
            logger2.record(_make_decision(DecisionKind.DENY))
            logger2.close()
            records = _read_jsonl(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["decision"], "ALLOW")
            self.assertEqual(records[1]["decision"], "DENY")
        finally:
            os.unlink(path)


# ═════════════════════════════════════════════════════════════════════════════
#  Required fields
# ═════════════════════════════════════════════════════════════════════════════

class RequiredFieldsTests(unittest.TestCase):
    """Verify all required fields are present in every record."""

    def test_required_fields_present(self):
        required = {"timestamp", "agent", "action", "decision"}
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="2026-01-01T00:00:00.000000Z")
        d_out = _record_to_dict(r)
        for field in required:
            self.assertIn(field, d_out, f"missing required field: {field}")

    def test_timestamp_format(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="2026-08-27T02:45:00.123456Z")
        self.assertEqual(r.timestamp, "2026-08-27T02:45:00.123456Z")

    def test_timestamp_auto_generated(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d)
        # Should be ISO 8601 UTC with microsecond precision
        self.assertIn("T", r.timestamp)
        self.assertTrue(r.timestamp.endswith("Z"))


# ═════════════════════════════════════════════════════════════════════════════
#  Decision-kind evidence
# ═════════════════════════════════════════════════════════════════════════════

class DecisionKindEvidenceTests(unittest.TestCase):
    """Verify evidence for each decision kind."""

    def test_allow_evidence(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            logger = EvidenceLogger(path)
            logger.record(_make_decision(DecisionKind.ALLOW))
            logger.close()
            records = _read_jsonl(path)
            self.assertEqual(records[0]["decision"], "ALLOW")
        finally:
            os.unlink(path)

    def test_deny_evidence(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            logger = EvidenceLogger(path)
            logger.record(_make_decision(DecisionKind.DENY))
            logger.close()
            records = _read_jsonl(path)
            self.assertEqual(records[0]["decision"], "DENY")
        finally:
            os.unlink(path)

    def test_approve_evidence(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            logger = EvidenceLogger(path)
            logger.record(_make_decision(DecisionKind.APPROVE))
            logger.close()
            records = _read_jsonl(path)
            self.assertEqual(records[0]["decision"], "APPROVE")
        finally:
            os.unlink(path)

    def test_default_deny_evidence(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            logger = EvidenceLogger(path)
            logger.record(_make_default_deny_decision())
            logger.close()
            records = _read_jsonl(path)
            self.assertEqual(records[0]["decision"], "DENY")
            self.assertEqual(records[0]["agent"], "unknown")
            self.assertNotIn("rule", records[0])
        finally:
            os.unlink(path)


# ═════════════════════════════════════════════════════════════════════════════
#  Secret redaction
# ═════════════════════════════════════════════════════════════════════════════

class SecretRedactionTests(unittest.TestCase):
    """Verify that secret values never appear in evidence."""

    def test_secret_identifier_not_secret_value(self):
        """The resource 'DATABASE_URL' is an identifier, not a value."""
        d = Decision(
            kind=DecisionKind.DENY,
            agent="dev",
            action="secret.read",
            resource="DATABASE_URL",
            reason="denied",
        )
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            logger = EvidenceLogger(path)
            logger.record(d)
            logger.close()
            records = _read_jsonl(path)
            # The record should contain the identifier, not any secret value
            self.assertEqual(records[0]["resource"], "DATABASE_URL")
            self.assertNotIn("password", json.dumps(records[0]).lower())
            self.assertNotIn("secret123", json.dumps(records[0]))
        finally:
            os.unlink(path)

    def test_no_env_vars_in_record(self):
        """Evidence must not capture environment variables."""
        d = _make_decision(DecisionKind.ALLOW)
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            logger = EvidenceLogger(path)
            logger.record(d)
            logger.close()
            records = _read_jsonl(path)
            record_str = json.dumps(records[0])
            self.assertNotIn("PATH", record_str)
            self.assertNotIn("HOME", record_str)
            self.assertNotIn("SECRET", record_str)
        finally:
            os.unlink(path)

    def test_no_prompt_content(self):
        """Evidence must not capture prompt contents."""
        d = _make_decision(DecisionKind.ALLOW)
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            logger = EvidenceLogger(path)
            logger.record(d)
            logger.close()
            records = _read_jsonl(path)
            record_str = json.dumps(records[0])
            self.assertNotIn("prompt", record_str.lower())
        finally:
            os.unlink(path)


# ═════════════════════════════════════════════════════════════════════════════
#  Omitted fields (Phase 5/15)
# ═════════════════════════════════════════════════════════════════════════════

class OmittedFieldsTests(unittest.TestCase):
    """Verify that Phase 5/15 fields are NOT emitted."""

    def test_no_request_hash(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="t")
        d_out = _record_to_dict(r)
        self.assertNotIn("request_hash", d_out)

    def test_no_approval_id(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="t")
        d_out = _record_to_dict(r)
        self.assertNotIn("approval_id", d_out)

    def test_no_previous_hash(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="t")
        d_out = _record_to_dict(r)
        self.assertNotIn("previous_hash", d_out)


# ═════════════════════════════════════════════════════════════════════════════
#  Audit failure handling
# ═════════════════════════════════════════════════════════════════════════════

class AuditFailureTests(unittest.TestCase):
    """Verify audit failures do not change the authorization decision."""

    def test_failure_preserves_allow(self):
        """Writing to a read-only path should not change ALLOW."""
        d = _make_decision(DecisionKind.ALLOW)
        logger = EvidenceLogger("/nonexistent/dir/evidence.jsonl")
        # Should not raise
        logger.record(d)
        logger.close()
        # The decision was already determined — recording failure is non-fatal

    def test_failure_preserves_deny(self):
        d = _make_decision(DecisionKind.DENY)
        logger = EvidenceLogger("/nonexistent/dir/evidence.jsonl")
        logger.record(d)
        logger.close()

    def test_failure_preserves_approve(self):
        d = _make_decision(DecisionKind.APPROVE)
        logger = EvidenceLogger("/nonexistent/dir/evidence.jsonl")
        logger.record(d)
        logger.close()

    def test_failure_writes_warning_to_stderr(self):
        d = _make_decision(DecisionKind.ALLOW)
        logger = EvidenceLogger("/nonexistent/dir/evidence.jsonl")
        stderr = StringIO()
        with patch("sys.stderr", stderr):
            logger.record(d)
        logger.close()
        self.assertIn("warning", stderr.getvalue().lower())
        self.assertIn("failed to write audit record", stderr.getvalue().lower())


# ═════════════════════════════════════════════════════════════════════════════
#  No side effect when audit absent
# ═════════════════════════════════════════════════════════════════════════════

class NoAuditSideEffectTests(unittest.TestCase):
    """Verify no file/audit side effect when --audit is not specified."""

    def test_no_file_created_without_logger(self):
        """Not creating a logger must not create any file."""
        cwd_before = set(os.listdir(os.getcwd()))
        # Evaluate a decision without logging
        d = _make_decision(DecisionKind.ALLOW)
        # Just build the record — don't write
        r = _decision_to_record(d, timestamp="t")
        d_out = _record_to_dict(r)
        _ = json.dumps(d_out)  # serialize but don't write
        cwd_after = set(os.listdir(os.getcwd()))
        self.assertEqual(cwd_before, cwd_after)


# ═════════════════════════════════════════════════════════════════════════════
#  Evaluator independence
# ═════════════════════════════════════════════════════════════════════════════

class EvaluatorIndependenceTests(unittest.TestCase):
    """Verify evaluator.py has no audit dependency."""

    def test_evaluator_has_no_audit_import(self):
        import inspect
        import agent_firewall.evaluator as eval_mod
        source = inspect.getsource(eval_mod)
        self.assertNotIn("audit", source.lower().split("import")[0]
                         if "import" in source.lower() else "")
        # More precise: no 'import.*audit' in the file
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("import") or stripped.startswith("from"):
                self.assertNotIn("audit", stripped.lower())

    def test_evaluate_function_has_no_audit_reference(self):
        import inspect
        import agent_firewall.evaluator as eval_mod
        source = inspect.getsource(eval_mod.evaluate)
        self.assertNotIn("audit", source.lower())
        self.assertNotIn("evidence", source.lower())
        self.assertNotIn("logger", source.lower())


# ═════════════════════════════════════════════════════════════════════════════
#  Determinism (record content, not timestamp)
# ═════════════════════════════════════════════════════════════════════════════

class RecordDeterminismTests(unittest.TestCase):
    """Verify record content is deterministic for the same input."""

    def test_same_decision_same_record(self):
        d = _make_decision(DecisionKind.ALLOW)
        r1 = _decision_to_record(d, timestamp="2026-01-01T00:00:00.000000Z")
        r2 = _decision_to_record(d, timestamp="2026-01-01T00:00:00.000000Z")
        self.assertEqual(_record_to_dict(r1), _record_to_dict(r2))

    def test_different_decisions_different_records(self):
        r1 = _decision_to_record(_make_decision(DecisionKind.ALLOW), timestamp="t")
        r2 = _decision_to_record(_make_decision(DecisionKind.DENY), timestamp="t")
        self.assertNotEqual(_record_to_dict(r1), _record_to_dict(r2))


# ═════════════════════════════════════════════════════════════════════════════
#  Context manager
# ═════════════════════════════════════════════════════════════════════════════

class ContextManagerTests(unittest.TestCase):
    """Verify EvidenceLogger works as a context manager."""

    def test_context_manager(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            with EvidenceLogger(path) as logger:
                logger.record(_make_decision(DecisionKind.ALLOW))
            records = _read_jsonl(path)
            self.assertEqual(len(records), 1)
        finally:
            os.unlink(path)


# ═════════════════════════════════════════════════════════════════════════════
#  No Phase 5/15 infrastructure
# ═════════════════════════════════════════════════════════════════════════════

class NoPhase5InfrastructureTests(unittest.TestCase):
    """Verify Phase 4 does not include Phase 5/15 functionality."""

    def test_no_hashlib_import_in_audit(self):
        import inspect
        import agent_firewall.audit as audit_mod
        source = inspect.getsource(audit_mod)
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("import") or stripped.startswith("from"):
                self.assertNotIn("hashlib", stripped)

    def test_no_subprocess_import(self):
        import inspect
        import agent_firewall.audit as audit_mod
        source = inspect.getsource(audit_mod)
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("import") or stripped.startswith("from"):
                self.assertNotIn("subprocess", stripped)

    def test_record_has_no_hash_fields(self):
        d = _make_decision(DecisionKind.ALLOW)
        r = _decision_to_record(d, timestamp="t")
        d_out = _record_to_dict(r)
        for key in ("request_hash", "previous_hash", "approval_id", "approval"):
            self.assertNotIn(key, d_out)


# ═════════════════════════════════════════════════════════════════════════════
#  Phase 1-3 invariants
# ═════════════════════════════════════════════════════════════════════════════

class Phase13InvariantsTests(unittest.TestCase):
    """Verify Phase 1-3 security invariants remain intact."""

    def test_core_evaluate_still_works(self):
        p = policy_from_dict({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "read"}]}},
        })
        d = evaluate(Request("dev", "read"), p)
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_default_deny_still_works(self):
        p = policy_from_dict({"version": 1, "agents": {}})
        d = evaluate(Request("ghost", "any"), p)
        self.assertEqual(d.kind, DecisionKind.DENY)

    def test_deny_precedence_still_works(self):
        p = policy_from_dict({
            "version": 1,
            "agents": {"dev": {
                "allow": [{"action": "x", "resource": "./**"}],
                "deny": [{"action": "x", "resource": "./secret"}],
            }},
        })
        d = evaluate(Request("dev", "x", "./secret"), p)
        self.assertEqual(d.kind, DecisionKind.DENY)


if __name__ == "__main__":
    unittest.main()
