"""Optional local audit evidence (Phase 4, DESIGN 32-33, SPEC 30).

Record structured evidence of every authorization decision to a local
JSONL file.  Evidence is **descriptive only** — it is never an authority
source.  The policy remains the authority.

Evidence recording is **optional** and **post-decision**: the evaluator
(``evaluate()``) remains pure and side-effect-free.  Evidence recording
happens at the integration layer (CLI or caller) after the Decision
already exists.

Properties (DESIGN 32):
    - append-oriented
    - machine-readable
    - easy to grep / diff / archive
    - usable without a database
    - no centralized logging service required

Security (SECURITY 19-21, SPEC 30):
    - secret values MUST NOT appear
    - prompts must not appear
    - source code must not appear
    - credential values must not appear

The implementation is zero-dependency (stdlib only).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import IO, Any, Dict, Optional


@dataclass(frozen=True)
class EvidenceRecord:
    """One structured evidence record for an authorization decision.

    Only carries fields derived from the Decision object.  No secrets,
    no environment variables, no prompts, no source code.
    """

    timestamp: str
    agent: str
    action: str
    decision: str
    resource: Optional[str] = None
    rule: Optional[Dict[str, str]] = None
    policy_version: Optional[int] = None
    policy_generation: Optional[int] = None
    reason: Optional[str] = None
    request_hash: Optional[str] = None
    approval_id: Optional[str] = None


def _decision_to_record(decision, timestamp: Optional[str] = None) -> EvidenceRecord:
    """Convert a Decision object to an EvidenceRecord.

    ``timestamp`` is generated in UTC if not supplied.  The Decision
    must already be fully resolved — this function performs no
    authorization logic.
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )

    rule_dict = None
    if decision.rule is not None:
        rule_dict = {"action": decision.rule.action}
        if decision.rule.resource is not None:
            rule_dict["resource"] = decision.rule.resource

    return EvidenceRecord(
        timestamp=timestamp,
        agent=decision.agent,
        action=decision.action,
        decision=decision.kind.value,
        resource=decision.resource,
        rule=rule_dict,
        policy_version=decision.policy_version,
        policy_generation=decision.policy_generation,
        reason=decision.reason if decision.reason else None,
    )


def _record_to_dict(record: EvidenceRecord) -> Dict[str, Any]:
    """Serialize an EvidenceRecord to a JSON-safe dict.

    Uses a controlled mapping — never ``__dict__`` or ``repr()``.
    Omits fields that are ``None`` to keep records minimal.
    """
    d: Dict[str, Any] = {
        "timestamp": record.timestamp,
        "agent": record.agent,
        "action": record.action,
        "decision": record.decision,
    }
    if record.resource is not None:
        d["resource"] = record.resource
    if record.rule is not None:
        d["rule"] = record.rule
    if record.policy_version is not None:
        d["policy_version"] = record.policy_version
    if record.policy_generation is not None:
        d["policy_generation"] = record.policy_generation
    if record.reason is not None:
        d["reason"] = record.reason
    if record.request_hash is not None:
        d["request_hash"] = record.request_hash
    if record.approval_id is not None:
        d["approval_id"] = record.approval_id
    return d


class EvidenceLogger:
    """Append-only JSONL evidence logger.

    Opens the evidence file in append mode (``"a"``), creates it if
    missing, and never truncates or overwrites existing content.

    Usage::

        logger = EvidenceLogger("/path/to/evidence.jsonl")
        logger.record(decision)
        logger.close()

    Or as a context manager::

        with EvidenceLogger("/path/to/evidence.jsonl") as logger:
            logger.record(decision)

    If recording fails (disk full, permissions), the error is printed
    to stderr and the original authorization decision is unaffected.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._fh: Optional[IO[str]] = None

    def _open(self) -> IO[str]:
        if self._fh is None:
            self._fh = open(self._path, "a", encoding="utf-8")
        return self._fh

    def record(self, decision) -> None:
        """Record a Decision as one JSONL line.

        This method must not raise.  If writing fails, a warning is
        printed to stderr and the original decision is preserved.
        """
        try:
            record = _decision_to_record(decision)
            line = json.dumps(_record_to_dict(record), ensure_ascii=False) + "\n"
            fh = self._open()
            fh.write(line)
            fh.flush()
        except Exception as exc:
            print(
                f"warning: failed to write audit record: {exc}",
                file=sys.stderr,
            )

    def close(self) -> None:
        """Close the underlying file handle if open."""
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def __enter__(self) -> "EvidenceLogger":
        return self

    def __exit__(self, *args) -> None:
        self.close()
