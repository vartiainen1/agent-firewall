"""Optional integrity features for agent-firewall (Phase 15).

Provides optional integrity mechanisms that build on the existing core
without modifying it:

- **Hash-chained evidence**: chain audit records for tamper detection
- **Policy integrity**: content-hash verification for policy files
- **Capability expiration**: time-limited capability checks
- **Capability revocation**: post-evaluation revocation override

All features are **optional** and **additive**.  The existing core
behavior is preserved when these features are not used.

Properties:
    - Optional (caller chooses whether to use)
    - Additive (no existing behavior changed)
    - Zero third-party dependencies (stdlib hashlib only)
    - Deterministic hashing
    - Fail-closed on all integrity failures

Limitations (DESIGN 34, SECURITY 20):
    - Hash chaining detects tampering but does NOT prevent it
    - An attacker with filesystem write access can rewrite the entire chain
    - Local JSONL is NOT tamper-proof
    - Stronger guarantees require external anchoring (out of scope)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .audit import EvidenceRecord, _record_to_dict
from .model import Decision, DecisionKind, InvalidRequestError, Request

if TYPE_CHECKING:
    from . import Firewall


# ── Canonical serialization ──────────────────────────────────────────────────


def _canonicalize_record(record: EvidenceRecord) -> str:
    """Produce a deterministic canonical serialization of an EvidenceRecord.

    Uses the existing ``_record_to_dict`` controlled field mapping from
    audit.py, then serializes with compact deterministic JSON:

    - ``sort_keys=True`` for stable ordering
    - ``separators=(",", ":")`` for compact output
    - ``ensure_ascii=False`` for Unicode support

    This is consistent with the canonicalization conventions in
    approval.py (``canonical_request``).
    """
    d = _record_to_dict(record)
    return json.dumps(d, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _hash_content(content: str) -> str:
    """Compute SHA-256 hex digest of a string.

    Encodes to UTF-8 before hashing.  Deterministic for identical inputs.
    Uses only the Python standard library.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ── Hash-chained evidence ────────────────────────────────────────────────────


@dataclass(frozen=True)
class ChainedEvidenceRecord:
    """An evidence record with hash-chain linkage.

    Wraps the existing ``EvidenceRecord`` (frozen, unchanged) and adds
    two hash fields for chain integrity.  The original ``EvidenceRecord``
    is never modified.
    """

    record: EvidenceRecord
    record_hash: str
    previous_hash: Optional[str] = None


@dataclass(frozen=True)
class ChainVerification:
    """Result of chain integrity verification."""

    valid: bool
    total_records: int
    broken_at: Optional[int] = None
    reason: str = ""


class EvidenceChain:
    """Append-only evidence chain with hash chaining.

    Optionally chains evidence records for tamper detection (DESIGN 34).
    When chaining is disabled, behaves identically to a plain append-only
    log.

    The chain is **not** tamper-proof.  An attacker with filesystem write
    access can rewrite the entire chain.  This feature detects tampering;
    it does not prevent it.
    """

    def __init__(self, chain_file: str, *, chaining: bool = True) -> None:
        self._path = chain_file
        self._chaining = chaining
        self._last_hash: Optional[str] = None
        self._total_records: int = 0
        self._load_existing()

    def _load_existing(self) -> None:
        """Load existing chain from disk and compute last hash."""
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        h = data.get("record_hash")
                        if h:
                            self._last_hash = h
                            self._total_records += 1
                    except (json.JSONDecodeError, ValueError):
                        pass
        except FileNotFoundError:
            pass
        except OSError:
            pass

    @property
    def last_hash(self) -> Optional[str]:
        """The hash of the most recent record, or None if empty."""
        return self._last_hash

    def append(self, record: EvidenceRecord) -> ChainedEvidenceRecord:
        """Append a record and return the chained version.

        Computes the record hash, links to the previous hash, and
        appends to the chain file.
        """
        canonical = _canonicalize_record(record)
        record_hash = _hash_content(canonical)
        previous = self._last_hash if self._chaining else None

        chained = ChainedEvidenceRecord(
            record=record,
            record_hash=record_hash,
            previous_hash=previous,
        )

        # Append to file
        try:
            line_data: Dict[str, Any] = {
                "record_hash": record_hash,
                "record": _record_to_dict(record),
            }
            if previous is not None:
                line_data["previous_hash"] = previous

            line = json.dumps(line_data, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False) + "\n"
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
        except OSError as exc:
            print(
                f"warning: failed to write chain record: {exc}",
                file=sys.stderr,
            )

        self._last_hash = record_hash
        self._total_records += 1
        return chained

    def verify(self) -> ChainVerification:
        """Verify the integrity of the entire chain.

        Reads all records from the chain file and checks:
        - each record's hash matches its content
        - each record's previous_hash matches the prior record's hash
        - no records are missing or reordered
        """
        records: List[Dict[str, Any]] = []
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                for line_num, line in enumerate(fh):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        records.append(data)
                    except (json.JSONDecodeError, ValueError) as exc:
                        return ChainVerification(
                            valid=False,
                            total_records=len(records),
                            broken_at=line_num,
                            reason=f"invalid JSON at record {line_num}: {exc}",
                        )
        except FileNotFoundError:
            return ChainVerification(valid=True, total_records=0)
        except OSError as exc:
            return ChainVerification(
                valid=False, total_records=0,
                reason=f"could not read chain file: {exc}",
            )

        if not records:
            return ChainVerification(valid=True, total_records=0)

        prev_hash: Optional[str] = None
        for idx, data in enumerate(records):
            # Check previous_hash link
            stored_prev = data.get("previous_hash")
            if stored_prev != prev_hash:
                return ChainVerification(
                    valid=False,
                    total_records=len(records),
                    broken_at=idx,
                    reason=(
                        f"broken link at record {idx}: "
                        f"expected previous_hash={prev_hash!r}, "
                        f"got {stored_prev!r}"
                    ),
                )

            # Recompute record hash
            record_data = data.get("record")
            if record_data is None:
                return ChainVerification(
                    valid=False,
                    total_records=len(records),
                    broken_at=idx,
                    reason=f"missing 'record' field at record {idx}",
                )

            canonical = json.dumps(
                record_data, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False,
            )
            expected_hash = _hash_content(canonical)
            stored_hash = data.get("record_hash")

            if stored_hash != expected_hash:
                return ChainVerification(
                    valid=False,
                    total_records=len(records),
                    broken_at=idx,
                    reason=(
                        f"hash mismatch at record {idx}: "
                        f"expected {expected_hash!r}, got {stored_hash!r}"
                    ),
                )

            prev_hash = stored_hash

        return ChainVerification(valid=True, total_records=len(records))


# ── Policy integrity ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PolicyIntegrity:
    """Integrity state for a loaded policy.

    Binds the content hash to the policy's version, generation, and path.
    """

    policy_hash: str
    verified_at: str
    policy_path: str
    policy_version: int = 0
    policy_generation: int = 0


class PolicyIntegrityVerifier:
    """Verify policy file integrity using content hashing.

    Uses stdlib hashlib SHA-256 only.  Provides integrity verification,
    NOT authentication or signer identity.  Detects whether a policy file
    has been modified after the hash was computed.
    """

    @staticmethod
    def hash_policy_file(path: str) -> str:
        """Compute SHA-256 hash of a policy file's raw content."""
        with open(path, "rb") as fh:
            content = fh.read()
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def hash_policy_content(content: bytes) -> str:
        """Compute SHA-256 hash of policy content bytes."""
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def verify_policy_file(path: str, expected_hash: str) -> bool:
        """Verify that a policy file matches its expected hash."""
        actual = PolicyIntegrityVerifier.hash_policy_file(path)
        return hmac.compare_digest(actual, expected_hash)

    @staticmethod
    def verify_policy_content(content: bytes, expected_hash: str) -> bool:
        """Verify that policy content matches its expected hash."""
        actual = PolicyIntegrityVerifier.hash_policy_content(content)
        return hmac.compare_digest(actual, expected_hash)

    @staticmethod
    def create_integrity(
        path: str,
        policy_version: int = 0,
        policy_generation: int = 0,
    ) -> PolicyIntegrity:
        """Compute and return a PolicyIntegrity for a policy file."""
        policy_hash = PolicyIntegrityVerifier.hash_policy_file(path)
        verified_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        return PolicyIntegrity(
            policy_hash=policy_hash,
            verified_at=verified_at,
            policy_path=path,
            policy_version=policy_version,
            policy_generation=policy_generation,
        )


# ── Capability expiration ────────────────────────────────────────────────────


@dataclass(frozen=True)
class ExpiringCapability:
    """A capability with an expiration timestamp.

    Immutable/frozen.  Timestamps are ISO-8601 UTC.
    """

    agent: str
    action: str
    resource: Optional[str] = None
    expires_at: str = ""


class CapabilityExpirationList:
    """Check whether capabilities have expired.

    Standalone utility.  Does not modify the evaluator or policy.
    Caller applies after authorization.
    """

    def __init__(self) -> None:
        self._capabilities: List[ExpiringCapability] = []

    def add(
        self,
        agent: str,
        action: str,
        resource: str = None,
        expires_at: str = "",
    ) -> ExpiringCapability:
        """Register an expiring capability."""
        cap = ExpiringCapability(
            agent=agent, action=action,
            resource=resource, expires_at=expires_at,
        )
        self._capabilities.append(cap)
        return cap

    def is_expired(self, agent: str, action: str,
                   resource: str = None) -> bool:
        """Check whether a capability has expired.

        Returns True if any matching capability with a valid expiration
        timestamp has expired.  Returns False if no matching capability
        is found or if no expiration is set.
        """
        for cap in self._capabilities:
            if cap.agent != agent or cap.action != action:
                continue
            if cap.resource != resource:
                continue
            if not cap.expires_at:
                return False  # no expiration set
            try:
                expires = datetime.fromisoformat(
                    cap.expires_at.replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                return True  # invalid timestamp → fail closed → expired
            now = datetime.now(timezone.utc)
            if now > expires:
                return True
        return False

    def check(self, decision: Decision) -> Decision:
        """Override a Decision to DENY if the capability has expired.

        ALLOW → DENY (if expired)
        DENY → DENY (unchanged)
        APPROVE → DENY (if expired)
        """
        if decision.kind is DecisionKind.DENY:
            return decision
        if self.is_expired(decision.agent, decision.action,
                           decision.resource):
            return Decision(
                kind=DecisionKind.DENY,
                agent=decision.agent,
                action=decision.action,
                resource=decision.resource,
                reason="capability expired",
            )
        return decision

    def entries(self) -> List[ExpiringCapability]:
        """Return all expiring capabilities (read-only)."""
        return list(self._capabilities)


# ── Capability revocation ────────────────────────────────────────────────────


@dataclass(frozen=True)
class RevocationEntry:
    """A single revocation record.

    Immutable/frozen.  Persisted to a JSON file.
    """

    agent: str
    action: str
    resource: Optional[str] = None
    revoked_at: str = ""
    reason: str = ""
    revocation_id: str = ""


class RevocationList:
    """Local revocation list for capabilities.

    Stores revocation entries in a JSON file.  Checked after policy
    evaluation: if a capability is revoked, the decision is overridden
    to DENY.

    **Limitation**: An attacker with filesystem write access can modify
    the revocation file.  This is the same limitation as policy files
    (SECURITY 8).  Stronger guarantees require signed revocation state.
    """

    def __init__(self, revocation_file: str) -> None:
        self._path = revocation_file
        self._entries: List[RevocationEntry] = []
        self._load()

    def _load(self) -> None:
        """Load revocation entries from disk."""
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, list):
                return
            for item in data:
                if not isinstance(item, dict):
                    continue
                entry = RevocationEntry(
                    agent=item.get("agent", ""),
                    action=item.get("action", ""),
                    resource=item.get("resource"),
                    revoked_at=item.get("revoked_at", ""),
                    reason=item.get("reason", ""),
                    revocation_id=item.get("revocation_id", ""),
                )
                self._entries.append(entry)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass

    def _save(self) -> None:
        """Persist revocation entries to disk."""
        data = []
        for e in self._entries:
            item: Dict[str, Any] = {
                "agent": e.agent,
                "action": e.action,
            }
            if e.resource is not None:
                item["resource"] = e.resource
            if e.revoked_at:
                item["revoked_at"] = e.revoked_at
            if e.reason:
                item["reason"] = e.reason
            if e.revocation_id:
                item["revocation_id"] = e.revocation_id
            data.append(item)
        try:
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
                fh.flush()
        except OSError as exc:
            print(
                f"warning: failed to write revocation file: {exc}",
                file=sys.stderr,
            )

    def revoke(
        self,
        agent: str,
        action: str,
        resource: str = None,
        reason: str = "",
    ) -> RevocationEntry:
        """Add a revocation entry."""
        revoked_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        revocation_id = f"rev-{len(self._entries) + 1}"
        entry = RevocationEntry(
            agent=agent,
            action=action,
            resource=resource,
            revoked_at=revoked_at,
            reason=reason,
            revocation_id=revocation_id,
        )
        self._entries.append(entry)
        self._save()
        return entry

    def is_revoked(self, agent: str, action: str,
                   resource: str = None) -> bool:
        """Check whether a capability has been revoked.

        Matching rules:
        - agent + action must match
        - resource=None in revocation matches ANY resource
        - specific resource requires exact equality
        """
        for entry in self._entries:
            if entry.agent != agent or entry.action != action:
                continue
            if entry.resource is None:
                return True  # revocation with no resource matches any
            if entry.resource == resource:
                return True  # exact match
        return False

    def check(self, decision: Decision) -> Decision:
        """Override a Decision to DENY if the capability is revoked.

        ALLOW → DENY (if revoked)
        DENY → DENY (unchanged)
        APPROVE → DENY (if revoked)

        Revocation must NEVER produce ALLOW.
        """
        if decision.kind is DecisionKind.DENY:
            return decision
        if self.is_revoked(decision.agent, decision.action,
                           decision.resource):
            return Decision(
                kind=DecisionKind.DENY,
                agent=decision.agent,
                action=decision.action,
                resource=decision.resource,
                reason="capability revoked",
            )
        return decision

    def entries(self) -> List[RevocationEntry]:
        """Return all revocation entries (read-only)."""
        return list(self._entries)


# ── Post-evaluation wrappers ─────────────────────────────────────────────────


def check_with_revocation(
    firewall: "Firewall",
    request: Request,
    revocation_list: RevocationList,
) -> Decision:
    """Authorize a request and then apply revocation.

    1. Calls ``firewall.check(request)`` to get the Decision
    2. Applies ``revocation_list.check(decision)`` to override if revoked
    3. Returns the final Decision

    This is a post-evaluation wrapper.  It does NOT modify the evaluator,
    the policy, or the firewall.  Revocation is opt-in.
    """
    decision = firewall.check(request)
    return revocation_list.check(decision)
