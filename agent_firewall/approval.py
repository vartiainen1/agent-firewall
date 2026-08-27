"""Approval records, validation, and request hashing (Phase 5).

An approval is a structured credential created by an external trusted
authority after the evaluator produces an APPROVE decision.  It proves
that a specific request was reviewed and authorized by someone other
than the requesting agent.

Phase 5 scope (ROADMAP §5):
    - approval records
    - request hashes
    - approval binding
    - approval expiration
    - approval validation
    - self-approval protection

Phase 5 does NOT implement:
    - hash-chained evidence (Phase 15)
    - approval revocation (Phase 15)
    - signed policies (Phase 15)
    - distributed approvals
    - approval consumption tracking

Security properties (SPEC 25-29, DESIGN 25-28, SECURITY 10-12):
    - approval binds to exact request via SHA-256 hash
    - binding includes agent, action, resource, policy_version, policy_generation
    - expired approvals are rejected
    - self-approval is rejected (approved_by != agent)
    - malformed approvals fail closed
    - validation never bypasses policy evaluation
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .model import Decision, DecisionKind, InvalidRequestError


# ── Approval record ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Approval:
    """A structured approval credential.

    Created by an external trusted authority.  Validated by comparing
    the recomputed request hash against the stored hash.
    """

    approval_id: str
    request_hash: str
    approved_by: str
    issued_at: str
    expires_at: Optional[str] = None
    policy_version: int = 0
    policy_generation: int = 0
    reason: Optional[str] = None


# ── Canonical request serialization ───────────────────────────────────────────

def canonical_request(
    agent: str,
    action: str,
    resource: Optional[str],
    policy_version: int,
    policy_generation: int,
) -> str:
    """Produce a deterministic canonical serialization of a request.

    Includes only authorization-relevant fields.  Uses deterministic
    JSON with sorted keys and no extraneous whitespace (IMPLEMENTATION 19,
    DESIGN 68).

    ``resource`` is included as JSON ``null`` when absent, ensuring
    two requests differing only in resource presence produce different
    serializations.
    """
    data: Dict[str, Any] = {
        "action": action,
        "agent": agent,
        "policy_generation": policy_generation,
        "policy_version": policy_version,
        "resource": resource,
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def compute_request_hash(
    agent: str,
    action: str,
    resource: Optional[str],
    policy_version: int,
    policy_generation: int,
) -> str:
    """Compute the SHA-256 hex digest of a canonical request.

    Deterministic across Python versions and platforms (SPEC 26,
    DESIGN 69).  Uses only the standard library.
    """
    canonical = canonical_request(agent, action, resource,
                                 policy_version, policy_generation)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def hash_request(
    agent: str,
    action: str,
    resource: Optional[str],
    policy_version: int,
    policy_generation: int,
) -> str:
    """Convenience alias for ``compute_request_hash``."""
    return compute_request_hash(agent, action, resource,
                                policy_version, policy_generation)


# ── Approval validation ───────────────────────────────────────────────────────

class ApprovalError(Exception):
    """An approval is invalid or cannot be validated.

    This is NOT an authorization decision.  It means the approval
    credential is invalid.  The caller must treat this as DENY.
    """


class ApprovalValidator:
    """Validate an Approval against a Decision.

    The validator compares:
        1. request hash (agent+action+resource+policy_version+policy_generation)
        2. expiration
        3. self-approval (approved_by != agent)

    The evaluator MUST run first (producing APPROVE).  The validator
    does NOT call evaluate() — it only validates the approval credential.
    Revalidation after successful approval is the caller's responsibility.
    """

    @staticmethod
    def validate(approval: Approval, decision: Decision) -> None:
        """Validate *approval* against *decision*.

        Raises ``ApprovalError`` if the approval is invalid.
        Returns silently if valid.

        This method must not raise for valid approvals.  For invalid
        approvals it must ALWAYS raise — never silently accept.
        """
        # 1. Verify decision is APPROVE
        if decision.kind is not DecisionKind.APPROVE:
            raise ApprovalError(
                "approval can only validate APPROVE decisions"
            )

        # 2. Verify required fields
        if not approval.approval_id:
            raise ApprovalError("approval_id is required and must be non-empty")
        if not approval.request_hash:
            raise ApprovalError("request_hash is required and must be non-empty")
        if not approval.approved_by:
            raise ApprovalError("approved_by is required and must be non-empty")
        if not approval.issued_at:
            raise ApprovalError("issued_at is required and must be non-empty")

        # 3. Compute expected hash from decision
        expected_hash = compute_request_hash(
            agent=decision.agent,
            action=decision.action,
            resource=decision.resource,
            policy_version=decision.policy_version,
            policy_generation=decision.policy_generation,
        )

        # 4. Compare hashes
        if not _hashes_match(approval.request_hash, expected_hash):
            raise ApprovalError("request_hash does not match")

        # 5. Check expiration
        if approval.expires_at is not None:
            try:
                expires = datetime.fromisoformat(
                    approval.expires_at.replace("Z", "+00:00")
                )
            except (ValueError, TypeError) as exc:
                raise ApprovalError(
                    f"invalid expires_at timestamp: {exc}"
                ) from exc
            now = datetime.now(timezone.utc)
            if now > expires:
                raise ApprovalError("approval has expired")

        # 6. Check self-approval
        if approval.approved_by == decision.agent:
            raise ApprovalError(
                "self-approval is not permitted: "
                f"approved_by {approval.approved_by!r} equals agent {decision.agent!r}"
            )


def _hashes_match(stored: str, expected: str) -> bool:
    """Constant-time comparison of two hash strings.

    Uses ``hmac.compare_digest`` to prevent timing side channels.
    """
    import hmac
    return hmac.compare_digest(stored, expected)


# ── Approval file I/O ─────────────────────────────────────────────────────────

def approval_from_dict(data: Dict[str, Any]) -> Approval:
    """Parse an approval record from a dict.

    Raises ``ApprovalError`` on missing or invalid fields.
    """
    required = ("approval_id", "request_hash", "approved_by", "issued_at",
                "policy_version", "policy_generation")
    for field in required:
        if field not in data:
            raise ApprovalError(f"missing required field: {field!r}")

    # Validate types
    if not isinstance(data["approval_id"], str) or not data["approval_id"]:
        raise ApprovalError("approval_id must be a non-empty string")
    if not isinstance(data["request_hash"], str) or not data["request_hash"]:
        raise ApprovalError("request_hash must be a non-empty string")
    if not isinstance(data["approved_by"], str) or not data["approved_by"]:
        raise ApprovalError("approved_by must be a non-empty string")
    if not isinstance(data["issued_at"], str) or not data["issued_at"]:
        raise ApprovalError("issued_at must be a non-empty string")
    if not isinstance(data["policy_version"], int):
        raise ApprovalError("policy_version must be an integer")
    if not isinstance(data["policy_generation"], int):
        raise ApprovalError("policy_generation must be an integer")

    expires_at = data.get("expires_at")
    if expires_at is not None and not isinstance(expires_at, str):
        raise ApprovalError("expires_at must be a string or null")

    reason = data.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise ApprovalError("reason must be a string or null")

    return Approval(
        approval_id=data["approval_id"],
        request_hash=data["request_hash"],
        approved_by=data["approved_by"],
        issued_at=data["issued_at"],
        expires_at=expires_at,
        policy_version=data["policy_version"],
        policy_generation=data["policy_generation"],
        reason=reason,
    )


def approval_from_file(path: str) -> Approval:
    """Load and parse an approval record from a JSON file.

    Raises ``ApprovalError`` on any read or parse failure.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise ApprovalError(
            f"could not read approval file {path!r}: {exc}"
        ) from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ApprovalError(
            f"approval file {path!r} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ApprovalError("approval must be a JSON object")
    return approval_from_dict(data)
