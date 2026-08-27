"""Core data structures for agent-firewall.

This module is the bottom of the trust hierarchy: it holds only plain,
immutable value objects and the two failure exception types. It performs no
parsing, no matching and no evaluation, and it is side-effect free.

Everything here is deterministic.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class InvalidRequestError(ValueError):
    """A request is malformed and cannot be evaluated.

    A malformed request must fail closed: it is never converted into a
    decision, and in particular never into ALLOW (SPEC 4/36, SECURITY 22).
    """


class InvalidPolicyError(ValueError):
    """A policy is malformed or unsupported and cannot become active.

    A malformed policy must fail before authorization begins; a partially
    valid policy must never be treated as active (SPEC 35/37, SECURITY 22).
    """


class UnsupportedPolicyVersionError(InvalidPolicyError):
    """The policy carries a version this implementation does not support.

    Unknown versions fail closed; semantics are never guessed (SPEC 19,
    DESIGN 30).
    """


class DecisionKind(Enum):
    """The three authorization decisions (SPEC 3)."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVE = "APPROVE"


@dataclass(frozen=True)
class Request:
    """One attempted action by one agent (SPEC 5)."""

    agent: str
    action: str
    resource: Optional[str] = None


@dataclass(frozen=True)
class Rule:
    """A single policy rule: an action plus an optional resource pattern.

    ``resource`` is the pattern as written in the policy document.
    ``resource_segments`` is the pre-normalized, canonical pattern used for
    deterministic matching; ``None`` means the rule applies to the action
    generally, regardless of resource (SPEC 10).
    """

    action: str
    resource: Optional[str] = None
    resource_segments: Optional[Tuple[str, ...]] = None


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating one request (SPEC 20).

    Only ever carries ALLOW, DENY or APPROVE. Errors are raised as
    exceptions instead of being represented here, so a Decision is never a
    way for an invalid request to become ALLOW.
    """

    kind: DecisionKind
    agent: str
    action: str
    resource: Optional[str] = None
    rule: Optional[Rule] = None
    reason: str = ""
    policy_version: Optional[int] = None
    policy_generation: Optional[int] = None

    @property
    def allowed(self) -> bool:
        """True only for ALLOW (DESIGN 42). DENY/APPROVE/error are not."""
        return self.kind is DecisionKind.ALLOW