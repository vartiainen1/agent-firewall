"""Policy test-case evaluation (Phase 3, DESIGN 40).

Evaluate expected-decision assertions against a loaded Policy.  Each test
case is a ``(verdict, agent, action, resource)`` tuple parsed from a simple
text format::

    PASS developer filesystem.read ./src/auth.py
    PASS developer network.connect production-db:5432
    PASS deployer production.deploy

The evaluator calls the core ``evaluate()`` function — it does NOT
re-implement authorization logic.  Tests are deterministic and offline.

Test file format (DESIGN 40):

    PASS agent action [resource]

Lines starting with ``#`` and blank lines are ignored.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional

from .evaluator import evaluate
from .model import (
    DecisionKind,
    InvalidPolicyError,
    InvalidRequestError,
    Request,
)
from .policy import Policy


@dataclass(frozen=True)
class TestCase:
    """One parsed policy test-case assertion."""

    expected: DecisionKind
    agent: str
    action: str
    resource: Optional[str] = None
    line_number: int = 0
    raw_line: str = ""


@dataclass(frozen=True)
class TestCaseResult:
    """The outcome of evaluating one TestCase against a Policy."""

    test_case: TestCase
    actual: DecisionKind
    passed: bool


def parse_test_file(text: str) -> List[TestCase]:
    """Parse a test-file string into a list of TestCase objects.

    Raises ``ValueError`` on malformed lines.
    """
    cases: List[TestCase] = []
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            raise ValueError(
                f"line {line_no}: expected at least 3 tokens "
                f"(VERB AGENT ACTION [RESOURCE]), got {len(parts)}: {line!r}"
            )
        verb = parts[0].upper()
        if verb == "PASS":
            expected = DecisionKind.ALLOW
        elif verb == "FAIL":
            expected = DecisionKind.DENY
        elif verb == "APPROVE":
            expected = DecisionKind.APPROVE
        else:
            raise ValueError(
                f"line {line_no}: unknown verb {parts[0]!r} "
                f"(expected PASS, FAIL, or APPROVE)"
            )
        agent = parts[1]
        action = parts[2]
        resource = parts[3] if len(parts) >= 4 else None
        cases.append(TestCase(
            expected=expected,
            agent=agent,
            action=action,
            resource=resource,
            line_number=line_no,
            raw_line=raw_line.rstrip(),
        ))
    return cases


def parse_test_file_from_path(path: str) -> List[TestCase]:
    """Read and parse a test file from *path*."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise InvalidPolicyError(
            f"could not read test file {path!r}: {exc}"
        ) from exc
    try:
        return parse_test_file(text)
    except ValueError as exc:
        raise InvalidPolicyError(str(exc)) from exc


def run_policy_tests(
    policy: Policy, cases: List[TestCase]
) -> List[TestCaseResult]:
    """Evaluate each TestCase against *policy*.

    Returns a list of TestCaseResult in the same order as *cases*.
    Invalid requests (malformed, absolute path, root escape) are treated as
    ``DENY`` for comparison — the test passes only when the expected verdict
    is also ``DENY`` (or ``APPROVE``, which is never produced by an invalid
    request — so those always fail).

    This function never executes external commands, never accesses the
    network, and never modifies the policy.
    """
    results: List[TestCaseResult] = []
    for tc in cases:
        request = Request(
            agent=tc.agent,
            action=tc.action,
            resource=tc.resource,
        )
        try:
            decision = evaluate(request, policy)
            actual = decision.kind
        except (InvalidRequestError, InvalidPolicyError):
            # Invalid request → fail closed → equivalent to DENY
            actual = DecisionKind.DENY

        results.append(TestCaseResult(
            test_case=tc,
            actual=actual,
            passed=(actual is tc.expected),
        ))
    return results
