"""Policy suggestion validation (Phase 18).

Validate Phase 17 PolicySuggestion objects by constructing a proposed
Policy and comparing it against the source Policy using the existing
lint and policy-test infrastructure.

Trust model:

    suggestions
        |
        v
    proposed_policy() → proposed Policy     (Phase 17)
        |
        +-- lint_policy()                   (Phase 3)
        +-- run_policy_tests()              (Phase 3)
        |
        v
    SuggestionValidationResult              (this module)
        |
        v
    human review

This module is strictly advisory.  It never modifies the source policy,
never activates the proposed policy, never calls Firewall.check(), never
produces Decision objects, and never writes to disk.

Design constraints:
    - Advisory only: results never become authorization decisions.
    - Never mutates the source Policy.
    - Never modifies the active policy.
    - Never calls Firewall.check() or the evaluator directly.
    - Never produces Decision or DecisionKind objects.
    - Never writes to disk or accesses the network.
    - Deterministic for identical inputs.
    - Zero third-party runtime dependencies.
    - Malformed input fails safely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set, Tuple

from .lint import LintFinding, lint_policy
from .policy import Policy
from .suggestions import PolicySuggestion, proposed_policy
from .test_cases import TestCase, TestCaseResult, run_policy_tests


def _lint_key(finding: LintFinding) -> Tuple[str, str, str, str, str]:
    """Comparison key for LintFinding.

    Uses (severity, code, agent, action, resource) — excludes the message
    field so that findings with the same identity but different wording are
    not treated as distinct.
    """
    return (
        finding.severity.value,
        finding.code,
        finding.agent or "",
        finding.action or "",
        finding.resource or "",
    )


def _tc_match_key(result: TestCaseResult) -> Tuple[str, str, str]:
    """Matching key for TestCaseResult.

    Uses (agent, action, resource) to match source and proposed results
    for the same logical test case, regardless of expected verdict,
    line_number, or raw_line differences.
    """
    tc = result.test_case
    return (tc.agent, tc.action, tc.resource or "")


# ── Result dataclass ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SuggestionValidationResult:
    """Advisory result of validating suggestions against lint and test infrastructure.

    This is a proposal-assessment, not an authorization decision.  It never
    modifies the active policy, evaluator, or any filesystem state.
    """

    source_lint_findings: List[LintFinding] = field(default_factory=list)
    proposed_lint_findings: List[LintFinding] = field(default_factory=list)
    new_lint_findings: List[LintFinding] = field(default_factory=list)
    source_test_results: List[TestCaseResult] = field(default_factory=list)
    proposed_test_results: List[TestCaseResult] = field(default_factory=list)
    test_regressions: List[TestCaseResult] = field(default_factory=list)
    is_clean: bool = True


# ── Validator ───────────────────────────────────────────────────────────────


class SuggestionValidator:
    """Validates suggestions against existing lint and policy-test infrastructure.

    This validator is strictly advisory.  It:

    - NEVER modifies the source policy
    - NEVER modifies the active policy
    - NEVER calls Firewall.check()
    - NEVER produces Decision objects
    - NEVER writes to disk
    - NEVER accesses the network
    - NEVER activates suggestions

    Results must be reviewed by a human before any policy activation
    occurs.
    """

    def __init__(
        self,
        policy: Policy,
        test_cases: List[TestCase],
    ) -> None:
        """Initialize with a source policy and test cases.

        The validator holds read-only references.  It never modifies
        the provided policy or test cases.
        """
        if not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy instance")
        if not isinstance(test_cases, list):
            raise TypeError("test_cases must be a list")
        self._policy = policy
        self._test_cases = list(test_cases)  # shallow copy of the list

    @property
    def policy(self) -> Policy:
        """Return the source policy (read-only reference)."""
        return self._policy

    @property
    def test_cases(self) -> List[TestCase]:
        """Return the test cases (read-only copy)."""
        return list(self._test_cases)

    def validate(
        self,
        suggestions: List[PolicySuggestion],
    ) -> SuggestionValidationResult:
        """Validate suggestions against lint and policy-test infrastructure.

        Constructs a proposed policy from the suggestions, then compares
        lint findings and test results between source and proposed policies.

        Returns a SuggestionValidationResult.  Never modifies the source
        policy, active policy, evaluator, or any filesystem state.
        """
        if not isinstance(suggestions, list):
            suggestions = []

        # 1. Construct proposed policy (Phase 17)
        new_policy = proposed_policy(self._policy, suggestions)

        # 2. Run lint on both policies (Phase 3)
        source_lint = lint_policy(self._policy)
        proposed_lint = lint_policy(new_policy)

        # 3. Identify new lint findings using key-based comparison
        source_keys: Set[Tuple[str, str, str, str, str]] = {
            _lint_key(f) for f in source_lint
        }
        new_lint = [
            f for f in proposed_lint
            if _lint_key(f) not in source_keys
        ]

        # 4. Run policy tests on both policies (Phase 3)
        source_test = run_policy_tests(self._policy, self._test_cases)
        proposed_test = run_policy_tests(new_policy, self._test_cases)

        # 5. Identify test regressions
        #    Build a map from match_key → source result
        source_by_key: dict = {}
        for r in source_test:
            key = _tc_match_key(r)
            source_by_key[key] = r

        regressions: List[TestCaseResult] = []
        for prop_r in proposed_test:
            key = _tc_match_key(prop_r)
            src_r = source_by_key.get(key)
            if src_r is not None and src_r.passed and not prop_r.passed:
                regressions.append(prop_r)

        # 6. Compute is_clean
        is_clean = len(new_lint) == 0 and len(regressions) == 0

        return SuggestionValidationResult(
            source_lint_findings=source_lint,
            proposed_lint_findings=proposed_lint,
            new_lint_findings=new_lint,
            source_test_results=source_test,
            proposed_test_results=proposed_test,
            test_regressions=regressions,
            is_clean=is_clean,
        )
