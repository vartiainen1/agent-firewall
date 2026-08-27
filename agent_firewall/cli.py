"""CLI interface for agent-firewall.

Phase 2 commands:

    agent-firewall check   — evaluate one request, print the decision
    agent-firewall explain — evaluate one request, print a detailed explanation

Phase 3 commands:

    agent-firewall lint         — lint a policy file for structural/semantic issues
    agent-firewall test         — evaluate policy test cases against a policy
    agent-firewall capabilities — show effective permissions per agent

All commands accept ``--policy`` (path to a policy JSON file).
check/explain additionally accept ``--agent``, ``--action``, ``--resource``
and ``--json``.  The CLI is a thin wrapper around the core API
(IMPLEMENTATION 14) and contains no authorization logic of its own.

Exit codes (SPEC 22, public API):

    0 = ALLOW / success
    1 = DENY / findings / test failures
    2 = APPROVE
    3 = INVALID_REQUEST
    4 = INVALID_POLICY
    5 = INTERNAL_ERROR

The CLI must not bypass the evaluator.  Every decision comes from
``Firewall.check()`` / ``evaluate()``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import NoReturn

from . import (
    Firewall,
    InvalidPolicyError,
    InvalidRequestError,
    Request,
    UnsupportedPolicyVersionError,
)

# ── Exit codes (IMPLEMENTATION 16) ────────────────────────────────────────────
# One canonical location.  Never scatter numeric literals elsewhere.

EXIT_ALLOW = 0
EXIT_DENY = 1
EXIT_APPROVE = 2
EXIT_INVALID_REQUEST = 3
EXIT_INVALID_POLICY = 4
EXIT_INTERNAL_ERROR = 5


# ── Renderers ─────────────────────────────────────────────────────────────────

def _decision_to_dict(decision) -> dict:
    """Convert a Decision object to a plain dict for JSON output (SPEC 24)."""
    d = {
        "decision": decision.kind.value,
        "agent": decision.agent,
        "action": decision.action,
    }
    if decision.resource is not None:
        d["resource"] = decision.resource
    if decision.rule is not None:
        rule: dict = {"action": decision.rule.action}
        if decision.rule.resource is not None:
            rule["resource"] = decision.rule.resource
        d["rule"] = rule
    if decision.reason:
        d["reason"] = decision.reason
    if decision.policy_version is not None:
        d["policy_version"] = decision.policy_version
    if decision.policy_generation is not None:
        d["policy_generation"] = decision.policy_generation
    return d


def _render_json(decision) -> None:
    """Print the decision as a single JSON object to stdout."""
    print(json.dumps(_decision_to_dict(decision), indent=2))


def _render_text(decision) -> None:
    """Print a single-line human-readable decision to stdout."""
    print(decision.kind.value)


def _render_explain_text(decision) -> None:
    """Print a structured human-readable explanation to stdout."""
    lines = [
        f"Decision: {decision.kind.value}",
        "",
        "Agent:",
        f"  {decision.agent}",
        "",
        "Action:",
        f"  {decision.action}",
    ]
    if decision.resource is not None:
        lines += ["", "Resource:", f"  {decision.resource}"]
    if decision.rule is not None:
        rule_str = decision.rule.action
        if decision.rule.resource:
            rule_str += f" {decision.rule.resource}"
        lines += ["", "Matched rule:", f"  {rule_str}"]
    if decision.reason:
        lines += ["", "Reason:", f"  {decision.reason}"]
    print("\n".join(lines))


def _render_explain_json(decision) -> None:
    """Print the explanation as JSON (same schema as check --json)."""
    _render_json(decision)


# ── Lint renderers ────────────────────────────────────────────────────────────

def _render_lint_text(findings) -> None:
    """Print lint findings as human-readable text."""
    for f in findings:
        loc = f.agent or ""
        if f.action:
            loc += f"/{f.action}" if loc else f.action
        if f.resource:
            loc += f":{f.resource}"
        suffix = f" ({loc})" if loc else ""
        print(f"{f.severity.value.upper()}: [{f.code}] {f.message}{suffix}")


def _render_lint_json(findings) -> None:
    """Print lint findings as a JSON array."""
    items = []
    for f in findings:
        d = {
            "severity": f.severity.value,
            "code": f.code,
            "message": f.message,
        }
        if f.agent is not None:
            d["agent"] = f.agent
        if f.action is not None:
            d["action"] = f.action
        if f.resource is not None:
            d["resource"] = f.resource
        items.append(d)
    print(json.dumps(items, indent=2))


# ── Test-case renderers ───────────────────────────────────────────────────────

def _render_test_text(results) -> None:
    """Print policy test results as human-readable text."""
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        tc = r.test_case
        line = f"{status} {tc.agent} {tc.action}"
        if tc.resource:
            line += f" {tc.resource}"
        if not r.passed:
            line += f"  (expected {tc.expected.value}, got {r.actual.value})"
        print(line)


def _render_test_json(results) -> None:
    """Print policy test results as a JSON array."""
    items = []
    for r in results:
        tc = r.test_case
        d = {
            "passed": r.passed,
            "expected": tc.expected.value,
            "actual": r.actual.value,
            "agent": tc.agent,
            "action": tc.action,
        }
        if tc.resource is not None:
            d["resource"] = tc.resource
        if tc.line_number:
            d["line"] = tc.line_number
        items.append(d)
    print(json.dumps(items, indent=2))


# ── Capabilities renderers ────────────────────────────────────────────────────

def _render_capabilities_text(policy) -> None:
    """Print effective permissions per agent as human-readable text."""
    for name in sorted(policy.agents):
        ap = policy.agents[name]
        print(f"Agent: {name}")
        if ap.allow:
            for rule in ap.allow:
                line = f"  allow {rule.action}"
                if rule.resource:
                    line += f" {rule.resource}"
                print(line)
        if ap.deny:
            for rule in ap.deny:
                line = f"  deny  {rule.action}"
                if rule.resource:
                    line += f" {rule.resource}"
                print(line)
        if ap.approve:
            for rule in ap.approve:
                line = f"  approve {rule.action}"
                if rule.resource:
                    line += f" {rule.resource}"
                print(line)
        if not ap.allow and not ap.deny and not ap.approve:
            print("  (no rules)")
        print()


def _render_capabilities_json(policy) -> None:
    """Print effective permissions as a JSON object."""
    agents = {}
    for name in sorted(policy.agents):
        ap = policy.agents[name]
        agent_data: dict = {}
        if ap.allow:
            agent_data["allow"] = [
                {"action": r.action, **({"resource": r.resource} if r.resource else {})}
                for r in ap.allow
            ]
        if ap.deny:
            agent_data["deny"] = [
                {"action": r.action, **({"resource": r.resource} if r.resource else {})}
                for r in ap.deny
            ]
        if ap.approve:
            agent_data["approve"] = [
                {"action": r.action, **({"resource": r.resource} if r.resource else {})}
                for r in ap.approve
            ]
        agents[name] = agent_data
    print(json.dumps({"version": policy.version, "agents": agents}, indent=2))


# ── Evidence recording ───────────────────────────────────────────────────────

def _record_evidence(path: str, decision) -> None:
    """Append a Decision as one JSONL evidence record.

    Non-fatal: if recording fails, a warning is printed to stderr and the
    original authorization decision is preserved.
    """
    from .audit import EvidenceLogger

    logger = EvidenceLogger(path)
    logger.record(decision)
    logger.close()


# ── Command implementations ───────────────────────────────────────────────────

def _exit_code_from_decision(decision) -> int:
    """Map a Decision to the documented exit code."""
    from .model import DecisionKind

    if decision.kind is DecisionKind.ALLOW:
        return EXIT_ALLOW
    elif decision.kind is DecisionKind.DENY:
        return EXIT_DENY
    elif decision.kind is DecisionKind.APPROVE:
        return EXIT_APPROVE
    else:
        return EXIT_INTERNAL_ERROR


def _run_check(args: argparse.Namespace) -> int:
    """Execute ``agent-firewall check`` and return the exit code."""
    try:
        firewall = Firewall.from_file(args.policy)
    except (InvalidPolicyError, UnsupportedPolicyVersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: unexpected error loading policy: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    request = Request(
        agent=args.agent,
        action=args.action,
        resource=args.resource,
    )

    try:
        decision = firewall.check(request)
    except InvalidRequestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_REQUEST
    except InvalidPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: unexpected error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    if getattr(args, "audit", None):
        _record_evidence(args.audit, decision)

    if args.json:
        _render_json(decision)
    else:
        _render_text(decision)

    return _exit_code_from_decision(decision)


def _run_explain(args: argparse.Namespace) -> int:
    """Execute ``agent-firewall explain`` and return the exit code."""
    try:
        firewall = Firewall.from_file(args.policy)
    except (InvalidPolicyError, UnsupportedPolicyVersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: unexpected error loading policy: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    request = Request(
        agent=args.agent,
        action=args.action,
        resource=args.resource,
    )

    try:
        decision = firewall.check(request)
    except InvalidRequestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_REQUEST
    except InvalidPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: unexpected error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    if getattr(args, "audit", None):
        _record_evidence(args.audit, decision)

    if args.json:
        _render_explain_json(decision)
    else:
        _render_explain_text(decision)

    return _exit_code_from_decision(decision)


def _run_lint(args: argparse.Namespace) -> int:
    """Execute ``agent-firewall lint`` and return the exit code."""
    from .lint import lint_policy
    from .policy import policy_from_file

    try:
        policy = policy_from_file(args.policy)
    except (InvalidPolicyError, UnsupportedPolicyVersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: unexpected error loading policy: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    try:
        findings = lint_policy(policy)
    except Exception as exc:
        print(f"error: unexpected error during lint: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    if args.json:
        _render_lint_json(findings)
    else:
        _render_lint_text(findings)

    # Exit 1 if any findings, 0 if clean
    return EXIT_DENY if findings else EXIT_ALLOW


def _run_test(args: argparse.Namespace) -> int:
    """Execute ``agent-firewall test`` and return the exit code."""
    from .policy import policy_from_file
    from .test_cases import parse_test_file_from_path, run_policy_tests

    try:
        policy = policy_from_file(args.policy)
    except (InvalidPolicyError, UnsupportedPolicyVersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: unexpected error loading policy: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    try:
        cases = parse_test_file_from_path(args.test_file)
    except InvalidPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: could not read test file: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    if not cases:
        print("warning: no test cases found", file=sys.stderr)
        return EXIT_ALLOW

    try:
        results = run_policy_tests(policy, cases)
    except Exception as exc:
        print(f"error: unexpected error running tests: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    if args.json:
        _render_test_json(results)
    else:
        _render_test_text(results)

    all_passed = all(r.passed for r in results)
    return EXIT_ALLOW if all_passed else EXIT_DENY


def _run_capabilities(args: argparse.Namespace) -> int:
    """Execute ``agent-firewall capabilities`` and return the exit code."""
    from .policy import policy_from_file

    try:
        policy = policy_from_file(args.policy)
    except (InvalidPolicyError, UnsupportedPolicyVersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: unexpected error loading policy: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    if args.agent:
        # Filter to one agent
        if args.agent not in policy.agents:
            print(f"error: agent {args.agent!r} not found in policy", file=sys.stderr)
            return EXIT_INVALID_REQUEST
        from .policy import Policy as PolicyType
        from types import MappingProxyType
        filtered = PolicyType(
            version=policy.version,
            generation=policy.generation,
            agents=MappingProxyType({args.agent: policy.agents[args.agent]}),
        )
        policy = filtered

    if args.json:
        _render_capabilities_json(policy)
    else:
        _render_capabilities_text(policy)

    return EXIT_ALLOW


def _run_approve(args: argparse.Namespace) -> int:
    """Execute ``agent-firewall approve`` and return the exit code."""
    from .approval import ApprovalError, ApprovalValidator, approval_from_file
    from .policy import policy_from_file

    # 1. Load policy
    try:
        firewall = Firewall.from_file(args.policy)
    except (InvalidPolicyError, UnsupportedPolicyVersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: unexpected error loading policy: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    from .model import DecisionKind

    # 2. Build request and evaluate (must get APPROVE)
    request = Request(
        agent=args.agent,
        action=args.action,
        resource=args.resource,
    )
    try:
        decision = firewall.check(request)
    except InvalidRequestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_REQUEST
    except InvalidPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: unexpected error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    if decision.kind is not DecisionKind.APPROVE:
        # Not an APPROVE decision — approval validation is not applicable
        if args.json:
            print(json.dumps({
                "decision": decision.kind.value,
                "approved": False,
                "reason": "decision is not APPROVE; approval validation not applicable",
            }, indent=2))
        else:
            print(f"{decision.kind.value} — approval validation not applicable")
        return _exit_code_from_decision(decision)

    # 3. Load approval
    try:
        approval = approval_from_file(args.approval)
    except ApprovalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if args.json:
            print(json.dumps({
                "decision": "APPROVE",
                "approved": False,
                "reason": f"approval load failed: {exc}",
            }, indent=2))
        else:
            print(f"DENY — approval invalid: {exc}")
        return EXIT_DENY
    except Exception as exc:
        print(f"error: unexpected error loading approval: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    # 4. Validate approval
    try:
        ApprovalValidator.validate(approval, decision)
    except ApprovalError as exc:
        if args.json:
            print(json.dumps({
                "decision": "APPROVE",
                "approved": False,
                "reason": str(exc),
                "approval_id": approval.approval_id,
            }, indent=2))
        else:
            print(f"DENY — {exc}")
        return EXIT_DENY

    # 5. Approval valid — print ALLOW
    if args.json:
        print(json.dumps({
            "decision": "ALLOW",
            "approved": True,
            "approval_id": approval.approval_id,
            "approved_by": approval.approved_by,
        }, indent=2))
    else:
        print("ALLOW")
    return EXIT_ALLOW


# ── Simulation renderers ─────────────────────────────────────────────────────

def _render_simulate_text(results) -> None:
    """Print simulation comparison as human-readable text."""
    print("SIMULATION — proposed policy is NOT active")
    print()
    for r in results:
        req = r.request
        print(f"  agent:    {req.agent}")
        print(f"  action:   {req.action}")
        if req.resource is not None:
            print(f"  resource: {req.resource}")
        print(f"  current:  {r.current_decision.kind.value}")
        print(f"  proposed: {r.proposed_decision.kind.value}")
        print()


def _render_simulate_json(results) -> None:
    """Print simulation comparison as a JSON array."""
    items = []
    for r in results:
        req = r.request
        d = {
            "agent": req.agent,
            "action": req.action,
            "current": r.current_decision.kind.value,
            "proposed": r.proposed_decision.kind.value,
            "changed": r.changed,
        }
        if req.resource is not None:
            d["resource"] = req.resource
        items.append(d)
    print(json.dumps(items, indent=2))


def _run_simulate(args: argparse.Namespace) -> int:
    """Execute ``agent-firewall simulate`` and return the exit code."""
    from .simulate import parse_requests_from_file, simulate_from_files

    try:
        results = simulate_from_files(args.current, args.proposed, args.requests)
    except InvalidPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except InvalidRequestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_REQUEST
    except Exception as exc:
        print(f"error: unexpected error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    if args.json:
        _render_simulate_json(results)
    else:
        _render_simulate_text(results)

    return EXIT_ALLOW


# ── Diff renderers ───────────────────────────────────────────────────────────

def _render_diff_text(diffs) -> None:
    """Print policy diff as human-readable text."""
    for d in diffs:
        if d.kind == "added":
            line = f"+ {d.agent}: {d.new_rule.action}"
            if d.new_rule.resource:
                line += f" {d.new_rule.resource}"
        elif d.kind == "removed":
            line = f"- {d.agent}: {d.old_rule.action}"
            if d.old_rule.resource:
                line += f" {d.old_rule.resource}"
        elif d.kind == "changed_resource":
            # Show as removed old + added new
            line = f"~ {d.agent}: {d.old_rule.action}"
            if d.old_rule.resource:
                line += f" {d.old_rule.resource}"
            line += f" -> {d.new_rule.resource or '(none)'}"
        else:
            line = f"? {d.agent}: unknown diff kind {d.kind!r}"
        print(line)


def _render_diff_json(diffs) -> None:
    """Print policy diff as a JSON array."""
    items = []
    for d in diffs:
        item = {
            "agent": d.agent,
            "collection": d.collection,
            "kind": d.kind,
            "action": d.new_rule.action if d.new_rule else d.old_rule.action,
        }
        if d.kind == "added" and d.new_rule:
            item["resource"] = d.new_rule.resource
        elif d.kind == "removed" and d.old_rule:
            item["resource"] = d.old_rule.resource
        elif d.kind == "changed_resource":
            item["old_resource"] = d.old_rule.resource if d.old_rule else None
            item["new_resource"] = d.new_rule.resource if d.new_rule else None
        else:
            item["resource"] = None
        items.append(item)
    print(json.dumps(items, indent=2))


def _run_diff(args: argparse.Namespace) -> int:
    """Execute ``agent-firewall diff`` and return the exit code."""
    from .diff import diff_policies
    from .policy import policy_from_file as _load

    try:
        old = _load(args.old)
        new = _load(args.new)
    except (InvalidPolicyError, UnsupportedPolicyVersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY
    except Exception as exc:
        print(f"error: unexpected error loading policy: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    try:
        diffs = diff_policies(old, new)
    except Exception as exc:
        print(f"error: unexpected error during diff: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    if args.json:
        _render_diff_json(diffs)
    else:
        _render_diff_text(diffs)

    return EXIT_ALLOW


# ── Argument parsing ──────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="agent-firewall",
        description="A small, deterministic authorization primitive for AI agents.",
    )
    sub = parser.add_subparsers(dest="command")

    # ── check ─────────────────────────────────────────────────────────────
    check_p = sub.add_parser(
        "check",
        help="Evaluate one request and print the decision.",
    )
    check_p.add_argument(
        "--policy", required=True,
        help="Path to the policy JSON file.",
    )
    check_p.add_argument(
        "--agent", required=True,
        help="Agent identifier.",
    )
    check_p.add_argument(
        "--action", required=True,
        help="Action identifier (e.g. filesystem.read).",
    )
    check_p.add_argument(
        "--resource", default=None,
        help="Resource identifier (optional).",
    )
    check_p.add_argument(
        "--json", dest="json", action="store_true", default=False,
        help="Output the decision as JSON.",
    )
    check_p.add_argument(
        "--audit", default=None,
        help="Append evidence records to this JSONL file (optional).",
    )

    # ── explain ───────────────────────────────────────────────────────────
    explain_p = sub.add_parser(
        "explain",
        help="Evaluate one request and print a detailed explanation.",
    )
    explain_p.add_argument(
        "--policy", required=True,
        help="Path to the policy JSON file.",
    )
    explain_p.add_argument(
        "--agent", required=True,
        help="Agent identifier.",
    )
    explain_p.add_argument(
        "--action", required=True,
        help="Action identifier (e.g. filesystem.read).",
    )
    explain_p.add_argument(
        "--resource", default=None,
        help="Resource identifier (optional).",
    )
    explain_p.add_argument(
        "--json", dest="json", action="store_true", default=False,
        help="Output the explanation as JSON.",
    )
    explain_p.add_argument(
        "--audit", default=None,
        help="Append evidence records to this JSONL file (optional).",
    )

    # ── lint ──────────────────────────────────────────────────────────────
    lint_p = sub.add_parser(
        "lint",
        help="Lint a policy file for structural and semantic issues.",
    )
    lint_p.add_argument(
        "--policy", required=True,
        help="Path to the policy JSON file.",
    )
    lint_p.add_argument(
        "--json", dest="json", action="store_true", default=False,
        help="Output findings as JSON.",
    )

    # ── test ──────────────────────────────────────────────────────────────
    test_p = sub.add_parser(
        "test",
        help="Evaluate policy test cases against a policy.",
    )
    test_p.add_argument(
        "--policy", required=True,
        help="Path to the policy JSON file.",
    )
    test_p.add_argument(
        "test_file",
        help="Path to the test-case file.",
    )
    test_p.add_argument(
        "--json", dest="json", action="store_true", default=False,
        help="Output results as JSON.",
    )

    # ── capabilities ──────────────────────────────────────────────────────
    cap_p = sub.add_parser(
        "capabilities",
        help="Show effective permissions per agent.",
    )
    cap_p.add_argument(
        "--policy", required=True,
        help="Path to the policy JSON file.",
    )
    cap_p.add_argument(
        "--agent", default=None,
        help="Show capabilities for one agent only (optional).",
    )
    cap_p.add_argument(
        "--json", dest="json", action="store_true", default=False,
        help="Output as JSON.",
    )

    # ── approve ───────────────────────────────────────────────────────────
    approve_p = sub.add_parser(
        "approve",
        help="Validate an approval record against a request.",
    )
    approve_p.add_argument(
        "--approval", required=True,
        help="Path to the approval JSON file.",
    )
    approve_p.add_argument(
        "--policy", required=True,
        help="Path to the policy JSON file.",
    )
    approve_p.add_argument(
        "--agent", required=True,
        help="Agent identifier.",
    )
    approve_p.add_argument(
        "--action", required=True,
        help="Action identifier.",
    )
    approve_p.add_argument(
        "--resource", default=None,
        help="Resource identifier (optional).",
    )
    approve_p.add_argument(
        "--json", dest="json", action="store_true", default=False,
        help="Output the result as JSON.",
    )

    # ── simulate ─────────────────────────────────────────────────────────
    sim_p = sub.add_parser(
        "simulate",
        help="Compare current vs proposed policy for a set of requests.",
    )
    sim_p.add_argument(
        "--current", required=True,
        help="Path to the current (active) policy JSON file.",
    )
    sim_p.add_argument(
        "--proposed", required=True,
        help="Path to the proposed (alternative) policy JSON file.",
    )
    sim_p.add_argument(
        "--requests", required=True,
        help="Path to a JSON file containing an array of request objects.",
    )
    sim_p.add_argument(
        "--json", dest="json", action="store_true", default=False,
        help="Output the simulation results as JSON.",
    )

    # ── diff ─────────────────────────────────────────────────────────────
    diff_p = sub.add_parser(
        "diff",
        help="Compare two policies and show structural differences.",
    )
    diff_p.add_argument(
        "--old", required=True,
        help="Path to the old (baseline) policy JSON file.",
    )
    diff_p.add_argument(
        "--new", required=True,
        help="Path to the new (comparison) policy JSON file.",
    )
    diff_p.add_argument(
        "--json", dest="json", action="store_true", default=False,
        help="Output the diff as JSON.",
    )

    return parser


# ── Entry point ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the appropriate command.

    Returns the exit code.  Never returns ``EXIT_ALLOW`` (0) for errors —
    every failure path returns a non-zero code (fail closed).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_INVALID_REQUEST

    if args.command == "check":
        return _run_check(args)
    elif args.command == "explain":
        return _run_explain(args)
    elif args.command == "lint":
        return _run_lint(args)
    elif args.command == "test":
        return _run_test(args)
    elif args.command == "capabilities":
        return _run_capabilities(args)
    elif args.command == "approve":
        return _run_approve(args)
    elif args.command == "simulate":
        return _run_simulate(args)
    elif args.command == "diff":
        return _run_diff(args)
    else:
        parser.print_help()
        return EXIT_INVALID_REQUEST


def entry_point() -> NoReturn:
    """Console_scripts entry point — calls ``main()`` and exits."""
    sys.exit(main())
