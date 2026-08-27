"""Policy simulation — compare current vs proposed policy (Phase 6).

Evaluate the same set of requests against two independent policy snapshots
and report the differences.  The proposed policy is NEVER activated;
the current policy remains authoritative.

Properties:
    - read-only (no files written, no state mutated)
    - deterministic
    - side-effect-free beyond loading the explicitly named policy files
    - zero third-party dependencies
    - uses the existing evaluate() function as-is

Security (DESIGN 85):
    Simulation results are INFORMATIONAL ONLY.
    A simulated ALLOW does not authorize real action.
    The proposed policy must never become the active policy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, List, Optional

from .evaluator import evaluate
from .model import Decision, DecisionKind, InvalidRequestError, Request
from .policy import Policy, policy_from_file


# ── Simulation result ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SimulationResult:
    """One request evaluated against both current and proposed policies.

    ``changed`` is True exactly when the two decision kinds differ
    (e.g. current=DENY, proposed=ALLOW).
    """

    request: Request
    current_decision: Decision
    proposed_decision: Decision
    changed: bool


# ── Request file parsing ──────────────────────────────────────────────────────

def parse_requests_from_file(path: str) -> List[Request]:
    """Load a JSON array of request objects from *path*.

    Each object must contain ``agent`` and ``action`` (strings).
    ``resource`` is optional (string or absent).

    Raises ``InvalidRequestError`` on any parse or validation failure.
    The file is read exactly once; no caching or side effects.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise InvalidRequestError(
            f"could not read request file {path!r}: {exc}"
        ) from exc

    try:
        data = json.loads(text)
    except ValueError as exc:
        raise InvalidRequestError(
            f"request file {path!r} is not valid JSON: {exc}"
        ) from exc

    if not isinstance(data, list):
        raise InvalidRequestError(
            f"request file {path!r} must contain a JSON array"
        )

    requests: List[Request] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise InvalidRequestError(
                f"request #{i + 1} is not a JSON object"
            )
        agent = item.get("agent")
        action = item.get("action")
        if not isinstance(agent, str) or not agent:
            raise InvalidRequestError(
                f"request #{i + 1} missing or invalid 'agent'"
            )
        if not isinstance(action, str) or not action:
            raise InvalidRequestError(
                f"request #{i + 1} missing or invalid 'action'"
            )
        resource = item.get("resource")
        if resource is not None and not isinstance(resource, str):
            raise InvalidRequestError(
                f"request #{i + 1} 'resource' must be a string or absent"
            )
        requests.append(Request(agent=agent, action=action, resource=resource))

    return requests


# ── Core simulation ───────────────────────────────────────────────────────────

def simulate_policy_comparison(
    current_policy: Policy,
    proposed_policy: Policy,
    requests: List[Request],
) -> List[SimulationResult]:
    """Evaluate *requests* against both policy snapshots independently.

    Returns one ``SimulationResult`` per request, in the same order.
    Each result contains the decision from the current policy, the
    decision from the proposed policy, and whether they differ.

    This function must not:
        - modify either policy
        - activate the proposed policy
        - write files
        - access the network
        - call an LLM
        - produce audit records
        - produce approval validations
    """
    results: List[SimulationResult] = []
    for request in requests:
        current = evaluate(request, current_policy)
        proposed = evaluate(request, proposed_policy)
        results.append(
            SimulationResult(
                request=request,
                current_decision=current,
                proposed_decision=proposed,
                changed=current.kind is not proposed.kind,
            )
        )
    return results


# ── Convenience: load-and-simulate ────────────────────────────────────────────

def simulate_from_files(
    current_path: str,
    proposed_path: str,
    requests_path: str,
) -> List[SimulationResult]:
    """Load both policies and the request file, then run the comparison.

    Raises ``InvalidPolicyError`` / ``InvalidRequestError`` on any
    loading failure.  The proposed policy file is loaded into a
    separate ``Policy`` snapshot and is never activated.
    """
    from .policy import policy_from_file as _load

    current = _load(current_path)
    proposed = _load(proposed_path)
    requests = parse_requests_from_file(requests_path)
    return simulate_policy_comparison(current, proposed, requests)
