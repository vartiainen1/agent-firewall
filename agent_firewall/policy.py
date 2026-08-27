"""Policy parsing, validation and immutable snapshot construction.

Responsibility (IMPLEMENTATION 6): load, parse, validate and build an
immutable Policy. It never evaluates requests.

Fail-closed contract (SPEC 35/37, SECURITY 22):
  * a missing/unsupported version fails;
  * a malformed policy fails before authorization;
  * a partially valid policy is never accepted as active;
  * unknown fields at every level are rejected so a typo'd key cannot
    silently grant or hide permissions.
"""

import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional, Tuple

from .model import (
    InvalidPolicyError,
    InvalidRequestError,
    Rule,
    UnsupportedPolicyVersionError,
)
from .normalize import normalize_pattern_segments

SUPPORTED_VERSION = 1

_AGENT_FIELDS = ("allow", "deny", "approve")
_RULE_FIELDS = ("action", "resource")
_TOP_FIELDS = ("version", "agents")


@dataclass(frozen=True)
class AgentPolicy:
    """The allow/deny/approve rule collections for one agent (SPEC 11)."""

    allow: Tuple[Rule, ...] = ()
    deny: Tuple[Rule, ...] = ()
    approve: Tuple[Rule, ...] = ()


@dataclass(frozen=True)
class Policy:
    """An immutable policy snapshot (SPEC 18, DESIGN 29)."""

    version: int
    generation: int = 1
    agents: Mapping[str, AgentPolicy] = field(
        default_factory=lambda: MappingProxyType({}))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidPolicyError(message)


def _require_str(value: Any, label: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{label} must be a non-empty string")
    return value


def _parse_rules(raw: Any, label: str) -> Tuple[Rule, ...]:
    _require(isinstance(raw, list), f"{label} must be a list")
    rules = []
    for i, item in enumerate(raw):
        _require(isinstance(item, dict), f"{label}[{i}] must be an object")
        for key in item:
            _require(key in _RULE_FIELDS,
                     f"{label}[{i}] has unknown field {key!r}")
        action = _require_str(item.get("action"), f"{label}[{i}].action")
        resource = item.get("resource", None)
        if resource is not None:
            _require(isinstance(resource, str),
                     f"{label}[{i}].resource must be a string")
        try:
            segments = normalize_pattern_segments(action, resource)
        except InvalidRequestError as exc:
            # A policy rule whose resource pattern attempts to escape the
            # workspace root is an INVALID POLICY, not an invalid request:
            # fail closed before it can ever become active (SPEC 35/37).
            raise InvalidPolicyError(
                f"{label}[{i}] has an invalid resource pattern: {exc}") from exc
        rules.append(Rule(
            action=action,
            resource=resource,
            resource_segments=segments,
        ))
    return tuple(rules)


def _parse_agent_policy(raw: Any, name: str) -> AgentPolicy:
    _require(isinstance(raw, dict), f"agent {name!r} must be an object")
    for key in raw:
        _require(key in _AGENT_FIELDS,
                 f"agent {name!r} has unknown field {key!r}")
    return AgentPolicy(
        allow=_parse_rules(raw.get("allow", []), f"agent {name!r} allow"),
        deny=_parse_rules(raw.get("deny", []), f"agent {name!r} deny"),
        approve=_parse_rules(raw.get("approve", []), f"agent {name!r} approve"),
    )


def policy_from_dict(data: Any, generation: int = 1) -> Policy:
    """Parse and validate a policy mapping into an immutable snapshot."""
    if not isinstance(data, dict):
        raise InvalidPolicyError("policy must be a JSON object")

    for key in data:
        if key not in _TOP_FIELDS:
            raise InvalidPolicyError(f"policy has unknown field {key!r}")

    _require("version" in data, "policy is missing 'version'")
    version = data["version"]
    _require(isinstance(version, int) and not isinstance(version, bool),
             "policy 'version' must be an integer")
    if version != SUPPORTED_VERSION:
        raise UnsupportedPolicyVersionError(
            f"unsupported policy version {version!r} (supported: {SUPPORTED_VERSION})")

    _require("agents" in data, "policy is missing 'agents'")
    agents_raw = data["agents"]
    _require(isinstance(agents_raw, dict), "policy 'agents' must be an object")

    agents = {
        name: _parse_agent_policy(cfg, name)
        for name, cfg in agents_raw.items()
    }
    return Policy(version=version, generation=generation,
                  agents=MappingProxyType(agents))


def policy_from_file(path: str, generation: int = 1) -> Policy:
    """Load and parse a policy document from a JSON file.

    Any read or parse failure raises InvalidPolicyError (fail closed); no
    partial policy is ever returned.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise InvalidPolicyError(f"could not read policy file {path!r}: {exc}") from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise InvalidPolicyError(f"policy file {path!r} is not valid JSON: {exc}") from exc
    return policy_from_dict(data, generation=generation)