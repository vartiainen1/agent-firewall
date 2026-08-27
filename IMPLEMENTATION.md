# IMPLEMENTATION.md — agent-firewall Implementation Guide

## 1. Purpose

This document describes how the specification should be implemented without unnecessarily expanding the project.

The implementation should be small, readable, deterministic, and dependency-free.

---

# 2. Architectural layers

The project should have three conceptual layers:

    Interface
       |
       v
    Core
       |
       v
    Adapters

The core must not depend on adapters.

---

# 3. Core

The core contains:

- request representation
- decision representation
- policy representation
- policy parsing
- validation
- normalization
- rule matching
- evaluation
- approval validation
- canonicalization

The core must remain independent of:

- CLI
- Git
- MCP
- network
- filesystem execution
- sandbox implementation
- cloud services

---

# 4. Suggested structure

Initial structure:

    agent_firewall/
    ├── __init__.py
    ├── __main__.py
    ├── model.py
    ├── policy.py
    ├── normalize.py
    ├── evaluator.py
    ├── approval.py
    ├── audit.py
    └── cli.py

Optional future structure:

    agent_firewall/
    └── adapters/
        ├── filesystem.py
        ├── process.py
        ├── network.py
        └── git.py

Do not create adapters until required.

---

# 5. model.py

`model.py` should contain small immutable data structures where appropriate.

Potential objects:

    Request
    Decision
    DecisionResult
    Rule
    Approval

Use Python standard-library mechanisms.

Dataclasses are acceptable.

Avoid complicated inheritance.

---

# 6. policy.py

Responsibilities:

- load policy
- parse policy
- validate policy
- validate version
- build immutable policy representation

It should not evaluate requests.

Keep:

    policy parsing

separate from:

    policy evaluation

---

# 7. normalize.py

Responsibilities:

- normalize agents
- normalize actions
- normalize resources
- canonicalize request data

Normalization must be deterministic.

Do not make normalization responsible for authorization.

Its job is representation.

---

# 8. evaluator.py

This is the most security-sensitive component.

Conceptually:

    evaluate(request, policy) -> decision

Recommended flow:

    validate request
        |
        v
    normalize request
        |
        v
    locate agent
        |
        v
    match deny
        |
        v
    match approve
        |
        v
    match allow
        |
        v
    default deny

No external calls should occur.

---

# 9. Rule matching

Keep matching simple.

For each agent:

1. evaluate deny rules
2. evaluate approve rules
3. evaluate allow rules
4. otherwise deny

Do not make matching dependent on iteration order.

The precedence rules must be explicit.

---

# 10. Specificity

If the implementation supports rule specificity, define it explicitly.

Do not accidentally create precedence based on:

    dictionary order
    file order
    parser order
    insertion order

Explicit deny should remain dominant.

---

# 11. Resource matching

Resource matching should be implemented by resource type where necessary.

Potential types:

    filesystem
    network
    process
    generic

Do not create an overly abstract plugin framework for the initial implementation.

A small internal dispatcher is sufficient.

---

# 12. Filesystem normalization

Filesystem paths should use standard-library path facilities.

The implementation should distinguish:

    lexical normalization

from:

    actual filesystem resolution

The core may perform lexical normalization.

The enforcement adapter is responsible for filesystem identity and TOCTOU concerns.

---

# 13. Policy representation

After parsing, policy should preferably become an immutable in-memory representation.

Example conceptual structure:

    Policy(
        version=1,
        agents={
            "developer": AgentPolicy(...)
        }
    )

Do not repeatedly parse policy for every request if a loaded snapshot can be reused.

---

# 14. CLI architecture

CLI should be a thin wrapper.

Flow:

    CLI arguments
        |
        v
    Request
        |
        v
    Firewall
        |
        v
    Decision
        |
        v
    renderer
        |
        v
    stdout + exit code

The CLI must not duplicate authorization logic.

---

# 15. JSON rendering

The CLI should render structured decision data.

The internal decision object is the source of truth.

Do not construct authorization semantics from terminal strings.

---

# 16. Exit codes

Keep exit codes in one clearly defined place.

Suggested constants:

    ALLOW = 0
    DENY = 1
    APPROVE = 2
    INVALID_REQUEST = 3
    INVALID_POLICY = 4
    INTERNAL_ERROR = 5

Do not scatter numeric literals throughout the code.

---

# 17. Error handling

Expected user errors should be represented explicitly.

Examples:

- malformed request
- missing agent
- malformed policy
- unsupported version

Unexpected exceptions should not silently become ALLOW.

Prefer:

    error -> safe failure

rather than:

    error -> fallback decision

---

# 18. Approval implementation

Approval should be represented as structured data.

Potential fields:

    approval_id
    request_hash
    policy_version
    policy_generation
    approved_by
    created_at
    expires_at

Validation must verify all authorization-relevant fields.

---

# 19. Canonical request

Canonical request serialization should:

- include authorization-relevant fields
- use deterministic ordering
- avoid irrelevant metadata
- produce stable bytes

Then:

    SHA-256(canonical_request)

produces the request hash.

---

# 20. Approval validation flow

Recommended:

    request
       |
       v
    normalize
       |
       v
    canonicalize
       |
       v
    hash
       |
       v
    compare approval
       |
       +-- mismatch -> DENY
       |
       +-- expired -> DENY
       |
       +-- invalid -> DENY
       |
       v
    approved

---

# 21. Audit implementation

Audit should be optional.

A minimal implementation can write JSONL.

Example:

    {"timestamp":"...","agent":"developer","action":"git.commit","decision":"ALLOW"}

Do not require a database.

Do not require a remote logging service.

---

# 22. Audit security

Never write:

    secret values

to audit evidence.

If a resource itself is sensitive, the audit representation may need redaction or hashing.

The implementation should prefer metadata that identifies the event without exposing secret material.

---

# 23. Immutable snapshots

When a policy is loaded:

    file
      |
      v
    parsed policy
      |
      v
    immutable snapshot

Evaluation should use that snapshot.

Do not allow concurrent mutation of active policy state.

---

# 24. Thread safety

The core should be safe to use concurrently if practical.

The easiest approach is:

- immutable policy
- immutable request
- side-effect-free evaluation

Do not introduce locks unless necessary.

---

# 25. Caching

Caching is not required for the MVP.

If introduced later:

    cache key =
        policy identity
        +
        canonical request

Policy changes must invalidate authorization results.

Never cache ALLOW independently of policy state.

---

# 26. Dependencies

Only standard-library modules should be used.

Potential modules:

    argparse
    dataclasses
    datetime
    enum
    fnmatch
    hashlib
    json
    os
    pathlib
    re
    subprocess
    sys
    typing

Use only what is actually needed.

---

# 27. No shell strings

Do not build authorization around arbitrary shell command strings.

Prefer structured process requests:

    action = process.spawn
    resource = pytest

The firewall authorizes the operation.

An adapter can separately construct the process invocation.

---

# 28. No subprocess in the core

The core evaluator must not execute external programs.

Git/process adapters may use subprocess where appropriate.

The evaluator itself remains pure.

---

# 29. Testing architecture

Tests should map to layers:

    parser tests
    normalization tests
    evaluator tests
    approval tests
    CLI tests
    security tests

Security tests should exercise public behavior rather than implementation internals where practical.

---

# 30. Minimal implementation principle

Before adding a component, ask:

1. Is it required by SPEC.md?
2. Does it belong in the core?
3. Can standard library functionality solve it?
4. Does it introduce a new trust boundary?
5. Does it increase attack surface?
6. Can the feature remain optional?

If the answer is unclear, do not add it yet.

---

# 31. Adapter principle

Adapters translate external operations into firewall requests.

Example:

    filesystem adapter
        |
        v
    Request(
        agent=...,
        action="filesystem.write",
        resource=...
    )
        |
        v
    firewall.check()
        |
        v
    decision
        |
        v
    actual filesystem operation

The adapter must respect DENY.

---

# 32. Integration principle

External projects should be able to consume the firewall without modifying the core.

Examples:

    orchestrator -> firewall
    MCP -> firewall
    sandbox -> firewall
    CLI -> firewall

The firewall should not know which caller initiated the request beyond explicit identity information.

---

# 33. Logging

Avoid verbose default logging.

The CLI should remain quiet unless the user requests explanation or JSON output.

Debug information should not leak secrets.

---

# 34. Configuration lookup

Configuration discovery should be explicit and documented.

Avoid surprising behavior such as searching arbitrary directories for policies.

If automatic discovery is implemented, define the exact search order.

---

# 35. Environment variables

Environment variables may be supported for convenience.

They must not silently bypass policy.

Do not implement:

    ALLOW_ALL=true

or equivalent insecure emergency switches.

If a development override is ever needed, it must be explicit and documented.

---

# 36. Emergency behavior

There must be no hidden emergency bypass.

If policy is unavailable:

    DENY / fail closed

If approval is unavailable:

    DENY

If normalization fails:

    DENY / invalid request

If evaluator crashes:

    no authorization is granted

---

# 37. Future extensibility

Extensibility should come from stable primitives:

    Request
    Policy
    Rule
    Decision

rather than a large plugin architecture.

Do not build plugin loading until actual integrations require it.

---

# 38. Implementation completion

A phase is complete when:

- implementation follows SPEC.md
- relevant tests pass
- security invariants pass
- no forbidden dependencies were introduced
- no undocumented authority was introduced
- no scope outside the roadmap was added
- public behavior is documented
