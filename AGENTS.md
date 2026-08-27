# AGENTS.md — Instructions for AI Coding Agents

## Purpose

You are working on `agent-firewall`.

This repository implements a small, deterministic, zero-dependency authorization layer for AI agents.

The project is security-sensitive.

Your primary responsibility is to implement the existing design and specification faithfully.

Do not redesign the project unless explicitly instructed to do so.

---

# 1. Required reading order

Before modifying code, read:

1. DESIGN.md
2. SPEC.md
3. SECURITY.md
4. THREAT_MODEL.md
5. IMPLEMENTATION.md
6. TEST_PLAN.md
7. ROADMAP.md

If any document is missing, do not invent its contents.

If documents contradict each other, stop and report the contradiction.

Do not silently choose an interpretation.

---

# 2. Core philosophy

The project follows these principles:

- zero third-party runtime dependencies
- local-first
- offline-first
- deterministic behavior
- explicit authorization
- default deny
- fail closed
- small trusted computing base
- no mandatory cloud
- no mandatory database
- no mandatory daemon
- no mandatory LLM
- no telemetry
- no hidden network calls
- explicit state
- inspectable behavior
- composability
- machine-readable output
- human-readable output

Preserve these principles.

---

# 3. The central rule

The firewall answers one question:

> Is this agent allowed to perform this action against this resource under the current policy?

It does NOT answer:

- Is the action intelligent?
- Is the action morally correct?
- Is the agent trustworthy in general?
- Is the code correct?
- Is the operation isolated?
- Is the prompt malicious?
- Is the agent's reasoning valid?

Do not expand the authorization engine into these areas.

---

# 4. AI must not become the authority

Never introduce an LLM into the authorization path.

The core must remain:

    Request + Policy -> Decision

not:

    Request + LLM -> Decision

AI may eventually suggest policies or changes.

AI suggestions must never directly become active authorization.

The intended trust model is:

    AI proposes
    trusted authority decides
    firewall enforces
    OS/sandbox executes

---

# 5. Zero dependency rule

The runtime MUST have zero third-party dependencies.

Prefer Python standard library modules.

Do not add:

- requests
- pydantic
- PyYAML
- click
- rich
- typer
- cryptography
- SQLAlchemy
- GitPython
- MCP SDK
- cloud SDKs

unless explicitly approved.

Development-only tooling may be considered separately, but the runtime must remain dependency-free.

---

# 6. No hidden infrastructure

Do not introduce:

- cloud services
- telemetry
- analytics
- remote policy servers
- mandatory databases
- mandatory Redis
- mandatory queues
- mandatory daemons
- mandatory internet access

The core must remain locally executable.

---

# 7. Security rules

Never weaken:

- default deny
- fail closed
- explicit identity
- explicit capabilities
- deterministic evaluation
- approval separation
- approval binding
- policy versioning
- immutable evaluation snapshots
- secret redaction
- policy integrity assumptions

If an implementation makes something more convenient but weakens one of these properties, reject the implementation.

---

# 8. Do not over-engineer

Prefer:

    100 lines of understandable code

over:

    500 lines of abstractions

Do not create abstractions without a demonstrated need.

Do not create classes merely because a framework convention suggests them.

Do not introduce interfaces for hypothetical future implementations.

Implement what the current specification requires.

---

# 9. Do not implement the entire roadmap

ROADMAP.md contains future ideas.

Do not implement future phases unless explicitly instructed.

If Phase 1 is being implemented, do not silently implement:

- MCP integration
- network enforcement
- policy servers
- distributed approvals
- policy signing
- dashboards
- remote logging

unless they are part of the requested phase.

---

# 10. Preserve public behavior

Once defined, treat these as public API:

- decision values
- CLI commands
- exit codes
- JSON fields
- policy schema
- request schema
- error semantics

Do not change them casually.

If a breaking change appears necessary, report it before implementing it.

---

# 11. Security-sensitive changes

Any change involving:

- authorization
- rule precedence
- normalization
- path matching
- approval
- request hashing
- policy parsing
- identity
- resource matching
- audit evidence
- secrets

must include corresponding tests.

Never change security-sensitive code without testing the relevant invariant.

---

# 12. Tests

Before declaring work complete:

1. run the existing tests
2. add tests for new behavior
3. run security tests
4. test invalid input
5. test default-deny behavior
6. test failure behavior
7. verify no third-party runtime dependency was introduced

Do not delete failing security tests simply to make the suite pass.

---

# 13. Errors

Security errors must fail closed.

Never convert:

    parser failure

into:

    ALLOW

Never convert:

    normalization failure

into:

    ALLOW

Never convert:

    approval failure

into:

    ALLOW

If the system cannot establish authorization, it must not authorize the action.

---

# 14. Policy changes

Do not automatically modify active policy while implementing features.

Do not create self-modifying authorization.

An agent must not be able to grant itself additional capabilities.

---

# 15. External integrations

Integrations must depend on the firewall core, not the reverse.

Preferred:

    integration
        |
        v
    firewall core

Not:

    firewall core
        |
        v
    integration SDK

MCP, Git, sandbox, network, filesystem, CI, etc. should remain adapters.

---

# 16. No hidden side effects

Authorization functions must not unexpectedly:

- execute commands
- write files
- modify Git
- access the network
- modify policy
- grant permissions
- approve requests

Keep authorization as close as possible to a pure evaluation.

---

# 17. When uncertain

Do not guess about security-sensitive behavior.

If the specification does not define behavior:

1. identify the ambiguity
2. explain why it matters
3. propose the smallest reasonable resolution
4. ask for clarification if necessary

Do not silently invent security semantics.

---

# 18. Definition of success

The implementation is successful when:

- it follows SPEC.md
- it preserves DESIGN.md
- it follows SECURITY.md
- it respects THREAT_MODEL.md
- it follows IMPLEMENTATION.md
- it satisfies TEST_PLAN.md
- it stays within ROADMAP.md scope
- it remains dependency-free at runtime
- it remains understandable
- it fails closed
- it does not expand the project's responsibility unnecessarily

The goal is not maximum functionality.

The goal is a small, trustworthy authorization primitive.
