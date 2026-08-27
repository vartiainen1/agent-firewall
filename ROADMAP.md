# ROADMAP.md — agent-firewall Roadmap

## Philosophy

Build the smallest useful authorization primitive first.

Do not implement future functionality simply because it appears in DESIGN.md.

Each phase should produce a usable, testable system.

---

# Phase 1 — Deterministic Core

Goal:

    A small library that can answer:

    "Is this request allowed?"

Implement:

- Request
- Decision
- Rule
- Policy
- policy loading
- policy validation
- agent matching
- action matching
- resource matching
- default deny
- explicit deny
- explicit allow
- explicit approve
- deterministic precedence
- normalization
- immutable policy snapshots

Requirements:

- zero runtime dependencies
- offline operation
- deterministic tests

---

# Phase 2 — CLI

Implement:

    agent-firewall check

Support:

- agent
- action
- resource
- policy path
- JSON output
- exit codes

Implement:

    agent-firewall explain

The CLI remains a thin wrapper around the core.

---

# Phase 3 — Policy Tooling

Implement:

    agent-firewall lint

and:

    agent-firewall test

Potentially:

    agent-firewall capabilities

Goals:

- catch policy mistakes
- make policies reviewable
- make policies testable
- expose effective permissions

No LLM required.

---

# Phase 4 — Audit

Implement optional local audit evidence.

Initial format:

    JSONL

Support:

- timestamp
- agent
- action
- resource
- decision
- rule
- policy version
- policy generation
- request hash where applicable

Ensure:

- no secrets
- no mandatory database
- no remote service

---

# Phase 5 — Approval

Implement:

- approval records
- request hashes
- approval binding
- approval expiration
- approval validation
- self-approval protection

Keep approval local and explicit initially.

---

# Phase 6 — Policy Simulation

Implement:

    agent-firewall simulate

Allow operators to compare:

    current policy
    proposed policy

without activating the new policy.

---

# Phase 7 — Policy Diff

Implement:

    agent-firewall diff

Show:

- added permissions
- removed permissions
- changed resources
- changed approval requirements

Policies should be reviewable like code.

---

# Phase 8 — Filesystem Adapter

Provide an optional adapter for:

    filesystem.read
    filesystem.write
    filesystem.delete

The adapter:

1. creates request
2. calls firewall
3. executes only when authorized

The core remains independent.

---

# Phase 9 — Process Adapter

Provide optional process authorization.

Example:

    process.spawn -> pytest

Keep process invocation structured.

Avoid arbitrary shell parsing.

---

# Phase 10 — Git Adapter

Support:

    git.read
    git.write
    git.commit
    git.push

The firewall does not become a Git library.

Use the Git CLI where appropriate.

---

# Phase 11 — Network Adapter

Support:

    network.connect

Keep network enforcement outside the core.

The adapter is responsible for actual enforcement.

---

# Phase 12 — MCP Adapter

Provide an optional MCP integration.

MCP should translate tool requests into firewall requests.

The MCP SDK must not become a core dependency.

---

# Phase 13 — Orchestrator Integration

Allow an orchestrator to ask:

    Can this agent perform this action?

The orchestrator remains responsible for:

- task decomposition
- agent selection
- scheduling
- coordination

The firewall remains responsible for authorization.

---

# Phase 14 — Sandbox Integration

Integrate with an existing sandbox rather than implementing a complete sandbox inside the firewall.

Relationship:

    firewall -> authorization
    sandbox -> isolation

---

# Phase 15 — Advanced Integrity

Optional features:

- hash-chained audit evidence
- signed policies
- policy integrity verification
- stronger approval identities
- capability expiration
- capability revocation

These are not MVP requirements.

---

# Phase 16 — Advanced Policy Analysis

Potential features:

- permission graph
- policy visualization
- privilege escalation analysis
- unused capability detection
- broad permission detection
- conflict analysis
- policy reachability analysis

Keep analysis separate from authorization.

---

# Phase 17 — AI-Assisted Policy Suggestions

Potential future system:

    observed behavior
        |
        v
    AI recommendation
        |
        v
    proposed policy
        |
        v
    human review
        |
        v
    active policy

AI must never directly modify active authorization.

---

# Explicitly deferred

Do not implement unless specifically requested:

- hosted policy service
- SaaS dashboard
- mandatory cloud
- mandatory database
- mandatory daemon
- mandatory LLM
- telemetry
- automatic permission learning
- automatic privilege escalation
- automatic policy modification
- full IAM
- full sandbox
- antivirus
- EDR
- secret manager

---

# Roadmap principle

The project should grow horizontally through adapters, not vertically through an enormous core.

The core should remain:

    Request
      +
    Policy
      +
    Evaluation
      =
    Decision

Everything else should build around that primitive.
