# agent-firewall

A small, deterministic authorization layer for AI agents.

`agent-firewall` answers one simple question:

> Is this agent allowed to perform this action against this resource?

It is designed to sit between AI agents and the tools they can operate.

    AI agent
        |
        v
    agent-firewall
        |
        v
    tool / adapter / OS

The firewall does not try to understand whether an agent's reasoning is good.

It evaluates the requested operation against explicit policy.

---

## Why?

AI agents are increasingly capable of:

- reading and writing files
- executing processes
- modifying repositories
- accessing networks
- calling tools
- interacting with production systems
- accessing sensitive resources

The problem is not only whether the agent can perform these actions.

The problem is:

> Which actions should this particular agent be allowed to perform?

`agent-firewall` provides a small authorization primitive for answering that question.

---

## Core idea

The core is intentionally simple:

    Request + Policy -> Decision

The possible decisions are:

    ALLOW
    DENY
    APPROVE

If the firewall cannot establish authorization, it fails closed.

Default:

    DENY

---

## Installation

Requires Python 3.10 or later.

    pip install agent-firewall

Zero runtime dependencies.

---

## Quick start

    from agent_firewall import Firewall, Request, Policy

    policy = Policy.from_dict({
        "version": 1,
        "agents": {
            "developer": {
                "allow": [{"action": "filesystem.write", "resource": "./src/**"}],
                "deny": [{"action": "filesystem.write", "resource": "./src/secrets/**"}]
            }
        }
    })

    fw = Firewall(policy)
    decision = fw.check(Request(agent="developer", action="filesystem.write", resource="./src/main.py"))
    print(decision.kind)  # DecisionKind.ALLOW

---

## Example

A policy might allow a developer agent to modify source code:

    {
      "version": 1,
      "agents": {
        "developer": {
          "allow": [
            {
              "action": "filesystem.write",
              "resource": "./src/**"
            }
          ],
          "deny": [
            {
              "action": "filesystem.write",
              "resource": "./src/secrets/**"
            }
          ]
        }
      }
    }

A request:

    agent = developer
    action = filesystem.write
    resource = ./src/main.py

produces:

    ALLOW

While:

    agent = developer
    action = filesystem.write
    resource = ./src/secrets/config.py

produces:

    DENY

Explicit deny takes precedence over allow.

---

## Design principles

The project intentionally follows a few strict principles.

### Zero runtime dependencies

The core uses the Python standard library.

No third-party runtime packages are required.

### Local-first

The core works locally.

No cloud service is required.

### Offline-first

Authorization does not require an internet connection.

### Deterministic

The same request evaluated against the same policy produces the same result.

### Default deny

Unknown or uncertain operations are not authorized.

### Explicit authority

The firewall does not infer permissions from natural language.

### Small trusted core

The authorization engine should remain small and understandable.

### Composable

The firewall is intended to sit underneath other systems rather than replace them.

### No mandatory LLM

The authorization engine itself does not need an LLM.

### No hidden behavior

The core should not secretly access networks, execute commands, modify policies, or make authorization decisions through external services.

---

## What it is

`agent-firewall` is:

- an authorization engine
- a policy evaluator
- a capability boundary
- a deterministic decision system
- a local security primitive
- an integration point for AI agents and tools

---

## What it is not

`agent-firewall` is not:

- a sandbox
- a container runtime
- an antivirus
- an EDR
- a secret manager
- a complete IAM system
- a network firewall
- an LLM safety system
- a prompt-injection detector
- a cloud authorization platform

The firewall answers:

    "Is this operation authorized?"

Other systems handle:

    "Can this operation physically be prevented?"
    "Is the code safe?"
    "Is the agent's reasoning correct?"
    "Is the endpoint authentic?"

---

## Architecture

The core architecture is intentionally small:

    +-------------------+
    |    AI Agent       |
    +---------+---------+
              |
              | Request
              v
    +-------------------+
    |  agent-firewall   |
    |                   |
    |  Normalize        |
    |  Match            |
    |  Evaluate         |
    +---------+---------+
              |
              | Decision
              v
       +------+------+
       |             |
     ALLOW         DENY
       |
       v
    Adapter / Tool
       |
       v
    Actual operation

An approval path may add:

    Request
       |
       v
    Firewall
       |
    APPROVE
       |
       v
    Trusted approval
       |
       v
    Revalidation
       |
       v
    ALLOW

---

## Decision precedence

The evaluator follows:

    DENY
    APPROVE
    ALLOW
    default DENY

Therefore:

    explicit deny
        >
    approval requirement
        >
    allow
        >
    no match

---

## CLI

Check a request:

    agent-firewall check \
      --agent developer \
      --action filesystem.write \
      --resource ./src/main.py

Output:

    ALLOW

Machine-readable output:

    agent-firewall check \
      --agent developer \
      --action filesystem.write \
      --resource ./src/main.py \
      --json

Explain a decision:

    agent-firewall explain \
      --agent developer \
      --action filesystem.write \
      --resource ./src/main.py

---

## Exit codes

    0 = ALLOW
    1 = DENY
    2 = APPROVE
    3 = INVALID_REQUEST
    4 = INVALID_POLICY
    5 = INTERNAL_ERROR

These exit codes are part of the CLI contract.

---

## Policy

Policies contain explicit agent permissions.

Conceptually:

    policy
      |
      +-- agent
           |
           +-- allow
           +-- deny
           +-- approve

A rule describes an action and optionally a resource.

Example:

    {
      "action": "git.push"
    }

or:

    {
      "action": "filesystem.write",
      "resource": "./src/**"
    }

---

## Security

The security model is based on:

- least privilege
- default deny
- explicit identity
- explicit capabilities
- deterministic evaluation
- stable policy snapshots
- external approval
- request binding
- secret redaction
- zero runtime dependencies

Read:

    SECURITY.md

for the security model.

Read:

    THREAT_MODEL.md

for the threat model and security boundaries.

---

## Important limitation

Authorization is not enforcement.

For example, the firewall may return:

    ALLOW

for:

    filesystem.write ./src/main.py

The system performing the actual write still needs to obey that decision.

Strong enforcement may require:

- OS permissions
- sandboxing
- containers
- process isolation
- network controls
- trusted adapters

The firewall is one layer.

---

## Repository documentation

Before modifying the project, read:

    AGENTS.md
    DESIGN.md
    SPEC.md
    SECURITY.md
    THREAT_MODEL.md
    IMPLEMENTATION.md
    TEST_PLAN.md
    ROADMAP.md

### Documentation overview

    AGENTS.md
        Instructions for AI coding agents.

    DESIGN.md
        Architecture and philosophy.

    SPEC.md
        Exact behavioral contract.

    IMPLEMENTATION.md
        Implementation structure and guidance.

    SECURITY.md
        Security principles.

    THREAT_MODEL.md
        Threats and trust boundaries.

    TEST_PLAN.md
        Required tests and security invariants.

    ROADMAP.md
        Current and future scope.

    CONTRIBUTING.md
        Contribution rules.

    CHANGELOG.md
        User-visible changes.

---

## Project status

The project is intentionally developed in small phases.

The initial goal is not to build a huge AI security platform.

The initial goal is:

> Build a small authorization primitive that can be trusted.

Future functionality should be added around the core through adapters rather than by making the core increasingly complicated.

---

## Philosophy

The project follows a simple architectural principle:

    AI proposes
        |
        v
    Policy decides
        |
        v
    Firewall authorizes
        |
        v
    OS / sandbox enforces
        |
        v
    Evidence records

The AI should become more capable without becoming the authority over its own capabilities.

---

## License

See:

    LICENSE
