# DESIGN.md — agent-firewall

## Purpose

`agent-firewall` is a zero-dependency, local-first capability and policy enforcement layer for AI agents.

It answers one question:

> Is this agent allowed to perform this action, against this resource, under the current policy?

The answer is deterministic:

- ALLOW
- DENY
- APPROVE

The firewall does not attempt to determine whether an AI agent is intelligent, trustworthy, or correct.

It does not inspect model reasoning.
It does not require an LLM.
It does not require the internet.
It does not replace the orchestrator.
It does not replace the sandbox.
It does not replace Git.
It does not replace human review.

It provides a small enforcement primitive that other tools can use to make agent capabilities explicit, inspectable, and enforceable.

The fundamental principle is:

> AI proposes. Deterministic systems decide. The operating system enforces where possible. Humans retain authority over trust and irreversible actions.

---

# 1. Design philosophy

This project must preserve the philosophy of the existing agent tooling:

- zero runtime dependencies
- local-first
- offline-first
- deterministic behavior
- small primitives
- composability
- explicit state
- inspectability
- machine-readable output
- human-readable output
- no telemetry
- no cloud requirement
- no mandatory database
- no mandatory daemon
- no mandatory LLM
- no hidden behavior
- no unnecessary abstractions

The firewall should be boring infrastructure.

That is intentional.

It should be possible to understand the complete authorization path by reading a small amount of code.

The project should favor:

- Python standard library
- plain files
- JSON/JSONL
- Git
- OS primitives
- stdin/stdout
- deterministic exit codes

over:

- cloud services
- SaaS
- external policy engines
- databases
- SDK ecosystems
- framework-heavy abstractions
- hosted control planes

---

# 2. Core idea

An AI agent is not the authority.

The agent may be:

- wrong
- compromised
- manipulated
- prompt-injected
- running malicious code
- operating on malicious input
- hallucinating
- incorrectly configured
- acting outside its intended role

Therefore the firewall must never authorize an action because an agent claims that it is allowed to perform it.

This is invalid:

    Agent:
    "I am allowed to access production."

    Firewall:
    ALLOW

Instead:

    Agent
      |
      | structured request
      v
    Firewall
      |
      +-- identity
      +-- action
      +-- resource
      +-- capability
      +-- policy
      +-- approval
      |
      v
    ALLOW / DENY / APPROVE

Authorization comes from trusted policy and trusted authority, not from the agent's own claims.

---

# 3. Goals

The project should provide:

- deterministic authorization
- explicit agent identities
- explicit capabilities
- action-level permissions
- resource-level permissions
- least privilege
- default deny
- fail-closed behavior
- optional human approval
- explainable decisions
- machine-readable decisions
- append-only audit evidence
- policy testing
- policy linting
- policy versioning
- policy snapshots
- request canonicalization
- approval binding
- optional approval expiration
- local operation
- offline operation
- zero third-party runtime dependencies
- easy embedding as a Python library
- easy use as a CLI
- thin adapters for external systems

---

# 4. Non-goals

`agent-firewall` is NOT:

- an AI agent framework
- an agent orchestrator
- an AI model
- an LLM judge
- a prompt-injection detector
- a sandbox implementation
- a container runtime
- an antivirus product
- a traditional network firewall
- a cloud security platform
- an IAM replacement
- a secret manager
- a database
- a telemetry platform
- a hosted policy service

Do not turn the project into a general-purpose security platform.

The core responsibility is narrow:

> Decide whether a structured agent action is authorized.

---

# 5. Fundamental security model

The firewall sits between an agent and the operation it wants to perform.

Conceptually:

    UNTRUSTED AGENT
           |
           | request
           v
    +------------------+
    |  AGENT FIREWALL  |
    +------------------+
    | identity         |
    | action           |
    | resource         |
    | capability       |
    | policy           |
    | approval         |
    +--------+---------+
             |
       ALLOW / DENY /
          APPROVE
             |
             v
      ENFORCEMENT LAYER
             |
       +-----+-----+
       |     |     |
       v     v     v
    sandbox  OS  adapter

The firewall decides.

Another component must enforce the decision.

This distinction is important.

A firewall returning:

    ALLOW

does not itself guarantee that the operation can or will happen.

A firewall returning:

    DENY

must be respected by the caller.

---

# 6. Default deny

The default decision is:

    DENY

This applies to:

- unknown agents
- unknown actions
- unknown capabilities
- unknown resources
- missing policy
- invalid policy
- malformed requests
- ambiguous matches
- unavailable approval
- expired approval
- failed authorization checks

Never silently convert uncertainty into permission.

Never fail open.

---

# 7. Decisions

The firewall has three normal decisions:

    ALLOW
    DENY
    APPROVE

## ALLOW

The action is authorized and may proceed.

## DENY

The action is not authorized and must not proceed.

## APPROVE

The action may be permitted by policy, but explicit trusted human authorization is required before execution.

`APPROVE` is not the same thing as `ALLOW`.

---

# 8. Agent identity

Every request must have an explicit agent identity.

Examples:

    developer
    reviewer
    tester
    researcher
    documenter
    deployer
    security

The firewall must not infer identity from prompts.

This is invalid:

    "I am the security agent."

Identity must come from a trusted caller or integration.

An agent cannot promote itself to a higher-trust identity.

---

# 9. Capabilities

A capability describes something an agent is allowed to do.

Examples:

    filesystem.read
    filesystem.write
    filesystem.delete

    network.connect
    network.listen

    process.spawn
    process.signal

    git.read
    git.write
    git.commit
    git.push

    secret.read

    memory.read
    memory.propose
    memory.promote

    artifact.read
    artifact.write

    production.deploy
    production.rollback

Capabilities should be granular.

Avoid giant permissions such as:

    everything
    admin
    full-access

unless a policy explicitly requires them.

The goal is least privilege.

---

# 10. Actions

An action represents a concrete operation.

Examples:

    filesystem.read
    filesystem.write
    filesystem.delete

    network.connect

    process.spawn

    git.read
    git.write
    git.commit
    git.push

    secret.read

    memory.read
    memory.propose

    artifact.read
    artifact.write

    production.deploy
    production.rollback

Unknown actions must fail closed.

The firewall must not automatically allow future actions merely because they share a prefix with an existing capability.

---

# 11. Resources

Actions should identify the resource they operate on whenever applicable.

Examples:

    filesystem.read
    resource: ./src/auth.py

    filesystem.write
    resource: ./src/auth.py

    network.connect
    resource: api.example.com:443

    process.spawn
    resource: pytest

    secret.read
    resource: DATABASE_URL

Resources must be normalized before policy matching.

---

# 12. Request model

The conceptual request is:

    {
      "agent": "developer",
      "action": "filesystem.write",
      "resource": "./src/auth.py"
    }

Additional metadata may exist, but the core authorization model should remain small.

Potential metadata:

    request_id
    timestamp
    policy_version
    caller
    working_directory
    protocol
    metadata

Do not make metadata mandatory unless required for authorization.

---

# 13. Deterministic evaluation

The core evaluation should behave approximately like:

    Policy + Request -> Decision

No LLM is required.

No network connection is required.

No database query is required.

No external service is required.

The evaluation path should be:

    request
      |
      v
    validate
      |
      v
    normalize
      |
      v
    identify agent
      |
      v
    identify action
      |
      v
    identify resource
      |
      v
    evaluate policy
      |
      v
    ALLOW / DENY / APPROVE
      |
      v
    evidence

The same policy and same normalized request must produce the same decision.

---

# 14. No LLM authorization

The firewall must never require an LLM to answer questions such as:

    "Is this action safe?"

    "Should the agent be allowed to do this?"

    "Does this seem malicious?"

    "Does the agent have a good reason?"

The firewall is not an AI judge.

An external AI system may recommend policy changes, but recommendations must become explicit policy before affecting authorization.

The correct pattern is:

    observation
        |
        v
    AI recommendation
        |
        v
    human/system review
        |
        v
    explicit policy
        |
        v
    firewall enforcement

Never:

    agent
      |
      v
    LLM judge
      |
      v
    ALLOW

---

# 15. Policy model

Policies should be simple and explicit.

Conceptually:

    agents:
      developer:
        allow:
          - filesystem.read: "./**"
          - filesystem.write: "./src/**"
          - filesystem.write: "./tests/**"
          - git.read
          - git.write
          - git.commit
          - process.spawn: "python"
          - process.spawn: "pytest"

        deny:
          - filesystem.read: "./.env"
          - filesystem.read: "~/.ssh/**"
          - network.connect: "production-db.internal:*"

      tester:
        allow:
          - filesystem.read: "./**"
          - process.spawn: "pytest"
          - network.connect: "staging.example.com:443"

      deployer:
        allow:
          - git.read

        approve:
          - production.deploy
          - production.rollback

The actual configuration syntax should be chosen according to the zero-dependency principle.

Do not introduce a third-party YAML dependency simply for convenience.

Prefer standard-library formats where appropriate.

JSON is acceptable.

A minimal line-based format is also acceptable if it produces a simpler implementation.

TOML may be used if the supported Python version provides it.

The exact configuration syntax should prioritize:

1. correctness
2. simplicity
3. zero dependencies
4. readability
5. deterministic parsing

---

# 16. Policy precedence

Policy precedence must be explicit.

Recommended semantics:

1. explicit DENY
2. explicit APPROVE
3. explicit ALLOW
4. default DENY

Specific rules must take precedence over broad rules where appropriate.

Example:

    allow filesystem.write ./src/**
    deny  filesystem.write ./src/secrets/**

Then:

    ./src/main.py

is:

    ALLOW

while:

    ./src/secrets/config.py

is:

    DENY

The policy engine must document and test precedence.

Do not rely on accidental implementation ordering.

---

# 17. Explicit deny

Explicit deny rules are important because they allow broad permissions while protecting sensitive areas.

Example:

    allow:
      filesystem.write ./**

    deny:
      filesystem.write ./.git/**
      filesystem.write ./.env
      filesystem.write ~/.ssh/**

The evaluator must ensure that sensitive exclusions cannot accidentally be overridden by a broader allow rule.

---

# 18. Resource matching

Resource matching must be deterministic.

Possible resource classes:

    filesystem paths
    network endpoints
    processes
    Git repositories
    secrets
    artifacts
    logical resources

Each class may eventually have specialized normalization.

Do not create one giant universal matcher if separate semantics make the implementation clearer.

---

# 19. Filesystem authorization

Filesystem actions:

    filesystem.read
    filesystem.write
    filesystem.delete

Paths must be normalized.

The implementation should account for:

- relative paths
- absolute paths
- `.` components
- `..` components
- path separators
- platform differences
- symlink considerations

At minimum, obvious traversal such as:

    ../../secret

must not bypass resource policy.

The firewall should not assume that textual path equality equals filesystem identity.

Where stronger guarantees are needed, the enforcement layer must also validate the final path.

---

# 20. Filesystem enforcement

The firewall should provide authorization decisions.

An optional filesystem adapter may combine authorization with execution.

Conceptually:

    requested write
          |
          v
    firewall.check()
          |
      +---+---+
      |       |
    ALLOW    DENY
      |       |
      v       v
    write    stop

The adapter must not treat firewall errors as ALLOW.

---

# 21. Network authorization

Network access should be represented explicitly.

Example:

    network.connect
    resource: api.github.com:443

or:

    network.connect
    resource: production-db.internal:5432

Policies may allow:

    developer -> api.github.com:443

while denying:

    developer -> production-db.internal:5432

The firewall should not assume that a hostname is safe merely because it looks safe.

The enforcement layer is responsible for resolving and enforcing the actual connection boundary.

---

# 22. Process authorization

Process execution should be explicit.

Example:

    process.spawn
    resource: python

    process.spawn
    resource: pytest

Policies may allow:

    developer -> python
    developer -> pytest
    developer -> git

while denying:

    developer -> sudo
    developer -> ssh

The core should prefer structured process authorization over arbitrary shell-string interpretation.

Do not attempt to build a complete shell parser unless there is a compelling reason.

---

# 23. Git authorization

Git should be treated as a first-class capability because agents commonly modify repositories.

Possible actions:

    git.read
    git.write
    git.commit
    git.push

Example:

    developer -> git.commit -> ALLOW

    developer -> git.push -> APPROVE

    developer -> git.push production -> DENY

The project must not require a Python Git package.

Where necessary, use the Git CLI through `subprocess`.

The core remains independent of Git.

---

# 24. Secrets

Secrets are high-risk resources.

Possible capability:

    secret.read

Example:

    secret.read
    resource: DATABASE_URL

The firewall must never print secret values.

Evidence should contain:

    secret.read DATABASE_URL -> DENY

not the actual value.

The firewall is not a secret store.

It only controls authorization around secret access.

---

# 25. Approval model

`APPROVE` means:

    policy permits this category of action,
    but explicit trusted authorization is required.

Example:

    deployer
      |
      v
    production.deploy
      |
      v
    APPROVE
      |
      v
    human
      |
      v
    approval
      |
      v
    execution

Approval should be explicit.

The requesting agent cannot approve itself.

---

# 26. Approval binding

An approval must be tied to the specific request.

At minimum it should bind:

    agent
    action
    resource
    policy generation

A stronger implementation should generate a canonical request representation and hash it.

Example:

    request_hash =
        SHA256(
            canonical(
                agent,
                action,
                resource,
                policy_generation
            )
        )

Then an approval can contain:

    approval_id
    request_hash
    expires
    approved_by

This prevents approval substitution.

---

# 27. Approval expiration

Approvals should be short-lived where appropriate.

Example:

    approval_id: apr-000001
    expires: 2026-08-27T12:00:00Z

After expiration:

    DENY

or require a new approval.

Do not allow stale approvals to become permanent permissions.

---

# 28. No self-approval

This must be a hard invariant.

Invalid:

    agent
      |
      v
    APPROVE
      |
      v
    same agent approves
      |
      v
    execution

Approval must originate from an external trusted authority.

Initially this may simply be a human using the CLI.

---

# 29. Policy snapshots

Every authorization decision should evaluate against one stable policy snapshot.

If policy changes:

    request A -> policy generation 12
    request B -> policy generation 13

each decision must remain attributable to its corresponding policy.

This makes auditing and debugging possible.

---

# 30. Policy versioning

Policies must have explicit versions.

Example:

    {
      "version": 1
    }

If policy semantics change incompatibly, use a new version.

The evaluator must reject unknown versions.

It must not guess what an unsupported policy version means.

---

# 31. Policy modification

An agent must not be able to modify the policy that controls its own authorization unless an external trusted mechanism explicitly permits that.

Otherwise:

    agent
      |
      v
    modify policy
      |
      v
    request privileged action
      |
      v
    ALLOW

becomes meaningless.

The intended deployment is:

    trusted human/admin
          |
          v
       policy
          |
          v
       firewall
          |
          v
        agent

Policy files should ideally be protected by OS permissions and repository controls.

---

# 32. Audit evidence

Every authorization decision should optionally produce structured evidence.

Example JSONL:

    {"timestamp":"...","agent":"developer","action":"filesystem.write","resource":"src/auth.py","decision":"ALLOW","rule":"developer-source-write"}

    {"timestamp":"...","agent":"developer","action":"network.connect","resource":"production-db:5432","decision":"DENY","rule":"deny-production-network"}

Evidence should be:

- append-oriented
- machine-readable
- easy to grep
- easy to diff
- easy to archive
- usable without a database

The core must not require a centralized logging service.

---

# 33. Evidence fields

Useful fields include:

    timestamp
    agent
    action
    resource
    decision
    rule
    policy_version
    policy_generation
    request_hash
    approval_id
    reason

Do not include:

    secret values
    prompt contents
    unnecessary source code
    sensitive environment values

unless explicitly requested by a higher-level integration.

---

# 34. Optional hash-chained evidence

An optional integrity mechanism may chain evidence records.

Conceptually:

    record 1
       |
       v
    hash(record 1)
       |
       v
    record 2
       |
       v
    hash(record 2 + previous_hash)
       |
       v
    record 3

This allows later detection of tampering.

This feature must remain optional.

Use standard-library cryptographic hashing.

Do not introduce a dependency.

Do not claim that local JSONL is tamper-proof.

---

# 35. Privacy

The project must have:

- no telemetry
- no analytics
- no phone-home
- no cloud requirement
- no remote logging
- no automatic data collection

The firewall must not transmit:

- prompts
- source code
- secrets
- policy files
- authorization history

to external services.

---

# 36. CLI

The CLI should use Python's standard library.

Example:

    agent-firewall check \
      --agent developer \
      --action filesystem.write \
      --resource ./src/auth.py

Output:

    ALLOW

Machine-readable:

    agent-firewall check \
      --agent developer \
      --action filesystem.write \
      --resource ./src/auth.py \
      --json

Output:

    {
      "decision": "ALLOW",
      "agent": "developer",
      "action": "filesystem.write",
      "resource": "./src/auth.py",
      "rule": "developer-source-write"
    }

---

# 37. Exit codes

Exit codes are part of the public API.

Suggested:

    0 = ALLOW
    1 = DENY
    2 = APPROVE
    3 = INVALID_REQUEST
    4 = INVALID_POLICY
    5 = INTERNAL_ERROR

These should be documented and kept stable.

Do not change them casually.

---

# 38. Explain mode

The firewall should provide:

    agent-firewall explain ...

Example:

    agent-firewall explain \
      --agent developer \
      --action network.connect \
      --resource production-db.internal:5432

Output:

    Decision: DENY

    Agent:
      developer

    Action:
      network.connect

    Resource:
      production-db.internal:5432

    Matched rule:
      deny-production-network

    Reason:
      development agents cannot connect to production resources.

Explain mode must never execute the action.

---

# 39. Policy linting

Provide a deterministic linter.

Example:

    agent-firewall lint policy.json

The linter should detect:

- malformed rules
- duplicate rules
- unreachable rules
- invalid capabilities
- conflicting rules
- suspicious wildcard permissions
- missing version
- ambiguous configuration
- unsafe broad permissions

Example:

    WARNING:
    developer has filesystem.write access to the entire workspace.

The linter should never require an LLM.

---

# 40. Policy testing

Policies should be testable like code.

Example:

    agent-firewall test policy.json

Tests may contain:

    PASS developer filesystem.read ./src/auth.py
    PASS developer filesystem.write ./src/auth.py
    PASS developer network.connect production-db:5432
    PASS tester network.connect staging.example.com:443
    PASS deployer production.deploy

The tests should verify expected decisions, not execute real actions.

---

# 41. CLI design principle

The CLI should be:

- composable
- scriptable
- predictable
- quiet by default
- machine-readable when requested

Do not build a giant interactive CLI.

The common use case should remain:

    check -> decision -> exit code

---

# 42. Python library

The firewall should also be usable directly as a Python library.

Conceptual API:

    from agent_firewall import Firewall, Request

    firewall = Firewall.from_file("policy.json")

    decision = firewall.check(
        Request(
            agent="developer",
            action="filesystem.write",
            resource="./src/auth.py",
        )
    )

    if decision.allowed:
        perform_action()

The API should remain small.

Potential core objects:

    Request
    Decision
    Policy
    Rule
    Firewall
    Evidence
    ApprovalRequest

Avoid framework-style architecture.

---

# 43. No hidden side effects

This:

    firewall.check(request)

must not:

- execute the operation
- modify files
- modify Git
- invoke an LLM
- contact the internet
- modify policy
- modify agent identity
- grant permissions
- mutate external state

Authorization should be as close to a pure function as possible.

Conceptually:

    Policy + Request -> Decision

---

# 44. Dependency architecture

Hard rule:

> The runtime has zero third-party dependencies.

The core should rely on the Python standard library.

Likely modules include:

    pathlib
    json
    re
    fnmatch
    hashlib
    hmac
    subprocess
    os
    sys
    argparse
    dataclasses
    enum
    typing
    datetime
    logging

Do not add a package merely because it makes development more convenient.

If functionality can reasonably be implemented with the standard library, use the standard library.

---

# 45. No mandatory database

The firewall must not require:

- PostgreSQL
- Redis
- MongoDB
- SQLite
- vector databases
- hosted databases

The core authorization path should be stateless.

Audit evidence can be JSONL.

Approval state can use local files if required.

The absence of a database is intentional.

---

# 46. No mandatory daemon

The simplest usage must work as:

    agent-firewall check ...

No server should be required.

No daemon should be required.

No background process should be required.

A daemon may exist later as an optional optimization, but the library and CLI must remain fully functional without it.

---

# 47. Architecture

Suggested structure:

    agent_firewall/
    ├── __init__.py
    ├── __main__.py
    ├── model.py
    ├── policy.py
    ├── evaluator.py
    ├── normalize.py
    ├── audit.py
    ├── approval.py
    ├── cli.py
    └── adapters/
        ├── __init__.py
        ├── filesystem.py
        ├── network.py
        ├── process.py
        └── git.py

This is a starting point, not a requirement.

Do not create files merely to satisfy an architectural diagram.

Keep the implementation small.

---

# 48. Core dependency direction

The dependency direction should be:

    adapters
       |
       v
     core

not:

    core
       |
       v
    adapters

The evaluator must not depend on specific integrations.

For example:

    core
       |
       X
    MCP SDK

must not happen.

Instead:

    MCP adapter
       |
       v
    firewall core

---

# 49. MCP integration

An optional MCP adapter may translate MCP tool calls into firewall requests.

Conceptually:

    MCP tool call
         |
         v
    agent/action/resource
         |
         v
    firewall
         |
         v
    ALLOW / DENY / APPROVE

The MCP SDK must not become a core dependency.

The adapter should remain thin.

---

# 50. Orchestrator integration

The orchestrator owns coordination.

The firewall owns authorization.

Relationship:

    orchestrator
         |
         | agent wants to perform X
         v
    firewall
         |
         +-- ALLOW
         +-- DENY
         +-- APPROVE
         |
         v
    execution adapter / sandbox

The firewall must not become another orchestrator.

It provides a reusable authorization primitive.

---

# 51. Sandbox integration

The sandbox owns isolation.

The firewall owns authorization.

Relationship:

    agent
      |
      v
    firewall
      |
    ALLOW
      |
      v
    sandbox
      |
      v
    OS

Neither layer replaces the other.

A sandboxed operation may still be unauthorized.

An authorized operation may still need sandboxing.

---

# 52. Diff-gate integration

The diff gate asks:

> Is this resulting change acceptable?

The firewall asks:

> Was this action authorized?

These are different questions.

Example:

    filesystem.write src/auth.py
             |
             v
        firewall
             |
           ALLOW
             |
             v
        code changes
             |
             v
         diff-gate
             |
           DENY
             |
             v
         commit blocked

This is correct behavior.

Authorization does not imply correctness.

---

# 53. Memory integration

Memory capabilities may include:

    memory.read
    memory.propose
    memory.promote

An agent might have:

    memory.read
    memory.propose

but not:

    memory.promote

This preserves the principle:

> AI proposes knowledge; trusted systems decide what becomes trusted knowledge.

The memory subsystem remains responsible for storage and trust semantics.

---

# 54. Decision-log integration

The firewall may emit structured evidence for an existing decision log.

However:

    agent-firewall

must not require:

    agent-decision-log

The dependency direction should be:

    firewall
       |
       v
    evidence
       |
       v
    decision-log

not:

    firewall
       |
       v
    decision-log

The firewall must remain independently installable.

---

# 55. Error-log integration

Authorization failures can be consumed by an error-log system.

Example:

    DENY:
    developer attempted production network access.

The firewall should expose structured information.

But it must not require the error-log project.

---

# 56. Blame integration

Historical code evidence belongs to the blame/history system.

The firewall does not need to understand repository history to authorize actions.

A higher-level orchestrator may combine:

    historical risk
    +
    current action
    +
    current capability

to decide that approval is required.

Then the firewall enforces the resulting policy.

---

# 57. Capability over intention

The firewall should not ask:

> Why does the agent want this?

It asks:

> Is the requested action authorized?

Example:

    Agent:
    "I need production credentials because I am debugging."

Firewall:

    DENY

if policy says the agent cannot access production credentials.

Intent can be considered by another system.

Authorization remains objective.

---

# 58. Prompt injection

Prompt injection is not an authorization mechanism.

The firewall must not attempt to understand arbitrary prompts.

If an injected instruction causes an agent to request:

    filesystem.read ~/.ssh/id_rsa

the firewall simply evaluates the request.

If policy denies it:

    DENY

The firewall does not need to understand why the request was made.

---

# 59. Threat model

Assume the agent may be malicious or compromised.

The attacker may attempt:

- unauthorized filesystem access
- unauthorized network access
- secret access
- policy modification
- identity spoofing
- action spoofing
- path traversal
- approval replay
- approval substitution
- malformed requests
- wildcard abuse
- shell escape
- environment manipulation
- policy race conditions
- audit tampering

The firewall protects the authorization boundary.

It does not claim to solve every security problem.

---

# 60. Policy tampering threat

If an agent can modify the active policy, authorization becomes meaningless.

Therefore:

    policy file

must be protected by a trusted layer.

Prefer:

    trusted authority
          |
          v
       policy
          |
          v
      firewall
          |
          v
        agent

The agent should not be able to rewrite its own security boundary.

---

# 61. Audit tampering threat

Local audit files are not automatically trustworthy.

If the agent can modify the evidence, evidence integrity is compromised.

Possible mitigations:

- append-only storage
- OS permissions
- separate audit location
- restricted ownership
- hash chaining
- external archival

The firewall should not falsely claim that local logs are tamper-proof.

---

# 62. Security invariants

These are load-bearing architectural rules.

## Invariant 1

Unknown capabilities are denied.

## Invariant 2

Default policy is deny.

## Invariant 3

Policy evaluation never requires an LLM.

## Invariant 4

The requesting agent cannot grant itself capabilities.

## Invariant 5

The requesting agent cannot approve its own request.

## Invariant 6

Invalid policy cannot produce ALLOW.

## Invariant 7

Policy changes cannot mutate an in-flight evaluation.

## Invariant 8

Authorization evaluation has no hidden execution side effects.

## Invariant 9

Secrets never appear in evidence output.

## Invariant 10

The runtime has zero third-party dependencies.

## Invariant 11

The firewall does not require network access.

## Invariant 12

The firewall never silently fails open.

---

# 63. Example: normal development

Policy:

    developer:
      filesystem.read ./**
      filesystem.write ./src/**
      filesystem.write ./tests/**
      git.read
      git.write
      git.commit
      process.spawn python
      process.spawn pytest

Request:

    filesystem.read ./src/auth.py

Result:

    ALLOW

Request:

    filesystem.write ./src/auth.py

Result:

    ALLOW

Request:

    network.connect production-db:5432

Result:

    DENY

Request:

    git.commit

Result:

    ALLOW

Then the diff gate independently evaluates the resulting change.

---

# 64. Example: production deployment

Agent:

    deployer

Request:

    production.deploy

Policy:

    production.deploy -> APPROVE

Firewall:

    APPROVE

The orchestrator pauses.

A human reviews the operation.

Human approves.

The firewall validates:

- approval exists
- approval is unexpired
- approval is bound to the request
- approval came from the trusted authority

Then execution proceeds.

---

# 65. Example: compromised coding agent

Suppose repository content attempts to manipulate an agent into exfiltrating an SSH key.

Agent requests:

    filesystem.read ~/.ssh/id_rsa

Firewall:

    DENY

Agent then attempts:

    network.connect attacker.example.com:443

Firewall:

    DENY

The firewall does not need to know about the malicious prompt.

It only enforces the capability boundary.

---

# 66. Example: broad policy mistake

Policy:

    developer:
      allow:
        filesystem.write "./**"

This grants broad write access.

The firewall should not secretly reinterpret the policy.

Instead the linter should report:

    WARNING:
    developer has filesystem.write access to the entire workspace.

The policy author remains responsible for the policy.

---

# 67. Deterministic normalization

Requests should be normalized before evaluation.

Potential normalization includes:

- action name normalization
- agent identifier normalization
- path normalization
- path separator normalization
- hostname normalization
- port normalization
- canonical request serialization

The normalized request should be inspectable in debug mode.

---

# 68. Canonical requests

Where request hashing or approval binding is used, requests must have a deterministic canonical form.

For example:

    {
      "agent": "developer",
      "action": "filesystem.write",
      "resource": "./src/auth.py"
    }

must serialize deterministically before hashing.

Do not rely on arbitrary dictionary ordering or human-readable formatting.

---

# 69. Hashing

If request hashes are used, standard-library cryptographic hashing is sufficient.

For example:

    SHA-256

Do not add a dependency merely for hashing.

The hash should identify the canonical request, not the human-readable output.

---

# 70. Caching

Caching is optional.

If introduced, it must not weaken authorization.

Cache keys must include enough information to identify the policy state.

For example:

    policy_generation
    policy_hash
    canonical_request

Never cache:

    ALLOW

without knowing which policy produced it.

A policy change must invalidate relevant cached decisions.

---

# 71. Concurrency

The preferred model is:

    load policy
         |
         v
    immutable snapshot
         |
         +--> request A
         +--> request B
         +--> request C

Policy mutation must remain separate from evaluation.

This reduces race conditions and makes authorization decisions reproducible.

---

# 72. Performance

Authorization should be cheap enough to sit in front of frequent tool calls.

A normal decision should involve approximately:

    parse
    normalize
    match
    return

It should not:

- call an LLM
- contact a cloud service
- start a daemon
- query a database
- scan the entire filesystem

Performance is useful, but correctness and determinism are more important.

---

# 73. Platform support

The core should target:

- Linux
- macOS
- Windows

The policy evaluator should remain platform-independent where possible.

Platform-specific enforcement belongs in adapters.

Do not contaminate the policy engine with platform-specific enforcement details.

---

# 74. Configuration

Configuration should be explicit.

Potential environment variables:

    AGENT_FIREWALL_POLICY
    AGENT_FIREWALL_AUDIT
    AGENT_FIREWALL_MODE

Environment variables should not silently override security-critical configuration without clear documentation.

The policy file should remain the most auditable configuration mechanism.

---

# 75. Modes

Modes may be provided if they simply select explicit policies.

Possible examples:

    development
    security
    enterprise

A mode should not secretly change authorization semantics.

For example:

    --mode development

should resolve to:

    known policy

rather than invoking hidden logic.

---

# 76. Development mode

A development policy might allow:

    workspace.read
    workspace.write
    git.read
    git.write
    process.spawn

while denying:

    production access
    host secrets
    policy modification

Exact permissions remain policy-defined.

---

# 77. Security mode

A security-focused policy may use:

    read-only workspace
    restricted network
    no secrets
    no production
    restricted process execution

Again, these are policy choices rather than hidden behavior.

---

# 78. Enterprise mode

An enterprise policy may require:

    explicit identity
    explicit policy
    audit evidence
    approval
    restricted capabilities

But enterprise infrastructure must not become a core dependency.

The firewall should still function locally.

---

# 79. Testing philosophy

Tests should focus heavily on security invariants.

Important tests include:

    unknown agent -> DENY

    unknown action -> DENY

    empty policy -> DENY

    invalid policy -> no ALLOW

    path traversal -> DENY

    expired approval -> DENY

    wrong request hash -> DENY

    self approval -> DENY

    specific deny overrides broad allow

    broad deny overrides broad allow

    policy generation remains stable

    secret values never appear in evidence

    policy changes do not alter an existing snapshot

    evaluator does not perform external side effects

---

# 80. Offline tests

The entire core test suite should be runnable without:

- internet
- LLM access
- cloud credentials
- external services
- databases

Tests should be deterministic.

---

# 81. No hidden network access

The firewall itself should never need the network.

This is an important security and philosophy requirement.

If a future feature requires network access, it should be an explicit adapter rather than part of the core.

---

# 82. AI-assisted policy generation

A future helper may inspect observed agent behavior and suggest a policy.

Example:

    observed actions
          |
          v
         AI
          |
          v
    proposed policy
          |
          v
    human review
          |
          v
    active policy

The AI must never directly modify active authorization policy.

This preserves:

    AI proposes
    trusted authority decides
    firewall enforces

---

# 83. Learning

The firewall must not automatically learn permissions from repeated behavior.

This is invalid:

    agent repeatedly requests production access
        |
        v
    firewall decides it must be legitimate
        |
        v
    ALLOW

Repeated behavior is evidence.

It is not authorization.

---

# 84. Capability discovery

A future CLI may expose:

    agent-firewall capabilities --agent developer

Output:

    filesystem.read
    filesystem.write ./src/**
    git.read
    git.write
    git.commit
    process.spawn python
    process.spawn pytest

This should expose explicit policy state.

It must not expose hidden permissions that do not actually exist.

---

# 85. Policy simulation

A future command may allow:

    agent-firewall simulate policy-new.json request.json

This should answer:

    current policy -> DENY
    proposed policy -> ALLOW

without changing the active policy or executing anything.

This is useful for policy review.

---

# 86. Policy diffing

A future command may compare:

    policy-v1
    policy-v2

and show:

    + developer: filesystem.write ./docs/**
    - developer: network.connect staging.example.com:443
    + deployer: production.rollback -> APPROVE

Policy changes should be reviewable like code changes.

---

# 87. Policy as code

Policies should be:

- version-controlled
- reviewable
- diffable
- testable
- lintable
- reproducible

The repository should encourage treating policy changes with the same seriousness as code changes.

---

# 88. Human-readable first

Security decisions should be understandable by humans.

Bad:

    ERR_AUTH_9F71C

Better:

    DENY

    developer cannot connect to production-db.internal:5432

Machine-readable details can still be emitted with:

    --json

---

# 89. Machine-readable first internally

Internally, decisions should have structured representations.

For example:

    Decision(
        result=DENY,
        agent="developer",
        action="network.connect",
        resource="production-db.internal:5432",
        rule="deny-production-network",
        reason="production network access is not permitted"
    )

Human-readable output is a rendering of structured state.

Do not make terminal strings the internal source of truth.

---

# 90. No hidden authority

The firewall should never silently grant permissions based on:

- environment
- hostname
- user-agent
- model identity
- prompt text
- previous success
- previous approval
- frequency of use

unless those properties are explicitly part of policy.

---

# 91. Trust model

The intended trust hierarchy is:

    HUMAN / TRUSTED AUTHORITY
              |
              v
           POLICY
              |
              v
          FIREWALL
              |
              v
           AGENT
              |
              v
          ACTION

The agent is intentionally below the authorization boundary.

---

# 92. Layered security

The complete architecture may look like:

    human authority
          +
       policy
          +
       firewall
          +
       sandbox
          +
          OS
          +
      diff gate
          +
         tests
          +
        review
          +
       evidence

Each layer solves a different problem.

Do not try to collapse all of them into the firewall.

---

# 93. Relationship to the broader agent architecture

The firewall should complement the surrounding tools.

Conceptually:

    agent-error-log
        |
        v
    What went wrong?

    agent-decision-log
        |
        v
    What was decided?

    agent-log-ai
        |
        v
    What can we learn?

    agent-memory
        |
        v
    What do we know?

    agent-blame
        |
        v
    Why does this code exist?

    agent-diff-gate
        |
        v
    Is this change acceptable?

    agent-sandbox
        |
        v
    Where can untrusted work execute?

    agent-orchestrator
        |
        v
    How do we coordinate work?

    agent-firewall
        |
        v
    What is this agent actually allowed to do?

The firewall should add a new dimension without absorbing the responsibilities of the other tools.

---

# 94. Architectural separation

Every feature should answer:

> Which component owns this responsibility?

Examples:

    "Can this agent execute this action?"
        -> firewall

    "Where can this process execute?"
        -> sandbox

    "Which agent should do the next task?"
        -> orchestrator

    "Is this code change acceptable?"
        -> diff gate

    "What did we decide?"
        -> decision log

    "What went wrong?"
        -> error log

    "What should be remembered?"
        -> memory

    "Why does this code exist?"
        -> blame/history

If the answer is unclear, the feature probably does not belong in the firewall.

---

# 95. Project success criteria

The project is successful if an engineer can answer:

    What can this agent do?

    Why can it do it?

    Why was this action denied?

    Which policy allowed it?

    Can I reproduce the decision?

    Can I run it offline?

    Can I audit the implementation?

    Can I embed it in another tool?

These should all have straightforward answers.

---

# 96. What the firewall should feel like

The firewall should not feel intelligent.

It should feel predictable.

Given the same:

    policy
    +
    request

it should return the same:

    decision

every time.

No personality.

No hidden reasoning.

No model roulette.

No cloud dependency.

No magic.

Just policy.

---

# 97. Core principle: AI proposes, deterministic systems decide

The project should preserve this distinction:

    AI:
        proposes actions

    Firewall:
        authorizes actions

    Sandbox / OS:
        enforces execution boundaries

    Human:
        retains authority over trust and irreversible operations

This division is the foundation of the architecture.

---

# 98. Core principle: authorization is not correctness

If:

    filesystem.write src/payment.py

returns:

    ALLOW

that does not mean:

    the code is correct

Correctness belongs to:

- tests
- review
- diff gates
- CI
- agents
- humans

The firewall only answers the authorization question.

---

# 99. Core principle: authorization is not isolation

If:

    process.spawn python

returns:

    ALLOW

that does not mean:

    python is isolated

Isolation belongs to:

- sandbox
- container
- VM
- OS
- filesystem permissions
- network controls

The firewall only authorizes the operation.

---

# 100. Core principle: authorization is not trust

An agent can be trusted to perform one operation without being trusted generally.

For example:

    developer
        |
        +-- filesystem.write ./src/** -> ALLOW
        |
        +-- production.deploy -> DENY
        |
        +-- secret.read PROD_DB_URL -> DENY

Trust should be expressed as specific capabilities rather than vague labels.

---

# 101. Core principle: least privilege

Agents should receive only the capabilities necessary for their role.

Prefer:

    developer:
        filesystem.read ./src/**
        filesystem.write ./src/**
        git.commit

over:

    developer:
        everything

The policy should make the difference explicit.

---

# 102. Core principle: no automatic escalation

If an agent encounters:

    DENY

the firewall must not automatically suggest:

    "Would you like to grant yourself this capability?"

A higher-level human or trusted authority may modify policy.

The agent cannot escalate itself.

---

# 103. Core principle: evidence remains

Important actions should leave evidence.

The system should be able to reconstruct:

    who
    did what
    to which resource
    under which policy
    with what result
    and, when applicable, under which approval

This makes autonomous systems inspectable.

---

# 104. Core principle: small trusted computing base

The most security-sensitive code should be the smallest code.

Ideally:

    request model
    +
    normalization
    +
    policy parser
    +
    evaluator
    +
    approval validation

Everything else should sit outside that core.

Avoid unnecessary dependencies.

Avoid unnecessary abstractions.

Avoid unnecessary magic.

---

# 105. Future integrations

Potential future integrations:

- MCP
- Git
- filesystem
- process execution
- network
- sandbox
- orchestrator
- CI
- approval workflows
- policy visualization
- policy simulation
- policy diffing
- signed policies
- capability delegation
- short-lived capabilities
- revocation

All integrations must preserve the core philosophy.

---

# 106. Explicitly out of scope for the core

Do not add these to the core:

    LLM inference
    cloud authentication
    remote policy servers
    telemetry
    centralized databases
    vector databases
    agent memory
    agent orchestration
    OS sandbox implementation
    container runtime
    secret storage
    full IAM
    hosted dashboards

Integrations may exist around the core.

They must not become mandatory.

---

# 107. Implementation order

The project should be implemented in small steps.

Recommended order:

1. Request model
2. Decision model
3. Capability/action model
4. Policy parser
5. Deterministic evaluator
6. Default-deny behavior
7. Resource normalization
8. CLI
9. JSON output
10. Stable exit codes
11. Explain mode
12. Policy linting
13. Policy tests
14. Audit evidence
15. Approval model
16. Approval binding
17. Approval expiration
18. Optional adapters
19. Optional integrations

Do not start by building adapters.

Build the deterministic core first.

---

# 108. Initial MVP

The first useful version should be small.

MVP requirements:

- zero runtime dependencies
- policy loading
- agent identities
- actions
- resources
- allow
- deny
- approve
- default deny
- deterministic evaluation
- CLI
- JSON output
- stable exit codes
- explain mode
- tests

Everything else can follow.

---

# 109. MVP example

Policy:

    {
      "version": 1,
      "agents": {
        "developer": {
          "allow": [
            {
              "action": "filesystem.read",
              "resource": "./**"
            },
            {
              "action": "filesystem.write",
              "resource": "./src/**"
            },
            {
              "action": "git.commit"
            }
          ],
          "deny": [
            {
              "action": "filesystem.read",
              "resource": "./.env"
            }
          ]
        }
      }
    }

Request:

    {
      "agent": "developer",
      "action": "filesystem.write",
      "resource": "./src/main.py"
    }

Result:

    {
      "decision": "ALLOW",
      "agent": "developer",
      "action": "filesystem.write",
      "resource": "./src/main.py"
    }

Request:

    {
      "agent": "developer",
      "action": "filesystem.read",
      "resource": "./.env"
    }

Result:

    {
      "decision": "DENY",
      "agent": "developer",
      "action": "filesystem.read",
      "resource": "./.env"
    }

---

# 110. Definition of done

The core should not be considered complete until:

- all authorization decisions are deterministic
- default deny is enforced
- invalid policy cannot produce ALLOW
- unknown actions cannot produce ALLOW
- unknown agents cannot produce ALLOW
- path traversal tests pass
- approval binding works
- expired approvals fail
- self-approval fails
- secrets are excluded from evidence
- policy snapshots are stable
- CLI exit codes are documented
- JSON output is stable
- no third-party runtime dependencies exist
- tests run offline
- no hidden network calls exist
- the implementation is understandable without external infrastructure

---

# 111. Final architecture

The intended architecture is:

                        HUMAN
                          |
                          | goals / trust
                          v
                 +-------------------+
                 |   ORCHESTRATOR    |
                 |    coordination   |
                 +---------+---------+
                           |
                           | action request
                           v
                 +-------------------+
                 |  AGENT FIREWALL   |
                 |   authorization   |
                 +---------+---------+
                           |
                  ALLOW / DENY /
                     APPROVE
                           |
                           v
                 +-------------------+
                 |      AGENT        |
                 |   proposes work   |
                 +---------+---------+
                           |
                           v
                 +-------------------+
                 |      SANDBOX      |
                 |     isolation     |
                 +---------+---------+
                           |
                           v
                        OS / TOOLS
                           |
                           v
                        evidence
                           |
              +------------+------------+
              |            |            |
              v            v            v
          diff-gate    error-log   decision-log
              |            |            |
              +------------+------------+
                           |
                           v
                         memory

The firewall occupies one precise point in this architecture:

> What is this agent actually allowed to do?

---

# 112. Final principle

The project should preserve this rule above everything else:

> AI proposes. Policy decides. The OS enforces. Evidence remains. Humans retain authority.

If a future feature makes the AI itself more authoritative, question it.

If a future feature moves authority into deterministic, explicit, inspectable boundaries, it is probably aligned with the architecture.

If a feature requires a cloud service, ask whether it can remain optional.

If a feature requires a third-party dependency, ask whether the standard library is sufficient.

If a feature makes the core larger without strengthening the authorization boundary, question whether it belongs.

The firewall should remain a small piece of infrastructure.

Its responsibility is deliberately narrow:

    REQUEST
       |
       v
    WHO / WHAT
       |
       v
    POLICY CHECK
       |
       +----------+----------+
       |          |          |
       v          v          v
     ALLOW      DENY      APPROVE
       |          |          |
       v          v          v
    EXECUTE      STOP      HUMAN
                             |
                             v
                         AUTHORIZE
                             |
                             v
                           EXECUTE

No intelligence is required at the authorization boundary.

No cloud is required.

No third-party runtime dependencies are required.

No hidden authority exists.

No silent fallback exists.

The firewall simply provides a small, deterministic capability boundary that autonomous agents cannot be allowed to bypass.
