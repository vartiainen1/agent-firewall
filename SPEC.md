# SPEC.md — agent-firewall Specification

## 1. Status

This document defines the externally observable behavior of `agent-firewall`.

DESIGN.md describes the broader architecture and philosophy.

This document defines the implementation contract.

If an implementation cannot satisfy this specification without changing the architecture, the implementation must stop and report the conflict.

---

# 2. Core operation

The core operation is:

    evaluate(request, policy) -> decision

The evaluator must be deterministic.

Given identical normalized request and identical policy snapshot, the result MUST be identical.

---

# 3. Decisions

Exactly three authorization decisions are supported:

    ALLOW
    DENY
    APPROVE

## ALLOW

The request is authorized under the active policy.

## DENY

The request is not authorized.

## APPROVE

The request matches a policy requiring explicit external approval.

APPROVE does not mean execution is authorized yet.

After approval, the request must be revalidated.

---

# 4. Default behavior

The default decision is:

    DENY

The following MUST NOT produce ALLOW unless explicitly authorized by policy:

- unknown agent
- unknown action
- unknown capability
- unknown resource
- empty policy
- missing policy
- malformed request
- malformed policy
- unsupported policy version
- failed normalization
- invalid approval
- expired approval
- mismatched approval
- evaluator uncertainty

---

# 5. Request

A request represents one attempted action.

Minimum fields:

    agent
    action

Resource is optional for actions that do not require a resource.

Conceptual representation:

    {
      "agent": "developer",
      "action": "filesystem.write",
      "resource": "./src/main.py"
    }

---

# 6. Agent identifier

Agent identifiers are explicit strings.

Examples:

    developer
    tester
    reviewer
    deployer

The firewall MUST NOT derive identity from:

- prompt text
- model name
- natural-language claims
- arbitrary metadata
- requested capability

Identity must be supplied by the caller.

---

# 7. Action identifier

Actions are explicit strings.

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
    production.deploy
    production.rollback

Unknown actions are denied unless explicitly defined by policy.

---

# 8. Resource

Resources identify the object of an action.

Examples:

    ./src/main.py
    ./tests/**
    production-db.internal:5432
    pytest
    DATABASE_URL

Resources are strings at the core model level.

Resource-specific normalization and matching may be implemented separately.

---

# 9. Policy

A policy contains:

    version
    agents

Example:

    {
      "version": 1,
      "agents": {
        "developer": {
          "allow": [],
          "deny": [],
          "approve": []
        }
      }
    }

Unknown top-level required fields must result in policy validation failure if they are required by the selected policy version.

---

# 10. Rules

A rule contains:

    action

and optionally:

    resource

Example:

    {
      "action": "filesystem.read",
      "resource": "./src/**"
    }

A rule without a resource applies to the action generally.

---

# 11. Rule collections

Each agent may contain:

    allow
    deny
    approve

All are lists.

Example:

    {
      "allow": [
        {
          "action": "filesystem.read",
          "resource": "./src/**"
        }
      ],
      "deny": [
        {
          "action": "filesystem.read",
          "resource": "./src/secrets/**"
        }
      ],
      "approve": [
        {
          "action": "git.push"
        }
      ]
    }

---

# 12. Rule precedence

Explicit deny has highest priority.

Recommended evaluation precedence:

    DENY
    APPROVE
    ALLOW
    default DENY

Therefore:

    matching deny
        -> DENY

otherwise:

    matching approve
        -> APPROVE

otherwise:

    matching allow
        -> ALLOW

otherwise:

    DENY

A specific deny must be able to override a broader allow.

---

# 13. Example precedence

Policy:

    allow filesystem.write ./**
    deny filesystem.write ./.env

Request:

    filesystem.write ./.env

Result:

    DENY

Request:

    filesystem.write ./src/main.py

Result:

    ALLOW

---

# 14. Matching

Matching must be deterministic.

Action matching should be exact unless the policy language explicitly defines another form.

Resource matching may support controlled patterns such as:

    ./src/**
    ./tests/**
    *.py

The implementation must document exact wildcard semantics.

Do not invent regex semantics unless regex is explicitly part of the policy specification.

---

# 15. Resource normalization

Before resource matching:

1. parse resource
2. normalize according to resource type
3. evaluate normalized representation

For filesystem paths, normalization must account for:

- relative paths
- absolute paths
- `.`
- `..`
- separators
- platform differences

Normalization failures must fail closed.

---

# 16. Path traversal

A request must not bypass policy through textual path tricks.

For example:

    ./src/../.env

must normalize consistently before matching.

The evaluator must not authorize based solely on the unnormalized string.

---

# 17. Symlinks

The core evaluator should not claim that lexical path normalization alone prevents symlink attacks.

Where actual filesystem enforcement occurs, the adapter must account for filesystem identity and symlink behavior.

The core may authorize a normalized logical path.

The enforcement layer is responsible for ensuring the actual operation matches that authorization.

---

# 18. Policy snapshots

Each evaluation operates against one immutable policy snapshot.

The policy must not change during evaluation.

If policy changes between requests:

    request A -> policy generation 1
    request B -> policy generation 2

the decisions remain attributable to their respective snapshots.

---

# 19. Policy version

Policies contain an explicit version.

Example:

    "version": 1

Unsupported versions MUST fail closed.

The implementation must not guess semantics for an unknown version.

---

# 20. Decision object

The internal decision should contain structured information.

Minimum conceptual fields:

    decision
    agent
    action

Optional:

    resource
    rule
    reason
    policy_version
    policy_generation
    request_hash
    approval_id

---

# 21. CLI

The CLI must support a basic check operation.

Conceptual usage:

    agent-firewall check \
      --agent developer \
      --action filesystem.write \
      --resource ./src/main.py

Human output:

    ALLOW

Machine output:

    agent-firewall check \
      --agent developer \
      --action filesystem.write \
      --resource ./src/main.py \
      --json

---

# 22. Exit codes

Exit codes:

    0 = ALLOW
    1 = DENY
    2 = APPROVE
    3 = INVALID_REQUEST
    4 = INVALID_POLICY
    5 = INTERNAL_ERROR

These codes are part of the CLI API.

---

# 23. Explain

The CLI should support:

    agent-firewall explain ...

The explanation must identify:

- decision
- agent
- action
- resource when present
- matching rule when available
- reason when available

Explain mode MUST NOT execute the requested action.

---

# 24. JSON output

JSON output must be valid JSON.

The decision field must be one of:

    ALLOW
    DENY
    APPROVE

JSON output must not contain secret values.

---

# 25. Approval

APPROVE requires an external trusted approval.

An approval must not be generated by the requesting agent.

An approval must bind to the request.

Minimum binding:

    agent
    action
    resource
    policy generation/version

---

# 26. Request hash

Where approval binding uses a request hash:

1. normalize request
2. canonicalize request
3. serialize deterministically
4. hash using SHA-256

The hash must represent the authorization-relevant request.

---

# 27. Approval expiration

An approval may contain an expiration timestamp.

Expired approvals MUST NOT authorize an action.

Invalid timestamps MUST fail closed.

---

# 28. Approval replay

An approval for:

    request A

must not authorize:

    request B

even if both requests share the same action.

The binding must prevent substitution.

---

# 29. Self-approval

The requesting agent cannot approve its own request.

The approval authority must be external to the requesting agent.

---

# 30. Audit evidence

Audit records may include:

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

Secret values MUST NOT appear.

---

# 31. Side effects

Core evaluation MUST NOT:

- execute the requested operation
- modify files
- modify Git
- access the network
- invoke an LLM
- change policy
- grant capabilities

Evaluation should be side-effect free.

---

# 32. Runtime dependencies

The runtime MUST have zero third-party dependencies.

The standard library is permitted.

---

# 33. Offline behavior

Core authorization MUST work without:

- internet
- cloud
- database
- daemon
- external API
- LLM

---

# 34. Unknown fields

Unknown fields should not silently change authorization behavior.

If fields are ignored, this must be deterministic and documented.

Security-sensitive unknown fields must not be interpreted as authorization.

---

# 35. Invalid policy

Invalid policy must not partially load into an active authorization state.

A malformed policy must fail before authorization begins.

---

# 36. Invalid request

Malformed requests must not be evaluated as ordinary requests.

They must return:

    INVALID_REQUEST

and must not result in ALLOW.

---

# 37. Policy loading

Policy loading should:

1. locate policy
2. parse it
3. validate schema
4. validate version
5. construct immutable representation
6. expose it to evaluator

A partially parsed policy must never become active.

---

# 38. Determinism

The following must be deterministic:

- normalization
- matching
- precedence
- decision
- request hashing
- JSON serialization where canonical serialization is required

---

# 39. Security boundary

The firewall is an authorization component.

It does not guarantee:

- process isolation
- network isolation
- filesystem isolation
- code correctness
- agent honesty
- prompt safety
- OS integrity

Adapters and external systems provide those guarantees where necessary.

---

# 40. Compatibility

The implementation should avoid unnecessary platform-specific behavior.

The core model should be portable.

Platform-specific enforcement belongs in adapters.

---

# 41. Specification rule

If behavior is not explicitly specified:

- prefer deny
- prefer deterministic behavior
- prefer the smallest implementation
- do not infer authority from untrusted input
- do not add hidden behavior
