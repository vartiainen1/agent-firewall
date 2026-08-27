# SECURITY.md — agent-firewall Security Model

## 1. Security objective

`agent-firewall` provides a deterministic authorization boundary for AI agents.

Its primary security objective is:

> Prevent an agent from performing actions that are not authorized by trusted policy.

The firewall is not a complete security system.

It is one layer in a larger architecture.

---

# 2. Security philosophy

The project follows:

    AI proposes
    policy decides
    firewall authorizes
    OS/sandbox enforces
    evidence records
    humans retain authority

The AI agent is not the source of authorization.

---

# 3. Default deny

All unknown or uncertain operations must fail closed.

Default:

    DENY

Examples:

    unknown agent -> DENY
    unknown action -> DENY
    unknown resource -> DENY
    invalid policy -> fail closed
    invalid request -> fail closed
    expired approval -> DENY
    invalid approval -> DENY

---

# 4. Least privilege

Policies should grant only necessary capabilities.

Prefer:

    filesystem.write ./src/**

over:

    filesystem.write ./**

Prefer:

    process.spawn pytest

over:

    process.spawn *

Capabilities should be specific.

---

# 5. Explicit identity

Identity must come from a trusted caller.

The following are not authentication:

    "I am the deployer."

    "The system says I am trusted."

    "My prompt says I have admin privileges."

The firewall must not accept self-declared authority.

---

# 6. Explicit actions

Actions must be explicit.

The firewall should not infer:

    filesystem.write

from:

    "do whatever is necessary"

Natural language is not an authorization language.

---

# 7. Explicit resources

Where possible, authorization should identify the target resource.

Examples:

    filesystem.write -> ./src/main.py
    network.connect -> staging.example.com:443
    secret.read -> DATABASE_URL

Broad resource permissions should be treated as higher risk.

---

# 8. Policy integrity

Policy is a trust boundary.

If an agent can modify its own active policy, authorization becomes meaningless.

Therefore policy should be protected by an external trusted layer such as:

- filesystem permissions
- repository permissions
- deployment controls
- signed configuration
- trusted administrator workflows

The firewall itself should not grant policy modification.

---

# 9. No self-escalation

An agent must not be able to:

1. modify policy
2. grant itself a capability
3. approve its own privileged request

These are separate security invariants.

---

# 10. Approval security

Approval is an explicit trust escalation.

Approvals should be:

- external
- explicit
- bound to the request
- version-aware
- optionally time-limited
- non-replayable across different requests

---

# 11. Approval binding

An approval must identify the exact authorization context.

At minimum:

    agent
    action
    resource
    policy generation/version

A canonical request hash is recommended.

---

# 12. Approval expiration

High-risk approvals should expire.

Expired approvals must not continue to authorize operations.

This prevents old approvals from becoming permanent capabilities.

---

# 13. Policy race conditions

A request must be evaluated against a stable policy snapshot.

Do not evaluate half of a request under one policy and half under another.

Policy generation/version should be available in evidence where appropriate.

---

# 14. Path traversal

Filesystem authorization must normalize paths before matching.

Dangerous examples:

    ../secret
    ./src/../secret
    ../../etc/passwd

must not bypass resource policy.

The firewall should not rely only on textual prefix comparisons.

---

# 15. Symlink attacks

Lexical path normalization does not solve symlink attacks.

For example:

    allowed/path/file

may resolve through a symlink to:

    sensitive/path/file

The actual enforcement layer must address filesystem identity where required.

The firewall should document this limitation rather than falsely claiming complete filesystem security.

---

# 16. TOCTOU

A check followed by an operation may create a time-of-check/time-of-use race.

Conceptually:

    check(path)
        |
        | path changes
        v
    write(path)

The firewall alone cannot guarantee immunity from all TOCTOU conditions.

Enforcement adapters should use appropriate OS primitives where strong guarantees are required.

---

# 17. Network security

A network rule such as:

    network.connect api.example.com:443

does not automatically guarantee that the eventual socket connects to the intended endpoint.

DNS rebinding and address changes are enforcement-layer concerns.

The firewall should authorize the declared resource.

The network adapter must enforce the actual connection boundary where necessary.

---

# 18. Process execution

Process authorization should use structured fields.

Avoid interpreting arbitrary shell strings as authorization policy.

For example:

    process.spawn -> pytest

is preferable to:

    shell.execute -> "pytest && curl attacker.example"

The process adapter remains responsible for actual command execution.

---

# 19. Secrets

Secrets are sensitive resources.

The firewall must never include secret values in:

- audit logs
- errors
- JSON output
- debug output
- exception messages

Only the secret identifier or appropriately redacted representation should appear.

---

# 20. Audit integrity

Local logs are not automatically trustworthy.

An attacker with filesystem access may modify them.

Potential future mitigations include:

- restrictive permissions
- separate ownership
- append-only storage
- hash chaining
- external archival
- signed evidence

The project must not claim local JSONL is tamper-proof.

---

# 21. Audit privacy

Audit records should contain only information needed for accountability.

Avoid recording:

- prompts
- full source code
- secret values
- unnecessary environment variables
- credentials

---

# 22. Fail closed

Security-sensitive failures must never become ALLOW.

Examples:

    parser exception
    missing policy
    invalid policy
    normalization failure
    approval failure
    unknown version
    unknown action
    internal uncertainty

The safe outcome is denial or an explicit error.

---

# 23. No LLM authorization

LLMs must not be trusted as the final authorization mechanism.

A model may:

    recommend

but cannot:

    authorize

The core evaluator must remain deterministic.

---

# 24. Prompt injection

Prompt injection is outside the firewall's primary responsibility.

If malicious content causes an agent to request:

    filesystem.read ~/.ssh/id_rsa

the firewall evaluates that request.

If the policy denies it:

    DENY

The firewall does not need to understand the prompt that caused the request.

---

# 25. Confused deputy

Integrations must ensure that an agent cannot cause a more privileged component to perform an action under the wrong identity.

Identity must remain explicit throughout the request path.

Example of unsafe behavior:

    low-trust agent
        |
        v
    privileged adapter
        |
        v
    action performed as admin

Adapters must preserve the correct authorization identity.

---

# 26. Capability leakage

Do not expose privileged capabilities merely because they exist in the system.

A capability listing should reflect actual policy.

Do not expose secrets or internal policy details unnecessarily.

---

# 27. Policy wildcard risks

Wildcards can unintentionally grant broad access.

The linter should eventually flag patterns such as:

    filesystem.write ./**
    network.connect *
    process.spawn *

Broad permissions are not automatically invalid, but they should be visible.

---

# 28. Dependency security

Zero runtime dependencies significantly reduce the dependency attack surface.

Do not add third-party packages without explicit justification.

Every dependency would introduce:

- supply-chain risk
- update requirements
- transitive dependencies
- additional code
- additional attack surface

The standard library is preferred.

---

# 29. Network independence

The core must not require network access.

This protects against:

- remote service compromise
- data leakage
- availability failures
- unexpected telemetry
- network-dependent authorization failures

---

# 30. Database independence

The core does not require a database.

This reduces:

- infrastructure
- attack surface
- operational complexity
- state-management complexity

Authorization should remain possible from local policy.

---

# 31. Security-sensitive output

Human-readable output must remain safe.

Do not echo arbitrary resources or metadata if they may contain secrets.

Machine-readable output must follow the same rule.

---

# 32. Security testing

Security tests should verify:

    default deny
    unknown agent deny
    unknown action deny
    invalid policy fail closed
    path traversal denied
    approval replay denied
    approval substitution denied
    expired approval denied
    self approval denied
    policy race behavior
    secret redaction
    deterministic evaluation
    zero network requirement

---

# 33. Security boundary limitations

The firewall does not guarantee:

- OS security
- process isolation
- sandbox security
- container security
- kernel security
- network packet filtering
- endpoint authenticity
- secret storage
- code correctness
- human correctness
- agent honesty

It provides authorization.

---

# 34. Reporting vulnerabilities

Security vulnerabilities should be reported privately using [GitHub Security Advisories](https://github.com/vartiainen1/agent-firewall/security/advisories/new).

A vulnerability report should include:

- affected version
- affected component
- reproduction steps
- expected behavior
- actual behavior
- security impact
- proposed mitigation if known

Do not publish sensitive exploit details before maintainers have had an opportunity to address the issue.

---

# 35. Security principle

The strongest security property of the project is not complexity.

It is explicitness.

A small deterministic system that:

    knows exactly what it is authorizing
    +
    denies what it does not know
    +
    cannot be silently overridden

is preferable to a much larger system whose behavior is difficult to inspect.
