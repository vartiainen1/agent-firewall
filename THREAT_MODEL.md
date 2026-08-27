# THREAT_MODEL.md — agent-firewall Threat Model

## 1. Purpose

This document defines the threats `agent-firewall` is designed to address and the threats it intentionally leaves to other layers.

---

# 2. Protected asset

The primary protected asset is:

    authorization authority

More concretely:

> The ability to perform actions against resources.

Examples:

- read files
- write files
- delete files
- execute processes
- access networks
- access secrets
- modify Git
- deploy systems

---

# 3. Attacker model

Assume the AI agent may be:

- malicious
- compromised
- manipulated
- prompt-injected
- hallucinating
- misconfigured
- running malicious code
- influenced by untrusted repository content

Do not assume the agent is trustworthy merely because it was created by a trusted system.

---

# 4. Threat: unauthorized filesystem access

Attacker attempts:

    filesystem.read ~/.ssh/id_rsa

or:

    filesystem.write ./protected/config

Mitigation:

    explicit filesystem capabilities
    resource matching
    default deny
    explicit deny rules

---

# 5. Threat: path traversal

Attacker requests:

    ./allowed/../../secret

Mitigation:

    deterministic normalization
    resource matching after normalization
    fail closed on normalization failure

Limit:

    symlink and TOCTOU attacks require enforcement-layer controls.

---

# 6. Threat: unauthorized network access

Attacker attempts:

    network.connect attacker.example.com:443

Mitigation:

    explicit network capability
    resource-specific policy
    default deny

Limit:

    actual network enforcement belongs to the network adapter/OS.

---

# 7. Threat: unauthorized process execution

Attacker attempts:

    process.spawn sudo

or:

    process.spawn ssh

Mitigation:

    explicit process capabilities
    resource matching
    default deny

---

# 8. Threat: secret exfiltration

Attacker attempts:

1. read a secret
2. connect to an external host
3. transmit the secret

Mitigation:

    secret.read policy
    network.connect policy

Both actions must be independently authorized.

Denying either action can block the attack path.

Limit:

    the firewall does not inspect arbitrary process internals or network payloads.

---

# 9. Threat: identity spoofing

Attacker claims:

    agent = deployer

when actually running as:

    developer

Mitigation:

    identity must come from trusted caller context
    self-declared identity is insufficient

Limit:

    if the caller itself is compromised and can forge trusted identity, authentication must be handled outside the core.

---

# 10. Threat: privilege escalation through policy modification

Attacker attempts:

    modify policy
        |
        v
    grant capability
        |
        v
    perform privileged action

Mitigation:

    policy is external trusted state
    agent must not modify its own authorization policy
    policy permissions must be protected by the host environment

---

# 11. Threat: self-approval

Attacker requests:

    production.deploy

receives:

    APPROVE

and attempts to approve itself.

Mitigation:

    approval authority is external
    approval identity must be distinct from requesting agent

---

# 12. Threat: approval replay

Valid approval:

    request A

is reused for:

    request B

Mitigation:

    approval binding
    request hash
    policy generation/version
    expiration

---

# 13. Threat: approval substitution

Attacker replaces:

    approved request

with:

    different privileged request

Mitigation:

    canonical request hashing
    exact request binding

---

# 14. Threat: stale approval

An approval granted hours or days ago is reused.

Mitigation:

    expiration timestamps
    policy generation
    request binding

---

# 15. Threat: malicious policy

A policy accidentally grants:

    filesystem.write ./**

Mitigation:

    policy linting
    policy review
    policy testing
    explicit broad-permission warnings

The firewall should enforce the policy as written rather than secretly rewriting it.

---

# 16. Threat: malformed policy

Attacker or operator introduces malformed policy.

Mitigation:

    schema validation
    version validation
    fail closed
    atomic policy loading

---

# 17. Threat: ambiguous policy

Two rules appear to conflict.

Mitigation:

    explicit precedence
    deterministic matching
    policy linting
    tests

The implementation must not depend on accidental rule ordering.

---

# 18. Threat: prompt injection

Repository content or external input causes an agent to request unauthorized actions.

Mitigation:

    firewall ignores prompt intent
    evaluates requested action against policy

Example:

    injected instruction
        |
        v
    agent requests secret
        |
        v
    firewall -> DENY

The firewall does not need to detect the injection itself.

---

# 19. Threat: confused deputy

A low-trust agent causes a high-trust integration to perform an action.

Mitigation:

    explicit agent identity
    authorization at operation boundary
    adapters preserve identity

---

# 20. Threat: fail-open behavior

Internal error causes authorization to default to ALLOW.

Mitigation:

    fail closed
    explicit error states
    security tests

This is a critical invariant.

---

# 21. Threat: policy race

Policy changes during evaluation.

Mitigation:

    immutable policy snapshots
    policy generation/version

---

# 22. Threat: cache poisoning

A cached ALLOW is reused after policy changes.

Mitigation:

    cache keys include policy identity
    cache invalidation on policy changes
    caching not required for MVP

---

# 23. Threat: audit leakage

Sensitive information appears in logs.

Mitigation:

    structured evidence
    secret redaction
    minimal metadata

---

# 24. Threat: audit tampering

Attacker modifies local evidence.

Mitigation options:

    OS permissions
    separate storage
    append-only mechanisms
    hash chaining
    external archival

Limit:

    the core cannot guarantee tamper-proof local logs against a fully privileged host attacker.

---

# 25. Threat: dependency compromise

Third-party dependency is compromised.

Mitigation:

    zero runtime dependencies

---

# 26. Threat: remote service compromise

Cloud authorization service is unavailable or compromised.

Mitigation:

    local-first
    offline authorization
    no mandatory remote service

---

# 27. Threat: malicious resource names

Attacker uses unusual strings to bypass matching.

Mitigation:

    normalization
    deterministic canonicalization
    resource-specific matching

---

# 28. Threat: wildcard abuse

Broad wildcard unexpectedly grants privileges.

Mitigation:

    explicit semantics
    linting
    policy review
    deny precedence

---

# 29. Threat: shell injection

Agent supplies a malicious shell string.

Mitigation:

    firewall authorizes structured actions
    process adapter avoids arbitrary shell interpretation where possible

Limit:

    the firewall is not a shell security engine.

---

# 30. Threat: time-of-check/time-of-use

Resource changes between authorization and execution.

Mitigation:

    enforcement adapters should use appropriate OS primitives

Limit:

    core authorization alone cannot solve all TOCTOU conditions.

---

# 31. Threat: malicious adapter

A compromised adapter ignores:

    DENY

and performs the action anyway.

The firewall cannot force a malicious caller to obey its output.

Mitigation must come from:

- OS permissions
- sandboxing
- privileged execution boundaries
- trusted integration design

---

# 32. Out-of-scope threats

The firewall does not directly solve:

- kernel compromise
- hardware compromise
- malicious OS administrators
- physical attacks
- full sandbox escape
- arbitrary malware detection
- antivirus
- endpoint detection
- full IAM
- secret management
- network intrusion detection
- model alignment
- hallucination detection
- semantic correctness

---

# 33. Trust boundaries

Primary boundaries:

    agent -> firewall
    policy -> firewall
    firewall -> adapter
    approval authority -> firewall
    firewall -> evidence

Each boundary should be explicit.

---

# 34. Threat-model principle

The firewall should not attempt to detect every possible attack.

It should make unauthorized actions difficult by making authorization:

    explicit
    deterministic
    inspectable
    least-privileged
    fail-closed
    externally controlled
