# TEST_PLAN.md — agent-firewall Test Plan

## 1. Purpose

This document defines how the implementation proves that it satisfies the specification and security model.

Tests are part of the security architecture.

---

# 2. Testing principles

Tests must be:

- deterministic
- offline
- repeatable
- dependency-free for the runtime
- focused on public behavior
- security-oriented

---

# 3. Core decision tests

Test:

    explicit allow -> ALLOW
    explicit deny -> DENY
    explicit approve -> APPROVE
    no matching rule -> DENY

---

# 4. Default-deny tests

Verify:

    unknown agent -> DENY
    unknown action -> DENY
    unknown resource -> DENY
    empty policy -> DENY
    missing permissions -> DENY

---

# 5. Policy parser tests

Test:

    valid policy loads
    missing version fails
    unsupported version fails
    malformed JSON fails
    malformed rule fails
    malformed agent policy fails
    invalid field types fail
    partially valid policy does not become active

---

# 6. Rule precedence tests

Test:

    deny overrides allow
    deny overrides approve
    approve overrides allow
    no match -> deny

Example:

    allow filesystem.write ./**
    deny filesystem.write ./secret/**

Expected:

    ./src/main.py -> ALLOW
    ./secret/key -> DENY

---

# 7. Action matching tests

Test:

    exact action match
    unknown action
    similar action names

Example:

    filesystem.read

must not implicitly authorize:

    filesystem.write

---

# 8. Resource matching tests

Test:

    exact resource
    wildcard resource
    nested path
    nonmatching path
    resource-less action
    resource supplied when not expected

---

# 9. Path normalization tests

Test:

    ./src/file.py
    src/file.py
    ./src/../src/file.py
    ./src/../../secret
    absolute paths
    platform separators

Expected behavior must be deterministic.

---

# 10. Traversal tests

Test requests such as:

    ../secret
    ../../etc/passwd
    ./allowed/../secret
    ./allowed/../../secret

Ensure policy cannot be bypassed through normalization tricks.

---

# 11. Symlink tests

Where filesystem adapters exist:

- allowed path pointing to denied target
- denied path pointing to allowed target
- symlink replacement
- broken symlink

Document which guarantees belong to the adapter rather than core.

---

# 12. Identity tests

Test:

    known agent
    unknown agent
    missing agent
    malformed agent

Ensure agent identity cannot be supplied through arbitrary policy fields.

---

# 13. Approval tests

Test:

    valid approval
    missing approval
    expired approval
    malformed approval
    wrong agent
    wrong action
    wrong resource
    wrong policy version
    wrong policy generation
    wrong request hash
    self approval

All invalid approval cases must fail closed.

---

# 14. Request hashing tests

The same canonical request must produce the same hash.

Different authorization-relevant requests must produce different hashes.

Test:

    agent changes
    action changes
    resource changes
    policy generation changes

---

# 15. Canonicalization tests

Ensure serialization is deterministic regardless of:

- dictionary insertion order
- irrelevant metadata order
- formatting differences

---

# 16. Expiration tests

Test:

    expiration in future -> valid
    expiration now -> expired according to defined semantics
    expiration in past -> invalid
    malformed timestamp -> invalid

---

# 17. Audit tests

Verify:

- decisions produce valid JSON when auditing
- JSONL records are parseable
- required fields are present
- secret values are absent
- audit failure does not convert DENY into ALLOW

---

# 18. Secret redaction tests

Use fake secret values.

Verify that they never appear in:

- decision output
- JSON output
- error output
- audit records
- debug output

---

# 19. CLI tests

Test:

    check
    explain
    --json
    missing arguments
    invalid policy
    invalid request

Verify exact exit codes.

---

# 20. Exit-code tests

Verify:

    ALLOW -> 0
    DENY -> 1
    APPROVE -> 2
    INVALID_REQUEST -> 3
    INVALID_POLICY -> 4
    INTERNAL_ERROR -> 5

---

# 21. Explain tests

Verify explain output contains:

    decision
    agent
    action
    resource where relevant
    rule where available
    reason where available

Explain must not execute the action.

---

# 22. Side-effect tests

Core evaluation must not:

- create files
- modify files
- execute processes
- contact network
- modify policy
- invoke external commands

Tests should verify this where practical.

---

# 23. Offline tests

The complete core suite must run with network unavailable.

No external service should be required.

---

# 24. Dependency tests

Verify runtime package metadata contains no third-party runtime dependencies.

The project should be inspectable using only standard Python tooling.

---

# 25. Policy snapshot tests

Test:

    load policy version 1
    evaluate request
    change policy file
    evaluate using existing snapshot

The existing snapshot must remain stable.

A newly loaded policy may produce a different result.

---

# 26. Concurrency tests

Where concurrency is supported:

- multiple evaluations
- same policy snapshot
- simultaneous requests

must not mutate one another.

---

# 27. Determinism tests

Run identical requests repeatedly.

Expected:

    same request
    +
    same policy
    =
    same decision

Run with different rule ordering if ordering is not semantically meaningful.

The result must remain the same.

---

# 28. Fuzz testing

Future work may fuzz:

- policy parser
- request parser
- path normalization
- resource matcher

Any malformed input must fail safely.

---

# 29. Regression tests

Every security bug discovered should become a regression test.

Test names should describe the invariant being protected.

---

# 30. Security invariant checklist

The following must always pass:

    [ ] unknown agent -> DENY
    [ ] unknown action -> DENY
    [ ] unknown resource -> DENY
    [ ] empty policy -> DENY
    [ ] invalid policy -> no ALLOW
    [ ] normalization failure -> no ALLOW
    [ ] deny overrides allow
    [ ] expired approval -> DENY
    [ ] wrong approval hash -> DENY
    [ ] self approval -> DENY
    [ ] secret values never logged
    [ ] policy snapshots are stable
    [ ] evaluator has no external side effects
    [ ] core works offline
    [ ] runtime has zero third-party dependencies

---

# 31. Test completion

A phase is complete only when:

- new functionality has tests
- relevant security invariants pass
- existing tests still pass
- CLI behavior is verified
- failure behavior is verified
- no forbidden dependencies were added
