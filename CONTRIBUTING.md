# CONTRIBUTING.md — Contributing to agent-firewall

## 1. Philosophy

Contributions should make the project:

- simpler
- safer
- more deterministic
- more inspectable
- more composable

Avoid contributions that make the core unnecessarily large.

---

# 2. Setup

Requires Python 3.10 or later.

    python -m venv .venv
    source .venv/bin/activate   # Windows: .venv\Scripts\activate
    pip install -e .

Run the test suite:

    python -m unittest discover -s tests -t .

There are zero runtime dependencies.
Do not add third-party packages.

---

# 3. Before contributing

Read:

- AGENTS.md
- DESIGN.md
- SPEC.md
- SECURITY.md
- THREAT_MODEL.md
- IMPLEMENTATION.md
- TEST_PLAN.md
- ROADMAP.md

---

# 4. Dependency policy

Runtime dependencies must remain zero unless explicitly approved.

Before adding a dependency, ask:

    Can the standard library reasonably solve this?

If yes, use the standard library.

---

# 5. Scope

Do not combine unrelated features into one change.

Prefer small changes with:

- clear purpose
- focused tests
- documented behavior

---

# 6. Security-sensitive changes

Changes involving authorization must include tests.

Examples:

- evaluator
- policy parsing
- normalization
- resource matching
- approval
- identity
- audit redaction

---

# 7. Public API

Avoid unnecessary breaking changes.

Treat these as public:

- Python API
- CLI
- exit codes
- JSON schema
- policy format
- decision values

---

# 8. Pull requests

A contribution should explain:

- what changed
- why it changed
- which specification requirement it satisfies
- tests added
- security implications
- whether public behavior changed

---

# 9. Documentation

If externally observable behavior changes, update:

    SPEC.md

If architecture changes:

    DESIGN.md

If implementation structure changes:

    IMPLEMENTATION.md

If security assumptions change:

    SECURITY.md

or:

    THREAT_MODEL.md

If tests change:

    TEST_PLAN.md

If scope changes:

    ROADMAP.md

---

# 10. Do not hide behavior

Avoid:

- implicit permissions
- hidden defaults
- network calls
- undocumented environment switches
- automatic policy changes
- silent fallback authorization

---

# 11. Principle

The best contribution is not necessarily the largest one.

Prefer the smallest change that solves the actual problem without weakening the project's architecture.
