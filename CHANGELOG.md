# Changelog

All notable changes to `agent-firewall` are documented here.

The project follows a simple versioning approach.

---

## [0.1.0] — 2026-08-27

### Added

- **Phase 1 — Deterministic Core**
  - Request, Decision, DecisionKind model
  - Rule and Policy data structures
  - Deterministic evaluator with deny-approve-allow precedence
  - Resource normalization and matching (glob, exact, segment-level wildcards)

- **Phase 2 — CLI**
  - `agent-firewall check` — evaluate a single request
  - `agent-firewall explain` — detailed decision explanation
  - `agent-firewall simulate` — compare current vs proposed policy
  - `agent-firewall diff` — compare two policy files
  - `agent-firewall approve` — validate approval records
  - Machine-readable JSON output
  - Structured exit codes (0=ALLOW, 1=DENY, 2=APPROVE, 3-5=errors)

- **Phase 3 — Policy Tooling**
  - `agent-firewall lint` — detect policy quality issues
  - `agent-firewall test` — evaluate policy against test cases
  - `agent-firewall capabilities` — enumerate effective permissions
  - Conflict detection for overlapping allow/deny rules

- **Phase 4 — Audit**
  - JSONL evidence recording
  - Request hashing for audit binding
  - Secret redaction in audit output

- **Phase 5 — Approval**
  - Request hash binding for approvals
  - Approval expiration
  - Self-approval protection

- **Phase 6 — Policy Simulation**
  - Policy comparison and simulation engine
  - Before/after analysis

- **Phase 7 — Policy Diff**
  - Structured policy diff output
  - Added/removed rule detection

- **Phase 8 — Filesystem Adapter**
  - FilesystemAdapter for file operation authorization
  - Path-based resource matching

- **Phase 9 — Process Adapter**
  - ProcessAdapter for subprocess authorization
  - Command and argument matching

- **Phase 10 — Git Adapter**
  - GitAdapter for Git operation authorization
  - Ref and path matching

- **Phase 11 — Network Adapter**
  - NetworkAdapter for network operation authorization
  - Host and URL matching

- **Phase 12 — MCP Adapter**
  - MCP bridge for tool-call translation to firewall requests
  - Configurable tool-name-to-action mapping
  - Unknown tool names fail closed (deny by default)
  - MCP SDK remains optional (not a runtime dependency)

- **Phase 13 — Orchestrator Integration**
  - OrchestratorBridge for batch authorization
  - TaskAuthorization result type
  - Sequential Firewall.check() delegation

- **Phase 14 — Sandbox Integration**
  - SandboxAdapter for sandboxed execution authorization
  - SandboxProtocol for external sandbox providers
  - Authorization-before-execution enforcement
  - SandboxError for sandbox failures

- **Phase 15 — Advanced Integrity**
  - Hash chain for evidence records (ChainedEvidenceRecord, EvidenceChain)
  - Policy integrity verification (PolicyIntegrity, PolicyIntegrityVerifier)
  - Capability expiration (ExpiringCapability, CapabilityExpirationList)
  - Capability revocation (RevocationEntry, RevocationList)
  - check_with_revocation() wrapper

- **Phase 16 — Advanced Policy Analysis**
  - Permission graph enumeration (PolicyAnalyzer.permission_graph)
  - Privilege mismatch detection (cross-agent advisory)
  - Unused capability analysis (evidence-based)
  - Broad permission detection
  - Conflict analysis (structured)
  - Reachability analysis (policy-matching, not authorization)
  - Deterministic serialization (to_dict, to_text)

- **Phase 17 — Policy Suggestions**
  - PolicySuggestion frozen dataclass
  - PolicySuggestionEngine for generating suggestions from findings and audit records
  - proposed_policy() for constructing proposed policies
  - export_suggestions() for JSON/text export
  - Advisory only — never modifies active policy

- **Phase 18 — Policy Suggestion Validation**
  - SuggestionValidator for validating suggestions against lint and test infrastructure
  - SuggestionValidationResult with regression detection
  - New lint finding detection via key-based comparison
  - Test regression detection (source pass → proposed fail)
  - Advisory only — never activates or applies suggestions

### Security

- Default deny on all unrecognized requests
- Fail closed on all authorization errors
- Zero third-party runtime dependencies
- No LLM in the authorization path
- No network access in the core
- No subprocess execution in the core
- No hidden policy mutation
- No hidden side effects in authorization functions

### Notes

- This is a pre-1.0 release
- All public APIs are subject to change
- The project is intentionally small and focused
- Future functionality will be added through adapters, not by expanding the core

---

# Changelog guidelines

Document externally observable changes.

Include:

- new features
- changed behavior
- removed behavior
- bug fixes
- security fixes
- breaking changes

Security fixes should clearly identify their impact without publishing unnecessary exploit details.

---

# Format

    ## [VERSION] — YYYY-MM-DD

    ### Added

    ### Changed

    ### Fixed

    ### Removed

    ### Security
