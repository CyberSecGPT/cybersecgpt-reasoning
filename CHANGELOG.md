# Changelog

## Unreleased

### Added

- P5 Reasoning repository bootstrap.
- Immutable normalized `BrainRequest` admission with shared Foundation identifiers and authoritative routing-security binding reuse.
- Canonical bounded JSON request input plus machine-evaluable task, resource, deadline, and verification metadata.
- Immutable `SubstrateDescriptor` metadata using shared Foundation `SubstrateId` identities and explicit kind, capability, network, data-handling, resource, availability, and provenance fields.
- Separate time-bounded `SubstrateValidationEvidence` requiring trusted-source, identity, version, integrity, compatibility, and external policy checks before a descriptor becomes validated discovery state.
- Deterministic immutable `CapabilitySnapshot` values bound to Foundation `CapabilitySnapshotId` identities, with duplicate-ID rejection and validation-freshness rechecks.
- Immutable structured routing decisions bound to Foundation routing-security state.
- Deterministic lifetime and binding validation with typed invalidity reasons.
- Structured routing reason codes without private chain-of-thought requirements.
- Immutable bounded `ReasoningBudget`, `ReasoningBudgetUsage`, and `ReasoningBudgetDelta` contracts.
- Monotonic budget consumption with candidate, branch-depth, step, model-token, tool-call, retrieval-call, and verifier-pass ceilings.
- Typed exhausted/exceeded budget dimensions with fail-closed over-consumption behavior.
- Immutable `ReasoningBudget` binding carried by every `RoutingDecision`.
- Routing-bound budget usage that rejects cross-decision ledger reuse and same-decision budget substitution.
- Deterministic immutable reasoning lifecycle snapshots with correlation identity, monotonic sequence, transition cause, and routing-bound budget usage.
- Explicit state-transition policy with terminal-state lockout and policy-gated entry to the authorized-tool execution state.
- Shared Foundation `CorrelationId` enforced for reasoning lifecycle correlation identity.
- Python 3.11–3.13 CI with strict static, security, coverage, build, and distribution checks.
