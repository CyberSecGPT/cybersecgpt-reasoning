# Changelog

## Unreleased

### Added

- P5 Reasoning repository bootstrap.
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
