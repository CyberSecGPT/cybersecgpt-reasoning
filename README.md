# cybersecgpt-reasoning

`cybersecgpt-reasoning` owns executable reasoning-control responsibilities for the CyberSecGPT Native Brain: Intelligence Router control, bounded reasoning budgets, planning/search state, and runtime verifier orchestration.

## Status

**P5 executable bootstrap — routing validity and bounded reasoning-control slices.**

The repository implements boundaries assigned by Accepted ADR-0011 in `CyberSecGPT/cybersecgpt-docs`. It does not own security-policy or authorization decisions, privileged tool execution, native model serving, persistent memory, tokenizer design, training, or model weights.

## Implemented P5 slices

### Routing-decision validity

- immutable structured `RoutingDecision` values;
- typed router reason codes;
- explicit decision creation and expiry timestamps;
- exact binding to Foundation `RoutingSecurityBinding` state;
- deterministic validation against current request, authorization-context, policy-revision, effective-classification, provider/network, offline, and capability-snapshot state;
- explicit stale/expired/not-yet-valid failure reasons.

A routing decision is **not** an authorization grant. The validator only proves that the supplied decision still matches the supplied current routing-security binding and lifetime. Authoritative security policy, authorization, target scope, and side-effect permission remain external control-plane responsibilities and must still be revalidated at the privileged execution boundary.

### Bounded reasoning budgets

- immutable `ReasoningBudget` ceilings for candidates, branch depth, steps, model tokens, tool calls, retrieval calls, and verifier passes;
- immutable `ReasoningBudgetUsage` snapshots;
- monotonic `ReasoningBudgetDelta` consumption;
- branch depth tracked as a monotonic high-water mark rather than an additive counter;
- exact-limit consumption allowed and machine-evaluable exhausted dimensions reported;
- fail-closed `ReasoningBudgetExceededError` when any proposed consumption crosses a ceiling;
- explicit stop-condition labels without requiring private chain-of-thought.

Budget values are control metadata and do not create permission. A budget cannot be mutated or enlarged by the consumption API. Any future increase must be admitted through a fresh authorized routing decision when the routing/budget integration slice is implemented; this slice intentionally does not mint or evaluate authorization.

## Native independence

Core routing and budget control have no proprietary-provider SDK dependency and perform no network I/O.

## Development

Python 3.11–3.13 are supported. CI installs the exact verified `cybersecgpt-foundation` baseline, then runs Ruff, Black, strict mypy, repository/security validation, dependency checks, split-package import verification, pytest with 100% source coverage, package build, and distribution-boundary verification.

## Architecture governance

Read `AGENTS.md` and `docs/ARCHITECTURE.md` before implementation. Cross-repository architecture remains governed by `CyberSecGPT/cybersecgpt-docs`, especially ADR-0011, the Native Brain architecture, threat model, and conformance profile.
