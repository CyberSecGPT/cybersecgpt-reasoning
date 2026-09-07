# cybersecgpt-reasoning

`cybersecgpt-reasoning` owns executable reasoning-control responsibilities for the CyberSecGPT Native Brain: Intelligence Router control, bounded reasoning budgets, planning/search state, and runtime verifier orchestration.

## Status

**P5 executable bootstrap — normalized request admission, validated substrate discovery, deterministic candidate selection, routing validity, bounded reasoning budgets, routing-budget binding, and deterministic lifecycle control.**

The repository implements boundaries assigned by Accepted ADR-0011 in `CyberSecGPT/cybersecgpt-docs`. It does not own security-policy or authorization decisions, privileged tool execution, native model serving, persistent memory, tokenizer design, training, or model weights.

## Implemented P5 slices

### Normalized request admission

`BrainRequest` is an immutable normalized control envelope for work that is ready to be considered by the Reasoning router. It carries:

- shared Foundation `RequestId` and `CorrelationId` values;
- the already-authoritative Foundation `RoutingSecurityBinding`;
- machine-evaluable task/domain/complexity/safety metadata;
- source/claimed data classification kept separate from authoritative effective classification;
- optional opaque identity-context reference;
- latency, compute, memory, and reasoning ceilings;
- accuracy, determinism, explainability, and verification requirements;
- UTC admission/deadline metadata; and
- canonical bounded JSON input.

`admit_brain_request` serializes raw input through Foundation's defensive JSON bounds before constructing the immutable request. Admission rejects request/security-binding identity mismatch, malformed metadata, invalid resource/deadline state, duplicate verification requirements, and noncanonical direct JSON construction.

This admission contract is **not** an authorization or classification engine. It consumes an already-authoritative `RoutingSecurityBinding`; it does not authenticate identity, mint a grant, evaluate target scope, derive or lower effective data classification, or authorize a side effect. Runtime enforcement of device/compute/memory/cancellation primitives remains outside this slice.

### Validated substrate discovery

`SubstrateDescriptor` is immutable machine-evaluable metadata for one routable intelligence substrate. It uses Foundation `SubstrateId` identity and explicitly carries substrate version/kind/owner, supported capabilities, offline/network properties, determinism and data-handling profiles, bounded resource metadata, authorization and verification requirements, availability state, and source/build/artifact integrity provenance.

A descriptor is not routable merely because a component describes itself. `SubstrateValidationEvidence` is a separate time-bounded record whose trusted boundary owner must have completed source-trust, identity, version, integrity, compatibility, and external policy-constraint checks. `ValidatedSubstrate` refuses incomplete validation evidence, and `validate_substrate_descriptor` rejects evidence that is not yet valid or has expired.

`build_capability_snapshot` creates an immutable deterministic `CapabilitySnapshot` bound to Foundation `CapabilitySnapshotId`. Snapshot members are sorted by substrate identity, duplicate identities are rejected, and validation freshness is rechecked at snapshot creation. Discovery preserves explicit `AVAILABLE`, `DEGRADED`, `UNAVAILABLE`, `REVOKED`, and `INCOMPATIBLE` states rather than silently converting availability into a routing choice.

The snapshot is control metadata, not authorization. Reasoning does not authenticate descriptor validators, evaluate authoritative security policy, grant permissions, or represent the authoritative security-policy/authorization evaluator as a router-selectable substrate. Those trusted boundaries remain external and must be enforced by their owning components.

### Deterministic candidate selection

`select_candidate_substrates` consumes a normalized `BrainRequest`, the exact validated `CapabilitySnapshot` bound by the current `RoutingSecurityBinding`, a current binding, and an immutable `CandidateSelectionPolicy`. It fails closed when request/binding/snapshot/policy identities do not match or when the request deadline has already been reached.

Each discovered substrate receives an immutable `CandidateEvaluation`. Eligibility is machine-evaluable and checks:

- required capability subset without inferring unknown capabilities;
- approved substrate kind;
- explicit availability state and degraded-route policy;
- offline capability when offline operation is mandatory;
- provider/network requirement classes allowed by the current router-policy input;
- exact support for the authoritative effective data classification;
- externally satisfied authorization-requirement facts bound to the current authorization context;
- minimum compute and memory requirements against request ceilings;
- declared maximum latency against the request latency ceiling;
- required determinism profile;
- verification and explainability requirements; and
- validation-evidence freshness at selection time.

Quantitative `required_accuracy` is currently fail-closed because P5 `SubstrateDescriptor` does not yet carry validated quantitative accuracy metadata. The selector therefore refuses to silently infer that a substrate satisfies a requested accuracy threshold.

Eligible candidates are ranked deterministically. `AVAILABLE` substrates rank ahead of `DEGRADED` substrates; within the same availability class the selector prefers lower minimum compute, lower minimum memory, lower declared maximum latency, then lexicographic `SubstrateId` as the stable tie-breaker. This implements the conformance requirement to prefer a competent route within budget rather than automatically selecting the largest substrate.

`CandidateSelectionResult` is proposal/control metadata only. It is **not an authorization grant**, does not execute a substrate, does not mint policy, and does not permit a side effect. The authoritative security-policy/authorization evaluator remains outside the selectable substrate registry and outside this selection function.

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

Budget values are control metadata and do not create permission. A budget cannot be mutated or enlarged by the generic consumption API.

### Routing-budget binding

Every admitted `RoutingDecision` carries one immutable `ReasoningBudget`. `begin_routing_reasoning_budget` creates a zero-usage ledger bound to that routing-decision identity and admitted budget. `consume_routing_reasoning_budget` refuses cross-decision ledger reuse and refuses substitution of a different budget under the same decision before delegating to the monotonic budget accounting layer.

A larger budget therefore requires a fresh routing decision before the routing-bound consumption path will accept it. This binding still does **not** authenticate authorization or make the router an authorizer; authoritative policy and authorization remain outside this repository.

### Deterministic reasoning lifecycle

`ReasoningState` exposes the P5 lifecycle states from `ADMITTED` through planning, evidence, policy, authorized-tool execution, verification/revision, and terminal outcomes. `ReasoningLifecycleSnapshot` is immutable and records:

- routing-decision identity;
- correlation identity;
- monotonic transition sequence;
- previous and current state;
- structured caller-safe cause text; and
- the routing-bound reasoning-budget usage snapshot.

`begin_reasoning_lifecycle` starts at `ADMITTED` with sequence zero. `transition_reasoning_state` increments the sequence by exactly one, applies a bounded routing-bound budget delta, and enforces the explicit transition graph. Terminal states (`COMPLETED`, `DEFERRED`, `DENIED`, `FAILED`, `CANCELLED`) cannot transition again.

`EXECUTING_AUTHORIZED_TOOL` is reachable only from `AWAITING_POLICY`, but the state name is still **not authorization**. This repository does not mint or validate the external grant required for a privileged tool side effect. Cancellation propagation to active components and deadline clocks are intentionally not implemented in this slice.

## Native independence

Core request admission, substrate discovery, candidate selection, routing, budget, and lifecycle control have no proprietary-provider SDK dependency and perform no network I/O.

## Development

Python 3.11–3.13 are supported. CI installs the exact verified `cybersecgpt-foundation` baseline, then runs Ruff, Black, strict mypy, repository/security validation, dependency checks, split-package import verification, pytest with 100% source coverage, package build, and distribution-boundary verification.

## Architecture governance

Read `AGENTS.md` and `docs/ARCHITECTURE.md` before implementation. Cross-repository architecture remains governed by `CyberSecGPT/cybersecgpt-docs`, especially ADR-0011, the Native Brain architecture, threat model, and conformance profile.
