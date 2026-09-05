# cybersecgpt-reasoning Architecture

## Status and governance

This repository implements the Reasoning ownership assigned by Accepted ADR-0011. Cross-repository ownership and security boundaries are governed by `CyberSecGPT/cybersecgpt-docs`.

## Role

Reasoning owns Intelligence Router control, bounded reasoning budgets, planning/search state, and runtime verifier orchestration. Current executable P5 slices implement normalized request admission, structured routing-decision validity, bounded discrete reasoning-budget accounting, routing-to-budget binding, and deterministic reasoning lifecycle transitions.

## Dependency direction

```text
cybersecgpt-reasoning
        |
        v
cybersecgpt-foundation
```

The dependency is one-way. Foundation must not depend on Reasoning. Reasoning must not import provider SDKs, application layers, tool executors, security-policy implementations, model runtimes, or persistent memory implementations into its core package.

## Normalized request admission

`BrainRequest` is the immutable Reasoning-side normalized envelope used before routing consideration. It reuses Foundation-owned cross-domain identifiers and security bindings rather than inventing duplicate request/security identity types.

The request contains:

- Foundation `RequestId` and `CorrelationId`;
- one Foundation `RoutingSecurityBinding` whose request identity must match the envelope;
- validated machine-evaluable `task_type`, `domain`, `task_complexity`, and `safety_impact` tokens;
- optional source/claimed data-classification metadata kept distinct from the authoritative effective classification inside `RoutingSecurityBinding`;
- an optional opaque identity-context reference;
- non-negative latency, compute, and memory ceilings;
- one immutable `ReasoningBudget` for reasoning/model/tool/retrieval/verifier accounting;
- accuracy, determinism, explainability, and verification requirements;
- UTC admission and optional deadline timestamps; and
- bounded canonical JSON task input.

`admit_brain_request` accepts raw JSON-compatible input and uses Foundation's defensive JSON serializer to enforce payload, nesting, container, key, string, and node safety bounds before storing only the canonical immutable JSON representation. Direct construction also validates that supplied `input_json` is valid and canonical, preventing mutable Python containers or ambiguous serialized representations from becoming internal request state.

Admission is structural control, not security-policy evaluation. It requires an already-authoritative `RoutingSecurityBinding`; it does not authenticate an actor, mint or validate a grant, evaluate target scope, derive effective data classification, widen provider/network permissions, or authorize a side effect. Source-provided classification is retained only as untrusted metadata and is never copied into the authoritative effective-classification field by this layer.

The envelope carries compute/memory/latency ceilings for later routing and runtime enforcement. This slice does not itself implement device-resource enforcement, cancellation propagation, or runtime deadline clocks; generic execution primitives remain owned by `cybersecgpt-runtime` under ADR-0011.

## Routing-decision contract

`RoutingDecision` contains:

- a typed routing-decision identity;
- the immutable Foundation `RoutingSecurityBinding` admitted for the decision;
- router policy identity and version;
- one or more selected substrate identities;
- structured reason codes;
- one immutable admitted `ReasoningBudget`;
- a UTC creation time; and
- a UTC expiry time.

It is immutable after construction. Replanning must create a new decision rather than mutating an admitted one. Changing the admitted reasoning budget therefore also requires a new routing decision; the existing decision has no budget-extension operation.

## Routing validation boundary

`validate_routing_decision` compares a decision against the current Foundation `RoutingSecurityBinding` and current UTC time. It reports deterministic typed reasons for:

- not-yet-valid decision time;
- expiry;
- request mismatch;
- authorization-context mismatch;
- security-policy revision mismatch;
- effective data-classification mismatch;
- provider/network policy mismatch;
- offline-requirement mismatch; and
- capability-snapshot mismatch.

The validator does not authenticate a binding, evaluate policy, verify target scope, consume a one-time grant, or authorize a side effect. Those remain responsibilities of their authoritative owners. Same-context replay/consumption tracking at a privileged side-effect boundary is therefore outside this slice; stale/replayed decisions that cross request/security bindings or lifetime are rejected here.

## Reasoning-budget contract

`ReasoningBudget` is immutable controller metadata defining explicit ceilings for:

- generated/evaluated candidates;
- branch-depth high-water mark;
- reasoning steps;
- model-token accounting;
- tool-call accounting;
- retrieval-call accounting; and
- verifier-pass accounting.

The budget also carries a validated policy name and optional unique structured stop-condition labels. Policy names are not intelligence claims and are not restricted to a closed enum by this slice.

`ReasoningBudgetUsage` is an immutable generic snapshot against exactly one immutable budget. `ReasoningBudgetDelta` describes a non-negative proposed increment. `consume_reasoning_budget` returns a new usage snapshot only when all resulting values remain within their ceilings. Candidate, step, token, tool, retrieval, and verifier counters are additive. Branch depth is a monotonic high-water mark and cannot decrease through consumption.

Reaching a ceiling exactly is valid and is reported through `exhausted_reasoning_budget_dimensions`. Any proposed value above a ceiling fails closed with typed `ReasoningBudgetDimension` values on `ReasoningBudgetExceededError`; the prior usage snapshot remains unchanged.

## Routing-budget binding

`RoutingReasoningBudgetUsage` binds one `ReasoningBudgetUsage` ledger to one `RoutingDecisionId`. `begin_routing_reasoning_budget` constructs that ledger directly from the immutable budget carried by the admitted routing decision.

`consume_routing_reasoning_budget` checks both invariants before any usage is advanced:

1. the ledger's routing-decision identity must equal the supplied admitted decision identity; and
2. the ledger's immutable budget must equal the budget carried by that decision.

A cross-decision ledger or a substituted larger/different budget fails closed with `RoutingReasoningBudgetError`. Only after those checks pass does the routing layer delegate to the generic monotonic budget consumer. This prevents the routing-integrated path from using budget substitution as an implicit extension mechanism.

This binding is control-state validation, not authorization. It does not authenticate the decision, evaluate policy, mint a grant, widen target scope, or make the router authoritative for security. A caller must still supply a currently valid decision admitted under the external authoritative security/authorization path.

## Deterministic reasoning lifecycle

`ReasoningState` implements the P5 conceptual state vocabulary:

```text
ADMITTED
PLANNING
GATHERING_EVIDENCE
GENERATING_CANDIDATES
AWAITING_POLICY
EXECUTING_AUTHORIZED_TOOL
VERIFYING
REVISING
COMPLETED
DEFERRED
DENIED
FAILED
CANCELLED
```

`ReasoningLifecycleSnapshot` is an immutable control snapshot carrying routing-decision identity, Foundation `CorrelationId`, monotonic sequence, previous/current state, a caller-safe cause, and a `RoutingReasoningBudgetUsage` snapshot. Using Foundation's shared identifier preserves one cross-domain correlation contract across Reasoning and other CyberSecGPT components instead of introducing a duplicate local identifier representation.

`begin_reasoning_lifecycle` creates only `ADMITTED` at sequence zero. Every transition produced by `transition_reasoning_state` increments sequence by exactly one and applies its `ReasoningBudgetDelta` through the routing-bound budget consumer before returning a new immutable snapshot.

The initial transition graph is deliberately conservative:

- terminal states `COMPLETED`, `DEFERRED`, `DENIED`, `FAILED`, and `CANCELLED` have no outgoing transitions;
- `ADMITTED` cannot be re-entered after sequence zero;
- `EXECUTING_AUTHORIZED_TOOL` is reachable only from `AWAITING_POLICY`;
- iterative planning/evidence/candidate/verification/revision states may loop only through explicitly enumerated edges; and
- invalid state edges fail closed with `ReasoningLifecycleError`.

The `EXECUTING_AUTHORIZED_TOOL` state is descriptive control metadata, not permission. The lifecycle layer does not authenticate policy state, evaluate authorization, invoke a tool, or permit a side effect. Privileged execution must still use the authoritative external policy/authorization path and current routing/security revalidation.

Terminal `CANCELLED` prevents further lifecycle transitions. This slice does not yet propagate cancellation signals to active model/tool/retrieval/verifier components and does not implement deadline clocks; those remain separate P5 integration work.

## Native independence

The core package has no proprietary-provider SDK dependency and performs no network I/O. Removing provider credentials does not affect request admission, routing-decision validation, routing-budget binding, budget accounting, or lifecycle transitions.

## Future P5 slices

Later P5 work may add validated substrate discovery, deterministic candidate selection, cancellation/deadline propagation, fallback replanning, and verifier orchestration. Those must be implemented incrementally with tests and may not cross into tokenizer, training, model-weight, persistent-memory, or privileged-tool ownership.
