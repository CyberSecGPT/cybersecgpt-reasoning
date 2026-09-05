# cybersecgpt-reasoning Architecture

## Status and governance

This repository implements the Reasoning ownership assigned by Accepted ADR-0011. Cross-repository ownership and security boundaries are governed by `CyberSecGPT/cybersecgpt-docs`.

## Role

Reasoning owns Intelligence Router control, bounded reasoning budgets, planning/search state, and runtime verifier orchestration. Current executable P5 slices implement structured routing-decision validity, bounded discrete reasoning-budget accounting, and routing-to-budget binding.

## Dependency direction

```text
cybersecgpt-reasoning
        |
        v
cybersecgpt-foundation
```

The dependency is one-way. Foundation must not depend on Reasoning. Reasoning must not import provider SDKs, application layers, tool executors, security-policy implementations, model runtimes, or persistent memory implementations into its core package.

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

This binding is control-state validation, not authorization. It does not authenticate the decision, evaluate policy, mint a grant, widen target scope, or make the router authoritative for security. A future caller must still supply a currently valid decision admitted under the external authoritative security/authorization path.

This slice intentionally does not implement deadline clocks, cancellation propagation, recursive delegation, lifecycle state transitions, model execution, tool execution, retrieval execution, or verifier execution. Those remain separate incremental P5/later-owner work and must preserve the same ceilings and authorization boundaries when integrated.

## Native independence

The core package has no proprietary-provider SDK dependency and performs no network I/O. Removing provider credentials does not affect routing-decision validation, routing-budget binding, or reasoning-budget accounting.

## Future P5 slices

Later P5 work may add normalized request admission, validated substrate discovery, deterministic candidate selection, explicit reasoning-state transitions and cancellation/deadline propagation, fallback replanning, and verifier orchestration. Those must be implemented incrementally with tests and may not cross into tokenizer, training, model-weight, persistent-memory, or privileged-tool ownership.
