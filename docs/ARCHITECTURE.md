# cybersecgpt-reasoning Architecture

## Status and governance

This repository implements the Reasoning ownership assigned by Accepted ADR-0011. Cross-repository ownership and security boundaries are governed by `CyberSecGPT/cybersecgpt-docs`.

## Role

Reasoning owns Intelligence Router control, bounded reasoning budgets, planning/search state, and runtime verifier orchestration. Current executable P5 slices implement structured routing-decision validity and bounded discrete reasoning-budget accounting.

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
- a UTC creation time; and
- a UTC expiry time.

It is immutable after construction. Replanning must create a new decision rather than mutating an admitted one.

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

`ReasoningBudgetUsage` is an immutable snapshot against exactly one immutable budget. `ReasoningBudgetDelta` describes a non-negative proposed increment. `consume_reasoning_budget` returns a new usage snapshot only when all resulting values remain within their ceilings. Candidate, step, token, tool, retrieval, and verifier counters are additive. Branch depth is a monotonic high-water mark and cannot decrease through consumption.

Reaching a ceiling exactly is valid and is reported through `exhausted_reasoning_budget_dimensions`. Any proposed value above a ceiling fails closed with typed `ReasoningBudgetDimension` values on `ReasoningBudgetExceededError`; the prior usage snapshot remains unchanged.

This slice does not authorize budget enlargement. The budget is frozen and the consumption API has no extension operation. A future routing/budget integration must bind any enlarged budget to a newly admitted authorized routing decision rather than reusing an existing decision or usage ledger.

This slice intentionally does not implement deadline clocks, cancellation propagation, recursive delegation, lifecycle state transitions, model execution, tool execution, retrieval execution, or verifier execution. Those remain separate incremental P5/later-owner work and must preserve the same ceilings and authorization boundaries when integrated.

## Native independence

The core package has no proprietary-provider SDK dependency and performs no network I/O. Removing provider credentials does not affect routing-decision validation or reasoning-budget accounting.

## Future P5 slices

Later P5 work may add normalized request admission, validated substrate discovery, deterministic candidate selection, explicit reasoning-state transitions and cancellation/deadline propagation, fallback replanning, routing/budget binding, and verifier orchestration. Those must be implemented incrementally with tests and may not cross into tokenizer, training, model-weight, persistent-memory, or privileged-tool ownership.
