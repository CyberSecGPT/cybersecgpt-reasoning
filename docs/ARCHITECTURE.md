# cybersecgpt-reasoning Architecture

## Status and governance

This repository implements the Reasoning ownership assigned by Accepted ADR-0011. Cross-repository ownership and security boundaries are governed by `CyberSecGPT/cybersecgpt-docs`.

## Role

Reasoning owns Intelligence Router control, bounded reasoning budgets, planning/search state, and runtime verifier orchestration. This initial P5 slice implements only structured routing-decision validity.

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

## Validation boundary

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

## Native independence

The core package has no proprietary-provider SDK dependency and performs no network I/O. Removing provider credentials does not affect routing-decision construction or validation.

## Future P5 slices

Later P5 work may add normalized request admission, validated substrate discovery, deterministic candidate selection, bounded reasoning budgets/state transitions, fallback replanning, and verifier orchestration. Those must be implemented incrementally with tests and may not cross into tokenizer, training, model-weight, persistent-memory, or privileged-tool ownership.
