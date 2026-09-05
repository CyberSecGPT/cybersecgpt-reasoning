# Security Policy

## Security boundary

`cybersecgpt-reasoning` treats request, routing, and reasoning state as control/proposal metadata, never as authorization. Authoritative policy and authorization remain external to this repository. Privileged execution must revalidate current policy, authorization, scope, effective classification, routing bindings, and other required controls immediately before side effects.

## Required properties

- reject malformed normalized request metadata before routing;
- require request identity to match the supplied authoritative `RoutingSecurityBinding`;
- keep source/claimed classification separate from authoritative effective classification and never derive the latter from untrusted request content;
- bound task input through Foundation's defensive JSON limits and store canonical immutable JSON rather than mutable caller containers;
- reject invalid UTC admission/deadline metadata and malformed resource ceilings;
- fail closed on expired or mismatched routing decisions;
- never lower effective data classification from untrusted content;
- never widen provider/network permission or offline constraints;
- never treat request admission or decision possession as permission;
- never silently fall back to a proprietary remote AI provider;
- keep core runtime dependencies free of provider SDKs;
- enforce immutable reasoning ceilings with monotonic consumption accounting;
- fail closed when proposed reasoning consumption crosses any admitted ceiling;
- bind routing-integrated budget usage to both routing-decision identity and the decision's immutable admitted budget;
- reject cross-decision budget-ledger reuse and same-decision budget substitution;
- preserve immutable lifecycle snapshots with monotonic transition sequences and routing-bound budget snapshots;
- make terminal lifecycle outcomes final so completed, deferred, denied, failed, or cancelled work cannot be resumed by mutating control state;
- allow the `EXECUTING_AUTHORIZED_TOOL` lifecycle state only after `AWAITING_POLICY`, while never treating that state transition as an authorization grant;
- never treat candidate agreement, remaining budget, lifecycle state, or a budget profile as authorization or verified fact;
- require a fresh authorized routing decision before any future budget enlargement is admitted;
- emit caller-safe typed failures without secrets or private chain-of-thought.

Normalized request admission validates structure and carries already-authoritative security references. It does not authenticate identity, evaluate security policy, validate target scope, grant side-effect permission, or perform runtime device/compute/memory enforcement.

Cancellation state is terminal in the current lifecycle contract. Propagation of cancellation to active model/tool/retrieval/verifier components is a separate required P5 integration and is not claimed by this slice.

## Reporting a vulnerability

Do not report an undisclosed vulnerability in a public issue. Use the repository or organization private vulnerability reporting mechanism when available and include affected revision, reproduction steps, impact, and any safe diagnostic evidence.
