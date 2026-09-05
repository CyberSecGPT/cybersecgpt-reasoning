# cybersecgpt-reasoning

`cybersecgpt-reasoning` owns executable reasoning-control responsibilities for the CyberSecGPT Native Brain: Intelligence Router control, bounded reasoning budgets, planning/search state, and runtime verifier orchestration.

## Status

**P5 executable bootstrap — routing-decision validity slice.**

The repository implements boundaries assigned by Accepted ADR-0011 in `CyberSecGPT/cybersecgpt-docs`. It does not own security-policy or authorization decisions, privileged tool execution, native model serving, persistent memory, tokenizer design, training, or model weights.

## Implemented in this slice

- immutable structured `RoutingDecision` values;
- typed router reason codes;
- explicit decision creation and expiry timestamps;
- exact binding to Foundation `RoutingSecurityBinding` state;
- deterministic validation against current request, authorization-context, policy-revision, effective-classification, provider/network, offline, and capability-snapshot state;
- explicit stale/expired/not-yet-valid failure reasons;
- no provider SDK or proprietary remote AI runtime dependency.

A routing decision is **not** an authorization grant. The validator only proves that the supplied decision still matches the supplied current routing-security binding and lifetime. Authoritative security policy, authorization, target scope, and side-effect permission remain external control-plane responsibilities and must still be revalidated at the privileged execution boundary.

## Development

Python 3.11–3.13 are supported. CI installs the exact verified `cybersecgpt-foundation` baseline, then runs Ruff, Black, strict mypy, repository/security validation, dependency checks, pytest with 100% source coverage, package build, and distribution-boundary verification.

## Architecture governance

Read `AGENTS.md` and `docs/ARCHITECTURE.md` before implementation. Cross-repository architecture remains governed by `CyberSecGPT/cybersecgpt-docs`, especially ADR-0011, the Native Brain architecture, threat model, and conformance profile.
