# cybersecgpt-reasoning

`cybersecgpt-reasoning` owns executable reasoning-control responsibilities for the CyberSecGPT Native Brain, including Intelligence Router control, bounded reasoning budgets, planning/search state, and runtime verifier orchestration.

## Status

**Bootstrap — Roadmap P5: Native Brain Architecture.**

The repository implements the executable boundaries assigned by Accepted ADR-0011 in `CyberSecGPT/cybersecgpt-docs`. It does not own security-policy or authorization decisions, privileged tool execution, native model serving, persistent memory, tokenizer design, training, or model weights.

## Security boundary

Routing output is proposal/control metadata, never an authorization grant. Authoritative security policy and authorization remain outside the router. Routing decisions must remain bound to their admitted request/security state and must be rejected after expiry or any security-relevant binding mismatch.

## Architecture governance

Cross-repository architecture is governed by `CyberSecGPT/cybersecgpt-docs`, especially:

- ADR-0011 — Native Brain System Architecture;
- Native Brain System Architecture;
- Native Brain Threat Model; and
- Native Brain Conformance Profile.

Implementation changes must preserve native/offline independence, non-downgradable effective classification, authorization separation, bounded resource use, explicit verification state, and stale/replay resistance.
