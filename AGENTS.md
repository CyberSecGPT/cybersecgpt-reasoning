# CyberSecGPT Reasoning Agent Instructions

Before modifying this repository:

1. Read `README.md`, `docs/ARCHITECTURE.md`, `SECURITY.md`, and `CONTRIBUTING.md`.
2. Treat Accepted ADR-0011, the Native Brain architecture, threat model, and conformance profile in `CyberSecGPT/cybersecgpt-docs` as governing cross-repository contracts.
3. Preserve repository ownership: Reasoning may control routing/reasoning state, but it must not implement or bypass authoritative security policy, authorization, privileged tool execution, model serving, persistent memory, or later tokenizer/training milestones.
4. A routing decision, prompt, model output, verifier output, retrieval result, memory record, or tool result never creates permission.
5. Effective data classification, provider/network policy, offline requirements, capability snapshots, policy revisions, authorization-context references, and expiry bindings must be machine-evaluable and must not be weakened by free-form content.
6. Core behavior must not require proprietary remote AI providers or provider SDKs.
7. Every change must include tests for success and failure paths and must pass the repository CI gate before merge.
8. Do not weaken tests, coverage, static analysis, secret scanning, or distribution-boundary checks to make a change pass.
