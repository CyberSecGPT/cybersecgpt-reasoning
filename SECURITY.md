# Security Policy

## Security boundary

`cybersecgpt-reasoning` treats routing and reasoning output as control/proposal metadata, never as authorization. Authoritative policy and authorization remain external to this repository. Privileged execution must revalidate current policy, authorization, scope, effective classification, routing bindings, and other required controls immediately before side effects.

## Required properties

- fail closed on expired or mismatched routing decisions;
- never lower effective data classification from untrusted content;
- never widen provider/network permission or offline constraints;
- never treat decision possession as permission;
- never silently fall back to a proprietary remote AI provider;
- keep core runtime dependencies free of provider SDKs;
- enforce immutable reasoning ceilings with monotonic consumption accounting;
- fail closed when proposed reasoning consumption crosses any admitted ceiling;
- never treat candidate agreement, remaining budget, or a budget profile as authorization or verified fact;
- require a fresh authorized routing decision before any future budget enlargement is admitted;
- emit caller-safe typed failures without secrets or private chain-of-thought.

## Reporting a vulnerability

Do not report an undisclosed vulnerability in a public issue. Use the repository or organization private vulnerability reporting mechanism when available and include affected revision, reproduction steps, impact, and any safe diagnostic evidence.
