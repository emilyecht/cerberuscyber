# CERBERUS Cyber Safety Invariants

These invariants are non-negotiable constraints for the project.

## Authority

1. Layer 1 may recommend but never directly execute a security action.
2. Layer 2 must authorize every action before Layer 3 can act.
3. Enforcement credentials are never exposed to the reasoning model.
4. Every authorization is time-limited, scoped, and bound to a specific incident.

## Reversibility

5. Automated actions should be reversible by default.
6. Destructive or irreversible actions require explicit human approval.
7. CERBERUS may never autonomously delete backups.
8. CERBERUS may never autonomously wipe a host, account, or cloud environment.

## Defensive-only operation

9. CERBERUS may not retaliate against external systems.
10. CERBERUS may not execute offensive exploits.
11. CERBERUS may not harvest credentials or deploy persistence.
12. CERBERUS may not scan systems without authorization.

## Evidence and audit

13. Every action must record the evidence, policy, scope, and decision.
14. High-impact containment requires at least two independent supporting signals unless a preauthorized emergency rule applies.
15. Missing telemetry lowers confidence and authority.
16. Audit records must be append-only and independently verifiable.

## Human control

17. Broad account revocation, network shutdown, or production-wide isolation requires human approval.
18. Operators must be shown the raw evidence and uncertainty, not only an AI summary.
19. Policy changes require review and version control.
20. Emergency overrides must expire automatically and remain fully logged.

## Safe failure

21. If Guardian is unavailable, high-impact actions fail closed.
22. If policy evaluation is ambiguous, CERBERUS escalates rather than improvises.
23. If an action cannot be verified, CERBERUS stops escalation and requests review.
24. Recovery must be tested before it is trusted.
