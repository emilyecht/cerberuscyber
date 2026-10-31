# CERBERUS Cyber Safety Invariants and Evidence Boundaries

These are project requirements, **not a blanket implementation or formal-proof
claim**. CERBERUS Cyber remains TRL 2–3. Evidence concerns named fixtures, the
simulated gateway and the bounded temporary-file lab.

## Non-overridable forbidden actions

The global list includes `delete_backups`, `modify_backups`, `disable_recovery`,
`wipe_host`, `retaliate`, `execute_exploit` and `harvest_credentials`.
Guardian denies them before approval processing. **Human approval, confidence
and emergency labels do not override this list.** Existing tokens grant no right
to alter the evaluated policy.

## Requirements and current evidence

| Requirement | Implemented evidence | Not established |
|---|---|---|
| Intelligence never self-authorizes | Proposal/evaluator/gateway split; lab worker lacks keys | Full operational credential/path separation |
| Exact bounded authority | Typed contracts; token binds envelope, policy/assurance, identity, action/target/scope, expiry/idempotency | Production identity lifecycle/key custody |
| Deny forbidden/excessive requests | Policy tests and explicit Guardian scope denial | Universal correctness or completed assurance case |
| Authenticate required evidence/approvals | Ed25519 verifier, configured principals/domains | Observation truth, organizational independence, operational issuer onboarding |
| Bad evidence cannot increase authority | Freshness, invalid-assurance denial, conflict escalation fixtures | Continuous telemetry health and compromise detection |
| Execution cannot expand intent | Exact simulated receipt; fixed marker broker rejects substitutions | Operational full mediation or real containment |
| Reject replay | Shared SQLite plus restarted-gateway test | Distributed/rollback-resistant state or crash-atomic exactly-once effect |
| Link decisions and effects | Snapshot-at-append in-memory hash chain, resource hashes | Durable independently anchored/immutable audit |
| Fail safely without authority/isolation | Invalid-authority refusal; no Landlock fallback; required syscall errno evidence | General runtime fail-safety after trusted OS/broker compromise |
| Reversibility before operational trust | Declared reversibility and policy checks | Tested connector rollback, restoration and recovery |
| Human/governance oversight | Configured approval counts, request binding, policy version/digest, repository review | Full approval UI, publisher signatures or emergency service |

No implemented emergency rule replaces required corroboration. Non-forbidden
actions still require configured evidence, exact scope and authenticated approval.
Policy thresholds are not universal safety thresholds.

## Defensive-only and future readiness

No exploit execution, retaliation, credential harvesting, destructive payloads
or unauthorized scan belongs in a connector. Operational action requires separate
reviewed capabilities, authenticated approvals, rollback and post-action checks.
The file-marker lab does not satisfy operational deployment gates.

[Inventory](CAPABILITY_INVENTORY.md) · [Threat model](THREAT_MODEL.md) ·
[Evaluation gates](EVALUATION_FRAMEWORK.md)
