# CERBERUS Cyber Evaluation Framework

**TRL 2–3 research prototype.** These are evaluation requirements and bounded
prototype evidence, not a completed assurance case. Separate current authorization
tests, the opt-in local-effect lab and proposed operational studies.
No production readiness, formal verification, independent validation, operational
superiority or real-world containment/recovery is claimed.

## Current instruments

| Instrument | Boundary | Evidence limits |
|---|---|---|
| Guardian v1 historical benchmark | Original frozen 59-case contract/oracle | Preserve original results; not a security trend with later contracts |
| Combined release contract | Exact action, policy, assurance, freshness and lifecycle fixtures | Historical `59c6a29`: 0/11 unsafe authorizations, 8/8 eligible simulated responses, three lifecycle episodes |
| Local enforcement lab | Fixed broker, kernel-denied bypasses, actual temporary marker | Scripted agent, fabricated trust, Linux Landlock; no network hold |
| Unit/schema/adversarial tests | Named properties and regressions | Not formal proof, exhaustive coverage or independent review |

See [inventory](CAPABILITY_INVENTORY.md), [historical record](../results/release_candidate/main-after-pr11.md)
and [lab acceptance criteria](LOCAL_ENFORCEMENT_DEMO.md). New runs identify their own
code commit; historical source hashes, denominators and non-claims are not rewritten.

## Authorization and effect metrics

| Metric | Definition |
|---|---|
| Unsafe authorization | Forbidden, unsupported, over-scoped or insufficiently authorized requests receiving authority; report numerator and selected denominator |
| Correct verdict | Expected **approve, escalate, deny**; no implemented `constrain` verdict |
| Determinism | Same validated inputs, policy, verifier configuration, clock and authority state; token bytes/audit timestamps need not match |
| Exact-scope compliance | Original action/target/scope preserved; excessive scope refused, not silently reduced |
| Human-gate compliance | Request-bound approvals verified against configured principals, not labels alone |
| Replay rejection | Same shared SQLite database/namespace; no exactly-once side-effect guarantee |
| Unauthorized effects | Independent before/after resource comparison; refusal or receipt alone is insufficient |
| Positive-control utility | Eligible request produces expected simulated receipt or actual bounded marker; permanently disabled execution cannot pass |
| Audit reconstruction | Request/policy/assurance/decision/outcome linkage; current hash chain is not durable independent anchoring |

Required cases include forbidden action despite approvals; incomplete, forged or
stale evidence/approvals; policy mismatch; scope widening; absent/invalid/expired
authority; action/target/scope substitution; replay; contradictory sources; and
benign controls. A narrower proposal requires a fresh submission. Approval cannot
override globally forbidden actions; no emergency exception is implemented.

The Linux lab additionally requires confinement setup, EACCES/EPERM evidence for
direct write/truncate/unlink/symlink-write/subprocess paths and unchanged hashes.
Unsupported isolation exits nonzero, never a simulated pass.

## Proposed metrics, not current performance

Live detection time, evidence precision, ATT&CK mapping, field false-containment,
mission latency, real blast radius, actual rollback/restoration and analyst
usability require representative studies and operational/lab connectors.
Reversibility metadata is not tested rollback. A temporary OPEN-to-HELD marker
is not network containment.

A proposed matched comparison holds telemetry, requests, baseline, permissions
and scoring fixed. Pre-register thresholds and partitions; report benign
disruption, policy effort, latency, errors and negative results. Budget, range
size, timeline and named model access remain applicant proposals until the
active official solicitation is verified.

## Readiness gates (requirements, not certification)

1. **Research simulator:** typed contracts, explicit policy, fixtures and
   side-effect-free default gateway. Implemented within prototype assumptions.
2. **Bounded file-effect lab:** kernel isolation, permission-denial evidence,
   resource hashes, real positive control and replay. Implemented for that lab only.
3. **Read-only operational pilot:** authenticated connectors, health/provenance,
   representative benign data and independent review. Proposed.
4. **Human-approved containment/recovery lab:** real capability-scoped connector,
   tested rollback, revocation, crash reconciliation and external audit. Proposed;
   the marker lab does not satisfy it.
5. **Bounded automation:** independently assessed controls and measured deployment
   behavior with post-action verification and policy lifecycle assurance. Not reached.
