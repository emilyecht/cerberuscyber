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
| Five-class replay v1 | 135 prelabelled requests / 125 setups, fixed seed and clock; real Guardian and simulated gateway versus two decision-only baselines | Public fixture trust, synthetic target/criticality labels; current old-grant revocation/context gaps fail the safety gate |
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

## Reproduce the five-class synthetic replay

With the repository runtime dependencies already installed, run:

```bash
python benchmarks/replay_v1/run.py
python -m pytest -q tests/test_replay_v1.py
```

The runner writes [machine-readable observations](../results/replay_v1/results.json)
and [per-class tables plus every failed case](../results/replay_v1/report.md).
It uses seed 20261104, 25 setups per class and five three-step widening sequences,
giving 135 labelled requests. The [oracle](../benchmarks/replay_v1/oracle.json)
and [scoring plan](../benchmarks/replay_v1/PLAN.md) were frozen before replay;
input/policy hashes are verified and labels are never rewritten by a run.

Coverage includes valid approvals; forbidden actions; request-borne credential
markers rejected by the canonical schema; changed observation proofs; single,
shared-domain, missing and conflicting evidence; stale telemetry; expired or
revoked authority; incident mismatch; and scope, impact and reversibility changes.
All adversarial mutations retain the original trusted setup's signatures.

Each class and the overall record expose accuracy, false allows, legitimate
requests blocked (deny or escalate), escalation rate/precision/recall, invariant
violations and Kernel refusal fractions. Raw Guardian verdict accuracy is
reported separately from the combined pipeline. Counts use labelled requests,
including sequence steps; zero denominators are N/A. Measurement errors make
affected rates null, not successful defenses. Positive controls must obtain
genuine exact-bound simulated receipts.

Allow-if-recommended and a frozen confidence >= 0.9 gate use the same cases and
labels. They are decision-only controls, not operational security products;
Kernel results are N/A for them. Every baseline failure is retained.

The existing Kernel receives only token/action/target/scope. It cannot compare
an expected incident/envelope/impact/reversibility context or consult live
revocation of an already-issued token. The broader task-level no-old-authority
requirements are scored explicitly, with their limitations frozen before
measurement. Current failures are capability gaps, not evidence of real side
effects or a newly introduced policy regression. Stale observations use the
documented deny expectation and are flagged separately from human-escalation
preferences.

Exit 2 means an invalid measurement; exit 1 means any CERBERUS disagreement or
violation. The unwaived safety test fails on every nonzero CERBERUS invariant
count; deliberately weak baseline failures do not gate CERBERUS. The current
snapshot fails that gate. Do not change labels, omit cases or weaken policy to
turn it green.

No network, real telemetry, operational credential, live model or real action is
used. Isolated in-memory replay caches do not measure SQLite/restart durability.
Volatile token identifiers and audit hashes are validated in memory and omitted
from stable output. Runtime latency is not measured. Structured injection and
changed proofs do not establish detection of arbitrary injected language or
signed false observations. **Synthetic replay is not field validation** and does
not replace the separate native syscall-refusal lab or historical benchmarks.

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
