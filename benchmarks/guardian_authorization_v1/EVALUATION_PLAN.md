# Next authorization assurance evaluation

**Status: planned; not executed. Updated 8 September 2026.** This document applies reviewer criticism to the interpretation and next evaluation of Guardian Authorization Benchmark v1. It introduces no production defenses, new measured results, or changes to the frozen corpus, oracle, runner, reviewer packet, or graphs.

## Current judgment

CERBERUS Cyber has demonstrated a **significant local improvement in a partially hardened authorization boundary**. In the matched selected corpus, unsafe valid authorizations fell from 26/33 to 11/33; the existing-contract subset fell from 15/22 to 0/22 while all 8 eligible controls retained exact signed authority and one matching simulated receipt. Controlled refusal on these exercised cases is useful evidence, but broader adversarial resistance and operational containment remain unproven.

| Additional assurance requirement | Baseline failures | Repaired failures | Interpretation |
|---|---:|---:|---|
| Evidence freshness, F01–F04 | 4/4 (100%) | 4/4 (100%) | Claimed observation times are not constrained by the proposed age/skew rule |
| Approval authenticity, H01–H04 | 4/4 (100%) | 4/4 (100%) | Approver labels and approval purpose lack a verified trust boundary |
| Evidence authenticity, E01–E03 | 3/3 (100%) | 3/3 (100%) | Source labels and claimed observations lack authenticated provenance |

All 11 additional assurance expectations remain unmet. These fractions describe selected cases, not field probabilities. Prioritizing them as likely next probe surfaces is an engineering judgment, not an observation of attacker behavior. Three separate lifecycle probes also produce duplicate simulated actions across fresh instances or a process; they are outside the 33-request denominator.

The authenticity cases exercise raw attacker-controlled envelopes. Eligible controls assume trusted upstream evidence/approvals; the harness does not authenticate those origins. Negative authenticity cases remove that assumption. They do not establish a bypass of an authenticated deployed integration. The attacker is not assumed to control the loaded policy or signing key.

## How the existing cases were generated

The project authored all 59 definitions in [`cases.json`](cases.json), using knowledge of known weaknesses and explicit contract boundaries. Expected rules were fixed before the recorded executions. They are separate from the evaluated implementation, but neither the authorship nor evaluation is independent. No representative sampling frame, discovery-rate estimate, held-out split, or adversarial search process is claimed.

Request cases select a profile and list JSON-path patches, including omitted fields, altered native types, changed actions/scopes, stale timestamps, and claimed identities. [`run.py`](run.py), principally `make_payload`, deterministically expands them into envelopes:

| Profile | Intended response | Evidence / approval setup |
|---|---|---|
| Ransomware | `isolate_endpoint`, one endpoint | Two signals; no human approval |
| Identity | `revoke_sessions`, one identity | Three signals; no human approval |
| Exfiltration | `temporary_egress_hold`, one workload | Two signals; one approval |
| Embedded | `quarantine_workload`, one workload | Five required behaviors; two approvals |

The simulated clock is `2026-09-07T12:00:00Z`. Default evidence is five seconds old, the envelope is one second old, and envelope expiry is 120 seconds ahead. Case patches override relevant values. Targets and IDs are deterministic; UUID5 idempotency values and synthetic SHA-256 nonce/evidence digests make inputs repeatable. A digest here is a fixture identifier, not proof that a sensor observed an event. Each ordinary request starts with a fresh Guardian/signer; ordinary rows do not accumulate state.

Some expectations require facts outside the input. H04 has no case-specific patches and stipulates that the approval was for another action/target. E03 likewise has no case-specific patches and stipulates fabricated observations and origins. A future authenticated fixture must embody those facts in verifiable credentials, signed contents, and trust configuration, rather than treating a descriptive label as verification. The [reviewer packet](../../results/guardian_authorization_v1/reviewer_packet/README.md) retains these assumptions beside each request.

## What has and has not been exercised

| Question | Existing v1 coverage | Remaining limitation |
|---|---|---|
| Deliberate adversarial crafting | Hand-authored action, scope, native-type, omission, timestamp and claimed-identity variants | No independently crafted challenge set; synthetic envelopes do not establish operational realism |
| Timing | Fixed observation timestamps and G05 token submission at clock +121 seconds | No real elapsed-time measurements, scheduler races, clock drift campaign, or freshness recheck during queued execution |
| Replay | G06 reuses a token in one gateway; G07 uses a new gateway; G08 uses an actual fresh Python process | No sustained replay storm, concurrent consumers, or shared-state failure injection |
| Multi-step behavior | G01–G08 start from a valid setup; L01/L02 re-evaluate using the same/new Guardian | Limited ordered lifecycle probes, not full attack chains or long-lived attacker sessions |
| Continuous probing | None | No duration, arrival rate, traffic mix, queue pressure, or availability measurement |
| Adaptive probing | None | No next request chosen from previous observed decisions |
| Independent evaluation | None | Public cases are regression material; no separately authored held-out run |
| Operational effect | Simulated receipts only, with `side_effects: false` | No live detection, containment, damage prevention, rollback, or recovery measurement |

G01–G05 alter action, target, scope, signature, or submission time after a valid setup. L01/L02 test re-evaluation within the same Guardian or a new Guardian, followed by gateway submission. Errors or invalid setup conditions cannot count as defenses. Repeated static batches alone would not answer the continuous or adaptive questions.

## Required engineering gates

These are proposed acceptance criteria for future implementation and evaluation, not guarantees supplied by the current policy. Each negative test must withhold usable authority or prevent the prohibited effect at the relevant boundary; each matched valid control must still succeed. Record rejection, denial, and escalation separately.

### 1. Evidence freshness

- Define which authenticated collection time and trusted clock govern each required observation. A fresh envelope must not refresh stale contents; a signed but stale observation must still fail.
- Adopt or explicitly revise the proposed maximum age of 60 seconds and forward-skew allowance of 5 seconds before execution. For those settings, test exact boundaries and values just inside/outside them, missing/malformed times, mixed fresh/stale evidence, and contradictory times.
- Prevent timestamp edits from restoring acceptance without valid provenance. Specify when delayed execution must revalidate freshness and current authority; test requests that become stale while queued and around clock adjustments.
- Acceptance: zero unsafe authorizations on the declared freshness cases; genuine, sufficiently fresh controls pass. Publish the tested thresholds and clock assumptions.

### 2. Approval authenticity and purpose

- Verify the authenticated principal and authorization role through an explicit trust configuration. Two labels or credentials belonging to the same principal must not satisfy a two-person requirement.
- Bind approval to the exact canonical request, action, target, scope, policy version, and validity period. Specify revocation and reuse semantics before testing.
- Exercise fabricated identities, aliases of one principal, unauthorized roles, altered approval contents, expired/revoked approvals, an approval for another request, and reuse for a different target. Include genuine approvals and valid distinct-principal controls.
- Acceptance: none of the invalid approval cases yields usable authority. A genuine approval for an eligible request works, and duplicate handling of the same request cannot create an additional prohibited effect.

### 3. Evidence authenticity and source independence

- Verify attestations binding the evidence body/digest, source, target, and collection time to configured trusted producers. Verify both the signature and the producer's authority for that observation.
- Define required source independence as a trust/administrative relationship. Different labels, keys, or valid signatures alone do not prove independent observations; the trust model must account for shared origin or common control.
- Exercise missing/tampered attestations, unknown/revoked producers, target substitution, fabricated observations, and duplicate evidence relabeled as different sources. Include correctly attested, permitted-source controls.
- Acceptance: all declared authenticity failures withhold authority while valid controls succeed. Explicitly retain compromised trusted sensors and correlated trusted sources as residual risks unless separately modeled and tested; signatures alone do not prove sensor truth.

### 4. Durable replay and idempotency

- Define atomic shared consumption/idempotency semantics across restarts and replicas, with recovery and retention rules. State loss or expiry must not silently restore already-consumed authority.
- Re-run G07, G08 and L02, then submit concurrent duplicates and inject failures around reservation, action dispatch, completion, and receipt persistence. Test state-store unavailability and ambiguous execution outcomes.
- Acceptance: zero extra prohibited effects within the declared fault model, with explicit reconciliation of unknown outcomes and successful eligible recovery. Do not claim general exactly-once execution from a simulated receipt or a small restart test.

## Next evaluation sequence

Every stage below is **planned, not run**. Freeze an evaluation manifest before each campaign: target commits, policies, trust roots/roles, clocks, fixture/generator hashes, seeds, case/episode counts, duration, query and concurrency budgets, state reset rules, allowed attacker observations, hardware/runtime, expected outcomes, and stop conditions. These are engineering budgets, not statistical power or population guarantees. Record deviations and preserve failed runs.

1. **Authenticated regression baseline.** Keep v1 unchanged as historical evidence. Add a separately versioned suite with genuine positive credentials/attestations and negative counterparts implementing the external facts. Freeze its oracle and run identical inputs against pinned before/after targets. Confirm that refusing everything fails the positive controls.
2. **Generated boundary and combination tests.** Use recorded seeds to mutate times, field types, request bindings, identities and source relationships, including combinations across the three assurance families. Record the generator and selection process; duplicate or correlated variants do not become independent evidence through larger counts.
3. **Stateful timed episodes.** Preserve state within each episode. Sequence valid approval, delay, reuse, altered target, revocation, restart and recovery as appropriate. Log every request and state transition, not only the final outcome. Exercise timing boundaries and concurrent duplicate submissions under the declared fault model.
4. **Continuous mixed-traffic runs.** Predeclare duration, offered load, burst pattern, valid/invalid mix, resource limits, restart schedule and latency/availability thresholds. Track unsafe authority, valid work completed, review queue growth, errors and dropped work throughout. Stopping at the first success or silently discarding overloaded intervals invalidates a clean-run claim.
5. **Feedback-driven adaptive campaigns.** Let a bounded test agent choose its next local request from prior observable decisions, errors, receipts and timing. Record its strategy/version, seed, starting knowledge, observations and query budget. Keep expected answers and hidden verifier state out of the agent's feedback; document white-box source access separately. Capture attempts-to-first-failure and complete episode traces. Repeat with declared starting states and seeds; do not equate repeated attempts with independent trials.
6. **Separately authored held-out challenge.** Have an evaluator author cases without tuning the evaluated implementation to them; freeze the implementation/configuration before disclosure. Document evaluator access, assistance, reused seeds/templates, and any overlap with development cases. Once disclosed, failures become regression cases and require a new holdout for another independent claim.

Use synthetic, isolated local targets for these campaigns. An operational containment claim additionally needs a separately scoped lab integration with independently observed post-action effects and recovery; issuing a token or returning a receipt is insufficient.

## Reporting and graph rules

| Measure | Denominator / required evidence | Graph or interpretation |
|---|---|---|
| Unsafe authority | Unsafe requests issuing a valid, usable token / validly measured unsafe requests, by family | Before/after fractions with exact counts and unchanged configuration |
| Prohibited effect | Episodes with an independently verified prohibited effect / validly measured episodes | Separate simulated and actual effects; never infer containment from a decision label |
| Eligible completion and review burden | Eligible completions / eligible requests; benign escalations / benign requests | Display beside refusal rates so rejecting everything cannot look strong |
| Sustained behavior | Offered/completed/dropped requests, errors, queue depth and p50/p95/p99 latency over declared time windows | Time series at stated load; unmeasured latency stays blank |
| Adaptive resistance within budget | Failure per episode, attempts/time to first failure, and exhausted budgets | Mark no-failure runs as budget-limited observations, not immunity |

Retain decision, token validity and exact binding, gateway acceptance, simulated receipt, and independently verified real effect as separate fields. Include case/episode IDs, expected rule, credential/evidence provenance, monotonic and wall-clock timestamps, state transitions, reset history, resource conditions, exceptions and hashes sufficient to replay the run. Protect real secrets if later integrations introduce them; current fixtures use test material.

Do not pool unrelated categories into one security score. Do not report malformed instrumentation, crashes, timeouts, unmet preconditions or missing observations as successful defenses. An incomplete run cannot satisfy a clean-run gate; expose its errors and missing work beside any valid subset. Do not assign IID confidence intervals to correlated hand-selected, generated or adaptive probes. Plot progress only between actually executed, comparable evaluations; planned gates are not additional measured points.

## Exit evidence for the next review

- All declared freshness/authenticity cases withhold unsafe authority, and their genuine positive controls complete correctly. The resulting claim remains limited to the tested cases and trust model.
- Replay/recovery episodes produce no extra prohibited effects under the declared concurrency and fault budget; ambiguous outcomes are reconciled and reported.
- Continuous runs meet predeclared utility, review-capacity and availability thresholds without hidden errors or omitted intervals. Adaptive and held-out results include all failures and budgets, even when they prevent a release claim.
- Publish a versioned manifest, raw requests and observations, episode traces, error records, reproduction commands, and separate measured/unmeasured claims. Reproduction verifies observations; it does not itself establish security success.

## Source evidence

- [Frozen v1 definitions and expected rules](cases.json), [generator and runner](run.py), and [measurement method](README.md).
- [Matched baseline/repaired results and graphs](../../results/guardian_authorization_v1/README.md), [baseline JSON](../../results/guardian_authorization_v1/baseline.json), and [repaired JSON](../../results/guardian_authorization_v1/repaired.json).
- [Full 41-request reviewer packet](../../results/guardian_authorization_v1/reviewer_packet/README.md) and [82-observation replay verification](../../results/guardian_authorization_v1/reviewer-verification.json).
- Targets remain baseline `ac22a922fae1475cbfa9921534222df96cbdf2b5` and repair `651bd4a465661c7c54d58d3c60c279338b727c4f`. This plan does not change either target.
