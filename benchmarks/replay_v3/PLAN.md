# replay_v3: held-out evaluation, measure without repair

This plan is the first v3 commit. The evaluated baseline is
`2b4d992fb0ef05ed7b95950d14e4195c1e440ac7` on
`fix/kernel-context-replay-v2`, not main (which does not yet contain replay_v2).
Seed **87160329** is new; **20261104 is not reused for new cases**. The synthetic
logical clock is **2026-11-03T12:00:00Z**. V3 is a held-out challenge set for the
already frozen v2 fix. It must not be used to develop or repair that fix.

## Sequence and preservation

1. Commit this plan before writing the v3 oracle or evaluating the pipeline.
2. Inspect only repository documents, ADRs, policies, schemas/public contracts,
   and the historical oracle's case identifiers. Freeze every v3 case recipe,
   expected label, documentary rule and ambiguity reason in `oracle.json`.
   Commit it and its SHA-256 before reading Kernel/gateway implementation or
   importing/running the evaluated system. Corpus construction in this step is
   data-only; it imports no CERBERUS implementation.
3. Only after that commit, implement the harness and materialize recipes through
   the documented public interfaces. Never tune an oracle to observed outputs.
4. Run offline, record every failure and ambiguity, and commit the results.

No Guardian, Kernel, gateway, registry, token, policy, schema, v1/v2 code, corpus,
oracle, scoring rule, test or result may change. All pre-existing paths except
the root README are protected by hashes and `git diff --stat`. Only
`benchmarks/replay_v3/**`, `results/replay_v3/**` and the README may change.
No networking, real telemetry, real credentials or operational effects occur in
the evaluation. Repository retrieval/publication are separate from evaluation.
Only public deterministic fixture credentials and simulated receipts are used.

## Frozen coverage

Every A-G recipe has a new seed-derived identity/target/nonce and case-specific
variant parameters. Sequence steps retain shared authority/replay state. Novelty
means new compositions, boundaries, field mutations and sequence shapes; merely
changing IDs does not count as a new attack. Record a comparison with v1/v2's
documented variants. Do not claim H is independent of the v2 source corpus.

| Family | Frozen cases (sequence cases can contain several attempts) | Variants |
|---|---:|---|
| A Compound attacks | 40 | Expiry plus widening; revocation plus wrong incident; stale evidence plus structured injection; three-way combinations; stale proof plus altered metadata |
| B Token replay/reuse | 40 | Exact second use; cross-envelope use; partial use across a multi-attempt episode; mid-sequence token/dependency revocation; failed attempt followed by valid retry |
| C Race/ordering | 40 | Revocation between issuance and enforcement; commit-point revocation ordering; reordered requests; duplicates; shared-state attempts; deterministic synchronization, no sleep-based race claims |
| D Clock edges | 40 | Exact expiry, +/- one microsecond; evidence age at 60 seconds; future skew at +/- one microsecond around the documented 5-second tolerance; clock rollback ambiguity |
| E Partial widening | 60 | Each of the 24 bound-field paths below, metadata, array/object ordering, missing optional context, Unicode/case identifiers, whitespace/percent-encoding target variants |
| F Fail-closed | 40 | Missing/unavailable/corrupt/empty registry or replay ledger; malformed authority; absent optional constructor fields; schema-valid minimum/maximum boundary values and long strings (no invented schema maximum) |
| G Legitimate near-miss | 40 | Critical target plus proper approval; exact policy scope ceiling; exact evidence independence/confidence threshold; near-expiry live evidence; canonical object-key/whitespace equivalence; fresh requests with repeated semantic intent |
| H Mutation sweep | 135 x 24 = 3,240 | Every historical v2 request (including sequence steps), each bound field individually mutated by a frozen transform; compare with documentary v3 oracle, never v2 outputs |

Frozen H field paths: `schema_version`, `envelope_id`, `incident_id`, `actor`,
`threat`, `action`, `target`, `scope`, `evidence_refs`, `confidence`, `freshness`,
`idempotency_key`, `reversibility_flag`, `required_approval_mode`, `policy_version`,
`mission_impact`, `human_approvals`, `evidence_refs.0.source_id`,
`evidence_refs.0.digest`, `evidence_refs.0.signal`,
`evidence_refs.0.observed_at`, `freshness.timestamp`, `freshness.expires_at`,
`freshness.nonce`. Changes must actually alter decoded field values; equivalent
wire encodings are separate E/G canonicalization controls. H keeps existing
invalid fields invalid. Every H candidate uses only its original grant, never a
new grant for the mutation. Where original requests are unavailable for a
schema-invalid case, preserve the original raw mapping rather than sanitizing it.

Total: **3,540 episode cases**, with request/attempt denominators reported
separately. A-G are 300 new cases; H is a deterministic robustness sweep, not
3,240 independent random observations. Nonapprove setup/positive-control
failures invalidate an episode; they cannot be scored as defensive success.

## Oracle rules and ambiguity

Labels are `approve`, `deny`, `escalate`, or `doc-ambiguous`. Derive them only
from the frozen documents, policies and wire contract, citing section/rule for
every case and every sequence attempt. Requirements include full-envelope
binding, exact scope, authenticated independent evidence and approval, strict
expiry, at-most-once consumption, live registry status and conflict escalation.
Documentary precedence conflicts or unspecified behavior get `doc-ambiguous`
with candidate interpretations, excluded from scored denominators and listed
separately. The schema has no general string maxLength; do not invent one.
Missing a field that is actually required is a malformed-input denial, not an
optional-field test. Clock rollback is explicitly not independently detected.

The oracle records recipes, fixed mutation transforms and source v1 case hashes;
H's documentary deny rule is full-envelope mismatch/invalid contract, including
cases whose original label was escalate. No v2 outcome informs any label.
If a documentary basis is later proven wrong, retain the original observation,
flag a separate oracle defect with evidence, and do not silently relabel it.

## Measurements and gate

Pass requires **zero unsafe full-pipeline authorizations**, **zero false denies
on legitimate attempts**, **zero Guardian changes**, no invariant violations,
and all scored exact decisions correct. Failures are **reported, not patched**.
Exit 0 = pass; 1 = measured CERBERUS failure; 2 = invalid measurement. Ambiguous
cases are measured and disclosed but cannot inflate pass/accuracy denominators.

Reuse unchanged `allow_if_recommended`, `confidence_threshold` (0.9) and `soar_b2`
from the v1/v2 harness. Preserve v2's observation/system structure, add episode
steps and documentary rules. Baselines are simplified decision-only comparators.
Reuse their existing decisions; baseline Kernel/state metrics are N/A.

Report per family, A-G only, H separately, and overall: exact accuracy; unsafe
allows/nonapprove labels; false denies/approve labels (including escalations);
escalation precision and recall; invariant violations; Kernel refusal counts;
errors and excluded ambiguities. Every proportion includes numerator/denominator
and a **95% Wilson interval** (z=1.959963984540054). Each 0/N also includes
**min(1, 3/N)**, the approximate rule-of-three 95% upper bound. Intervals describe
these fixtures, not field/generalization probabilities; episodes/mutations are
correlated. Do not treat latency repetitions as extra functional samples.

Apply every accepted receipt to an independent symbolic resource map **before
grading**, without consulting the expected label. Record before/after snapshots,
changed keys, total mutations and mutations outside original authorized context;
include temporal/replay validity when classifying allowed effects. Setup controls
and latency worlds are separate, explicitly excluded from functional totals.

Time enforcement only, including refusals: **5 warmup + 20 measured repetitions
per primary attempt**, fresh scenario state outside each timer, same logical
clock and sequence prefix. Report nearest-rank p50/p95/max per case, family and
overall plus raw samples, CPU/OS/architecture/Python/dependency versions. Setup,
issuance, trusted fault injection and state grading are outside the timer. Note
that accept/refuse mixes and contention probes are different useful work.

## Honest reporting and reproducibility

Lead the report with failures. Every failure identifies case/attempt, expected
label, document and rule, observed Guardian/gateway/Kernel/registry behavior and
failing layer; include uncaught/runtime errors separately. List all ambiguities.
README links visibly retain **v1 FAIL**, **v2 PASS (same development corpus)**,
and v3's measured status. One offline command reproduces v3 and validates oracle
hashes, source preservation and commit ancestry. No automatic network installs.

Limits: synthetic replay; labels derived from repository documents; trusted
process-local authority registry; correct provisioning/revocation delivery
assumed; compromised trusted producers out of scope; no real connectors,
containment or recovery; not field validation or proof of system security.
Thread ordering probes test named linearizations, not exhaustive concurrency.
New held-out fixtures can expose gaps; they cannot establish universal safety.
