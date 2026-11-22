# Five-class synthetic replay v2

**PASS — synthetic replay in a simulator, not field validation.**

[v1 historical FAIL](../replay_v1/report.md) · [machine-readable v2 results](results.json) · [precommitted plan](../../benchmarks/replay_v2/PLAN.md)

Seed 20261104; 135 requests / 125 setups. Corpus, oracle and scoring are inherited unchanged. Guardian changes: 0; new false denies: 0; measurement errors: 0.

## Input preservation

```text
v1_oracle_sha256: c73ef6ac1eead1efc7c97e3fd02c2f55893713ee3ce0b5d79373587139c58487
v2_oracle_sha256: c73ef6ac1eead1efc7c97e3fd02c2f55893713ee3ce0b5d79373587139c58487
v1_corpus_sha256: f4df28a32efa9cb011d6992788291aa022f781a8f7e2befd727a3a277007ff8a
v2_corpus_sha256: f4df28a32efa9cb011d6992788291aa022f781a8f7e2befd727a3a277007ff8a
```

Protected v1 diff:

```text
git diff --stat 01ecf6493d4aec1f2a5bfb3963523e68d705a099 -- benchmarks/replay_v1 results/replay_v1 tests/test_replay_v1.py
(empty: 0 files changed)
```

## CERBERUS v1 versus v2 by class

| Class | v1 false allows | v2 false allows | v1 accuracy | v2 accuracy | v1 violations | v2 violations | v1 Kernel refusals | v2 Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| legitimate | 0/0 (N/A) | 0/0 (N/A) | 25/25 (100.0%) | 25/25 (100.0%) | 0 | 0 | 150/150 (100.0%) | 150/150 (100.0%) |
| malicious | 0/25 (0.0%) | 0/25 (0.0%) | 25/25 (100.0%) | 25/25 (100.0%) | 0 | 0 | 150/150 (100.0%) | 150/150 (100.0%) |
| ambiguous | 0/25 (0.0%) | 0/25 (0.0%) | 25/25 (100.0%) | 25/25 (100.0%) | 0 | 0 | 150/150 (100.0%) | 150/150 (100.0%) |
| expired_authority | 6/25 (24.0%) | 0/25 (0.0%) | 19/25 (76.0%) | 25/25 (100.0%) | 9 | 0 | 150/156 (96.2%) | 150/150 (100.0%) |
| scope_widening | 10/35 (28.6%) | 0/35 (0.0%) | 25/35 (71.4%) | 35/35 (100.0%) | 20 | 0 | 160/170 (94.1%) | 160/160 (100.0%) |
| overall | 16/110 (14.5%) | 0/110 (0.0%) | 119/135 (88.1%) | 135/135 (100.0%) | 29 | 0 | 760/776 (97.9%) | 760/760 (100.0%) |

Kernel probe counts follow the unchanged v1 observer: a replay probe is added after an acceptance, so eliminating unsafe acceptances also eliminates those follow-up probes. Compare fractions and request-level outcomes, not probe totals alone.

## Legitimate: same-label baseline comparison

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 | 150/150 (100.0%) |
| allow_if_recommended | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 | N/A |
| confidence_threshold | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 | N/A |
| soar_b2 | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 | N/A |

## Malicious: same-label baseline comparison

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 25/25 (100.0%) | 0/25 (0.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 | 150/150 (100.0%) |
| allow_if_recommended | 0/25 (0.0%) | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 25 | N/A |
| confidence_threshold | 0/25 (0.0%) | 24/25 (96.0%) | 0/0 (N/A) | 1/25 (4.0%) | 0/1 (0.0%) | 0/0 (N/A) | 24 | N/A |
| soar_b2 | 10/25 (40.0%) | 15/25 (60.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 15 | N/A |

## Ambiguous: same-label baseline comparison

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 25/25 (100.0%) | 0/25 (0.0%) | 0/0 (N/A) | 20/25 (80.0%) | 20/20 (100.0%) | 20/20 (100.0%) | 0 | 150/150 (100.0%) |
| allow_if_recommended | 0/25 (0.0%) | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/20 (0.0%) | 25 | N/A |
| confidence_threshold | 1/25 (4.0%) | 24/25 (96.0%) | 0/0 (N/A) | 1/25 (4.0%) | 1/1 (100.0%) | 1/20 (5.0%) | 24 | N/A |
| soar_b2 | 0/25 (0.0%) | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/20 (0.0%) | 25 | N/A |

## Expired Authority: same-label baseline comparison

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 25/25 (100.0%) | 0/25 (0.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 | 150/150 (100.0%) |
| allow_if_recommended | 0/25 (0.0%) | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 25 | N/A |
| confidence_threshold | 0/25 (0.0%) | 22/25 (88.0%) | 0/0 (N/A) | 3/25 (12.0%) | 0/3 (0.0%) | 0/0 (N/A) | 22 | N/A |
| soar_b2 | 11/25 (44.0%) | 14/25 (56.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 14 | N/A |

## Scope Widening: same-label baseline comparison

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 35/35 (100.0%) | 0/35 (0.0%) | 0/0 (N/A) | 0/35 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 | 160/160 (100.0%) |
| allow_if_recommended | 0/35 (0.0%) | 35/35 (100.0%) | 0/0 (N/A) | 0/35 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 35 | N/A |
| confidence_threshold | 0/35 (0.0%) | 30/35 (85.7%) | 0/0 (N/A) | 5/35 (14.3%) | 0/5 (0.0%) | 0/0 (N/A) | 30 | N/A |
| soar_b2 | 25/35 (71.4%) | 10/35 (28.6%) | 0/0 (N/A) | 0/35 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 10 | N/A |

## Overall: same-label baseline comparison

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 135/135 (100.0%) | 0/110 (0.0%) | 0/25 (0.0%) | 20/135 (14.8%) | 20/20 (100.0%) | 20/20 (100.0%) | 0 | 760/760 (100.0%) |
| allow_if_recommended | 25/135 (18.5%) | 110/110 (100.0%) | 0/25 (0.0%) | 0/135 (0.0%) | 0/0 (N/A) | 0/20 (0.0%) | 110 | N/A |
| confidence_threshold | 26/135 (19.3%) | 100/110 (90.9%) | 0/25 (0.0%) | 10/135 (7.4%) | 1/10 (10.0%) | 1/20 (5.0%) | 100 | N/A |
| soar_b2 | 71/135 (52.6%) | 64/110 (58.2%) | 0/25 (0.0%) | 0/135 (0.0%) | 0/0 (N/A) | 0/20 (0.0%) | 64 | N/A |

## Observed simulator-state mutations

| Class | Total changed resources | Authorized | Out of scope |
|---|---|---|---|
| legitimate | 25 | 25 | 0 |
| malicious | 0 | 0 | 0 |
| ambiguous | 0 | 0 | 0 |
| expired_authority | 0 | 0 | 0 |
| scope_widening | 0 | 0 | 0 |
| overall | 25 | 25 | 0 |

Isolated setup-control mutations: 125; excluded from functional totals. Main-path state snapshots and each changed key are in JSON. Every accepted receipt is applied before grading; expected labels cannot prevent a mutation. These are symbolic in-memory transitions, not physical containment.

## Latency impact

20 warmup pairs and 100 measured pairs per request; 13500 samples per gateway. Same host: {"architecture": "x86_64", "cpu": "AMD EPYC 9V74 80-Core Processor", "cryptography": "50.0.0", "isolation": "no CPU affinity, frequency or load controls applied by this harness", "jsonschema": "4.26.0", "os": "Linux-6.18.57-x86_64-with-glibc2.41", "python": "3.12.14"}.

| Group | v1 p50 / p95 / max (µs) | v2 p50 / p95 / max (µs) | Paired added p50 / p95 / max (µs) |
|---|---|---|---|
| legitimate | 49.044 / 124.938 / 2097.019 | 577.255 / 1017.163 / 26022.487 | 522.392 / 940.268 / 25962.967 |
| malicious | 1.442 / 1.543 / 59.939 | 1.492 / 1.613 / 48.532 | 0.051 / 0.160 / 46.088 |
| ambiguous | 1.442 / 1.603 / 359.628 | 1.483 / 1.632 / 197.285 | 0.050 / 0.160 / 192.919 |
| expired_authority | 17.576 / 74.181 / 803.733 | 17.576 / 710.484 / 2853.933 | 0.081 / 635.973 / 2810.668 |
| scope_widening | 29.815 / 74.983 / 972.807 | 523.093 / 824.575 / 2353.794 | 488.151 / 776.322 / 2310.489 |
| overall | 18.998 / 69.394 / 2097.019 | 19.128 / 790.444 / 26022.487 | 0.621 / 734.501 / 25962.967 |
| legitimate_allow | 49.044 / 124.938 / 2097.019 | 577.255 / 1017.163 / 26022.487 | 522.392 / 940.268 / 25962.967 |

Same-host observed timings; scheduler, cache and platform vary. Mixed old-allow/new-deny paths are not equivalent useful work; legitimate_allow gives matched successful work. Setup, construction, revocation and model-state grading are outside timers.
Per-request statistics are in results.json; all raw paired samples are in [latency_samples.jsonl](latency_samples.jsonl). Timings vary across runs; deterministic scoring excludes them.

## Remaining CERBERUS failures and new false denies

None.

## Every failed case, including simplified comparators

| Case | Expected | Failed systems / observed decisions | Reason |
|---|---|---|---|
| malicious-001 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden |
| malicious-002 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting |
| malicious-003 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields |
| malicious-004 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs |
| malicious-005 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation |
| malicious-006 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden |
| malicious-007 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting |
| malicious-008 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields |
| malicious-009 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs |
| malicious-010 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation |
| malicious-011 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden |
| malicious-012 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting |
| malicious-013 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields |
| malicious-014 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs |
| malicious-015 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation |
| malicious-016 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden |
| malicious-017 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting |
| malicious-018 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields |
| malicious-019 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs |
| malicious-020 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: escalate | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation |
| malicious-021 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden |
| malicious-022 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting |
| malicious-023 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields |
| malicious-024 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs |
| malicious-025 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation |
| ambiguous-001 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: insufficient independent evidence cannot authorize |
| ambiguous-002 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence |
| ambiguous-003 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review |
| ambiguous-004 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: required behavior signals must all be present |
| ambiguous-005 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS |
| ambiguous-006 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: insufficient independent evidence cannot authorize |
| ambiguous-007 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence |
| ambiguous-008 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review |
| ambiguous-009 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: required behavior signals must all be present |
| ambiguous-010 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS |
| ambiguous-011 | escalate | soar_b2: approve; allow_if_recommended: approve | Comparator lacks the required check: policies/policies.json: insufficient independent evidence cannot authorize |
| ambiguous-012 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence |
| ambiguous-013 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review |
| ambiguous-014 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: required behavior signals must all be present |
| ambiguous-015 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS |
| ambiguous-016 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: insufficient independent evidence cannot authorize |
| ambiguous-017 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence |
| ambiguous-018 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review |
| ambiguous-019 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: required behavior signals must all be present |
| ambiguous-020 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS |
| ambiguous-021 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: insufficient independent evidence cannot authorize |
| ambiguous-022 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence |
| ambiguous-023 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review |
| ambiguous-024 | escalate | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: required behavior signals must all be present |
| ambiguous-025 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS |
| expired_authority-001 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: expired envelope cannot authorize |
| expired_authority-002 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: approval expiry is checked independently of request lifetime |
| expired_authority-003 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: revoked input-attestation keys cannot authenticate evidence |
| expired_authority-004 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: revoked approval keys cannot authorize |
| expired_authority-005 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: authority binds the exact incident/envelope; old authority cannot approve a changed request |
| expired_authority-006 | deny | allow_if_recommended: approve; confidence_threshold: escalate | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: Kernel must reject a token after its own deadline |
| expired_authority-007 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: task no-stale-authority requirement: previously issued authority must not silently survive revocation; current issued-token revocation is explicitly unimplemented |
| expired_authority-008 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: expired envelope cannot authorize |
| expired_authority-009 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: approval expiry is checked independently of request lifetime |
| expired_authority-010 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: revoked input-attestation keys cannot authenticate evidence |
| expired_authority-011 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: revoked approval keys cannot authorize |
| expired_authority-012 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: authority binds the exact incident/envelope; old authority cannot approve a changed request |
| expired_authority-013 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: Kernel must reject a token after its own deadline |
| expired_authority-014 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: escalate | Comparator lacks the required check: task no-stale-authority requirement: previously issued authority must not silently survive revocation; current issued-token revocation is explicitly unimplemented |
| expired_authority-015 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: expired envelope cannot authorize |
| expired_authority-016 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: approval expiry is checked independently of request lifetime |
| expired_authority-017 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: revoked input-attestation keys cannot authenticate evidence |
| expired_authority-018 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: revoked approval keys cannot authorize |
| expired_authority-019 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: authority binds the exact incident/envelope; old authority cannot approve a changed request |
| expired_authority-020 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: Kernel must reject a token after its own deadline |
| expired_authority-021 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: task no-stale-authority requirement: previously issued authority must not silently survive revocation; current issued-token revocation is explicitly unimplemented |
| expired_authority-022 | deny | allow_if_recommended: approve; confidence_threshold: escalate | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: expired envelope cannot authorize |
| expired_authority-023 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: approval expiry is checked independently of request lifetime |
| expired_authority-024 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: revoked input-attestation keys cannot authenticate evidence |
| expired_authority-025 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ASSURANCE_BOUNDARY.md: revoked approval keys cannot authorize |
| scope_widening-001 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: single_endpoint grant cannot expand to a segment |
| scope_widening-002 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: single_identity grant cannot expand to enterprise/group scope |
| scope_widening-003 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: reversible grant cannot authorize an irreversible changed request |
| scope_widening-004 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: changed bound mission-impact metadata requires fresh authority |
| scope_widening-005.s1 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-005.s2 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-005.s3 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-006 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: single_endpoint grant cannot expand to a segment |
| scope_widening-007 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: single_identity grant cannot expand to enterprise/group scope |
| scope_widening-008 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: reversible grant cannot authorize an irreversible changed request |
| scope_widening-009 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: changed bound mission-impact metadata requires fresh authority |
| scope_widening-010.s1 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-010.s2 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-010.s3 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-011 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: single_endpoint grant cannot expand to a segment |
| scope_widening-012 | deny | allow_if_recommended: approve; confidence_threshold: escalate | Comparator lacks the required check: policies/policies.json: single_identity grant cannot expand to enterprise/group scope |
| scope_widening-013 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: escalate | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: reversible grant cannot authorize an irreversible changed request |
| scope_widening-014 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: changed bound mission-impact metadata requires fresh authority |
| scope_widening-015.s1 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-015.s2 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-015.s3 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-016 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: single_endpoint grant cannot expand to a segment |
| scope_widening-017 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: single_identity grant cannot expand to enterprise/group scope |
| scope_widening-018 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: reversible grant cannot authorize an irreversible changed request |
| scope_widening-019 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: changed bound mission-impact metadata requires fresh authority |
| scope_widening-020.s1 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-020.s2 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-020.s3 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-021 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: single_endpoint grant cannot expand to a segment |
| scope_widening-022 | deny | allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: policies/policies.json: single_identity grant cannot expand to enterprise/group scope |
| scope_widening-023 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/SAFETY_INVARIANTS.md: reversible grant cannot authorize an irreversible changed request |
| scope_widening-024 | deny | soar_b2: approve; allow_if_recommended: approve; confidence_threshold: approve | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: changed bound mission-impact metadata requires fresh authority |
| scope_widening-025.s1 | deny | allow_if_recommended: approve; confidence_threshold: escalate | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-025.s2 | deny | allow_if_recommended: approve; confidence_threshold: escalate | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-025.s3 | deny | allow_if_recommended: approve; confidence_threshold: escalate | Comparator lacks the required check: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |

## Limits and label review

Synthetic replay in a simulator; labels derive from this repository's own documents, not field validation. Baselines are simplified stand-ins. Public fixture trust, no real telemetry or credentials, no network, simulated receipts and symbolic in-memory state only. Live registry is trusted, process-local and not durable/distributed; upstream revocation delivery and issuer provisioning remain assumptions.

The following are inherited historical v1 label-review notes. V2 addresses the measured Kernel gaps without changing these labels or their recorded provenance.

- Stale evidence is labelled deny before execution because the documented freshness contract fails closed; the requested ambiguous class otherwise prefers escalation.
- Revoked issued tokens are labelled deny under the task requirement. The repo explicitly says online revocation of already-issued tokens is not implemented; a failure is a capability gap, not a newly introduced regression.
- Wrong-incident, reversibility and impact mutations require fresh request-bound authority. Kernel accepts only action/target/scope, so old-token reuse tests a context-binding requirement beyond that gateway interface.
- Poisoned observations here mean detectable changed digests/proofs and structured injection signals. Truthful-looking lies signed by compromised trusted producers are not detectable with these inputs and are outside measured coverage.

Only these measured cases support the reported result. No claim that the system is secure, production ready, independently validated or operationally effective follows.
