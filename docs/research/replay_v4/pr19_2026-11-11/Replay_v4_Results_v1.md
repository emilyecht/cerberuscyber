# Replay v4 Results, version 1

**Frozen scoring gate: PASS (runner exit 0).** 1005 episodes; 1100 primary attempts; 1,078 planned scored; 22 documentary ambiguities.

Measured implementation: PR #19 / `6fe417400ff4844d7647dddd9435288c3485ffc0`. Runner local commit `00ba8f610e862b5ea30e55da1bb0cd52f34d980e`; runner SHA-256 `1bb4b9250032f51b7d4c558e770cfd24dc4a63e3d31960342b6d011efa760521`. Published tree equivalents and exact restorable local commit objects are recorded separately.

Start UTC: `2026-11-11T23:53:12.581001+00:00`. Finish UTC: `2026-11-12T00:07:55.492696+00:00`. Fixture seed: `604279153`; fixed logical clock: `2027-02-16T04:30:00Z`. Both real dates are 11 November 2026 in America/Chicago.

## Primary outcomes and comparison coverage

| System | Valid scored / planned | False allows | False denies | Correct decisions | Measurement errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| allow_if_recommended | 1078/1078 | 878/878 | 0/200 | 200 | 0 |
| cerberus | 1078/1078 | 0/878 | 0/200 | 1078 | 0 |
| confidence_0.9 | 1078/1078 | 878/878 | 1/200 | 199 | 0 |
| soar_b2 | 1078/1078 | 780/878 | 0/200 | 298 | 0 |

A false allow is an allow on a frozen deny/escalate attempt; a false deny is any non-allow on a legitimate allow. Exact decision correctness also distinguishes deny from escalate. The five expected escalations remain separately scored.

The baseline functions are unchanged v1 allow-if-recommended / confidence 0.9 and v2 SOAR B2. All three decisions are independently recalculated by verify_results.py. Baselines have no measured durable claims, receipts or effect pipeline; their unmeasured effect/invariant fields are null, not zero. Comparator decisions do not observe CERBERUS storage faults or replay state. The baseline grant is a genuine original-template control. These are bounded decision comparators, not operational competitors.

| Family / subgroup | Attempts | Ambiguous | Valid scored | False allows | False denies | Scored invariant labels |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| S | 55 | 2 | 53 | 0/43 | 0/10 | 0 |
| T | 115 | 10 | 105 | 0/85 | 0/20 | 0 |
| U | 160 | 5 | 155 | 0/125 | 0/30 | 0 |
| U/clock_edges | 30 | 5 | 25 | 0/15 | 0/10 | 0 |
| U/compound | 25 | 0 | 25 | 0/25 | 0/0 | 0 |
| U/partial_widening | 25 | 0 | 25 | 0/25 | 0/0 | 0 |
| U/race_ordering | 30 | 0 | 30 | 0/20 | 0/10 | 0 |
| U/token_replay | 50 | 0 | 50 | 0/40 | 0/10 | 0 |
| V | 45 | 5 | 40 | 0/0 | 0/40 | 0 |
| W | 725 | 0 | 725 | 0/625 | 0/100 | 0 |

Each subgroup's full baseline counts, Wilson 95% intervals and 0/N bounds are in results.json.gz. W has **25 correlated parent clusters**, 625 nonidentity mutations and 100 identity controls. Its 725 attempts are not independent draws. Overall sums are descriptive arithmetic, not generalization or field-security probabilities.

- Overall descriptive false_allows: 0/878; Wilson 95% `[0, 0.004356178519698306]`; zero-count rule-of-three upper bound `0.003416856492027335`.
- Overall descriptive false_denies: 0/200; Wilson 95% `[1.734723475976807e-18, 0.018845326377266575]`; zero-count rule-of-three upper bound `0.015`.

## Every scored gate failure and invalid measurement

No scored primary correctness/safety failures were observed in this run. This does not erase the separately listed ambiguous history failures or security-review findings.
Invalid primary measurements: **0**. Repeated-outcome mismatches: **0**. No case was silently discarded.

Instrument v1's full run is preserved under results/replay_v4/pr19_2026-11-11 as **INVALID_MEASUREMENT** (exit 2). S-023.s1 and S-024.s1 were invalid because the setup probe incorrectly required separate write denial for frozen write-only mode bits. Corrected O_RDWR confirmation changes no file mode, oracle, expected label, baseline or implementation. V1 retained 1,100 observations, 1,076 valid scored attempts, two invalid attempts and all 22 ambiguities. Its valid observations had 0/876 false allows and 0/200 false denies; these are not substituted for a complete passing gate. Its runner/source hashes and every timing sample remain intact.

## All 22 documentary ambiguities and observed effects

| Attempt | Observed decision | Symbolic writes | Observed invariant labels |
| --- | --- | ---: | --- |
| S-031.s1 | deny | 0 | none |
| S-032.s1 | deny | 0 | none |
| T-041.s2 | allow | 1 | none |
| T-042.s2 | allow | 1 | none |
| T-043.s2 | allow | 1 | none |
| T-044.s2 | allow | 1 | none |
| T-045.s2 | allow | 1 | none |
| T-046.s2 | allow | 1 | REPLAY_HISTORY_VIOLATION, OUT_OF_SCOPE_SIMULATOR_MUTATION |
| T-047.s2 | allow | 1 | REPLAY_HISTORY_VIOLATION, OUT_OF_SCOPE_SIMULATOR_MUTATION |
| T-048.s2 | allow | 1 | REPLAY_HISTORY_VIOLATION, OUT_OF_SCOPE_SIMULATOR_MUTATION |
| T-049.s2 | allow | 1 | REPLAY_HISTORY_VIOLATION, OUT_OF_SCOPE_SIMULATOR_MUTATION |
| T-050.s2 | allow | 1 | REPLAY_HISTORY_VIOLATION, OUT_OF_SCOPE_SIMULATOR_MUTATION |
| U-K-026.s1 | deny | 0 | none |
| U-K-027.s1 | deny | 0 | none |
| U-K-028.s1 | deny | 0 | none |
| U-K-029.s1 | deny | 0 | none |
| U-K-030.s1 | deny | 0 | none |
| V-041.s1 | deny | 0 | none |
| V-042.s1 | deny | 0 | none |
| V-043.s1 | deny | 0 | none |
| V-044.s1 | deny | 0 | none |
| V-045.s1 | deny | 0 | none |

T-046–T-050 demonstrate five duplicate receipts after schema-valid history erasure: five REPLAY_HISTORY_VIOLATION and five OUT_OF_SCOPE_SIMULATOR_MUTATION labels. These ten labels occur in five frozen ambiguous attempts, outside the scored gate. They are concrete remaining assurance limits, not successful defenses. T-041–T-045 admit the still-unused original grant after exact snapshot restoration. The frozen ambiguity contract is retained; no post-outcome relabeling occurs.

Scored symbolic writes: **200**. Scored invariant labels: **0**. All-primary symbolic writes: **210**. These are harness-local synthetic state changes attached to observed receipts; gateway receipts explicitly have side_effects=false. No real connector/network containment occurs.

## Timing and reproducibility

305 exact genuine template controls passed in separate provisioned worlds; excluded from primary totals. Every primary episode has 5 warmup + 20 measured rebuilds with its ordered history retained. Constructor refusal is separately recorded from actual Kernel refusal.

| Group | Kernel-call samples | No Kernel call (measured repetitions) | p50 ms | p95 ms | max ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| S | 200 | 900 | 1.357279 | 2.240190 | 3.675241 |
| T | 1500 | 800 | 1.175083 | 2007.874421 | 2117.932558 |
| U | 3200 | 0 | 0.907961 | 1.684593 | 4.862671 |
| V | 900 | 0 | 1.157175 | 1.873202 | 5.855909 |
| W | 14500 | 0 | 0.932552 | 1.940546 | 191.643050 |
| overall | 20300 | 1700 | 0.961535 | 1.961274 | 2117.932558 |

Raw nanoseconds for every call/repetition are retained, including separately timed fresh Guardian evaluations, actual constructor/reopen calls and baseline decision calls. Signing, fixture materialization, event delivery, snapshots and grading are excluded from Kernel timing. Percentiles use nearest rank. Timeout tails and filesystem/scheduling delays are retained, never trimmed. No CPU pinning or host-load/frequency controls were used; validation processes overlapped parts of measurement. Baseline and pipeline timings do different work, so no speedup claim is justified.

Python: `3.12.14 (main, Aug 25 2026, 14:00:49) [Clang 22.1.3 ]`. SQLite: `3.53.1`; source ID `2026-05-05 10:34:17 c88b22011a54b4f6fbd149e9f8e4de77658ce58143a1af0e3785e4e6475127e9`. CPU: `INTEL(R) XEON(R) PLATINUM 8573C`; platform `Linux-6.18.57-x86_64-with-glibc2.41`. Dependencies: `{"cryptography": "50.0.1", "jsonschema": "4.23.0", "pytest": "8.3.5", "rfc3339-validator": "0.1.4"}`. Full pip freeze, initial clean worktree state, tree ID and timestamps are in the result environment.

Oracle SHA-256: `18539d829f7f95ef0a3e93bde607b253b76b15085c184816b862574c48b217a0`. 183 selected source/historical paths checked byte-for-byte; Guardian, policies and wire schemas unchanged. Protected source and historical diff stats are empty. Complete decompressed/gzip hashes are in results.sha256. REPRODUCE.md gives the commit restoration, hash verification, tests and complete rerun commands.

Frozen plan and repair were sibling branches with earlier oracle timestamp, not an ancestry proof of blindness. This public, prior-failure-informed post-repair challenge is not independent field validation or a fully untouched assessment. Review provenance is self-review plus separately labeled AI examinations; no independent human review.
