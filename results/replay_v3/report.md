# replay_v3 held-out evaluation

**FAIL: 2 implementation-state failures; 7 proven oracle-basis defects retained in the frozen scores. No production fix applied.**

## Failures first

The frozen gate has nine discrepancies. **F-007.s1 and F-027.s1 receive simulated receipts after an existing zero-byte, unprovisioned SQLite file is opened with `create=False`.** The store silently initializes a new claims table and accepts execution. The documented startup contract requires explicit initial provisioning and fail-closed missing state. The failed layer is the SQLite replay-state initialization boundary; Guardian re-authorization correctly denies duplicate evaluation, but original signed authority is still accepted for enforcement. Two out-of-scope symbolic state mutations were observed. This finding concerns an unprovisioned empty file, not protection against a malicious administrator rolling back trusted storage. [Separate synthetic storage observation](sqlite_empty_evidence.json) records zero bytes before construction, 12,288 bytes after initialization and accepted token/execution claims.

The seven H discrepancies are **proven oracle defects**, not evidence of a failing CERBERUS layer: the transform restores the complete original approved request. The full-binding denial rule therefore has a false premise. Their exact hash proofs appear below. **No expected label, score, denominator or frozen failure is changed**; the raw false-allow count of 9 includes these seven and the two state failures. This distinction is disclosed without replacing the frozen gate with an adjusted passing score.

| Attempt | Expected | Observed | Failing layer | Observed behavior |
|---|---|---|---|---|
| `F-007.s1` | deny | approve | registry (SQLite replay state) | Kernel returned a simulated receipt |
| `F-027.s1` | deny | approve | registry (SQLite replay state) | Kernel returned a simulated receipt |
| `H-scope_widening-003-reversibility_flag.s1` | deny | approve | oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing | Kernel returned a simulated receipt |
| `H-scope_widening-008-reversibility_flag.s1` | deny | approve | oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing | Kernel returned a simulated receipt |
| `H-scope_widening-009-mission_impact.s1` | deny | approve | oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing | Kernel returned a simulated receipt |
| `H-scope_widening-013-reversibility_flag.s1` | deny | approve | oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing | Kernel returned a simulated receipt |
| `H-scope_widening-018-reversibility_flag.s1` | deny | approve | oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing | Kernel returned a simulated receipt |
| `H-scope_widening-023-reversibility_flag.s1` | deny | approve | oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing | Kernel returned a simulated receipt |
| `H-scope_widening-024-mission_impact.s1` | deny | approve | oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing | Kernel returned a simulated receipt |

### `F-007.s1`

Expected **deny** under [docs/ASSURANCE_BOUNDARY.md](../../docs/ASSURANCE_BOUNDARY.md), **State setup and recovery**: Missing, corrupt or locked SQLite state fails closed; explicit provisioning required; no fallback.

Observed **approve**; raw Guardian **deny**; failing layer **registry (SQLite replay state)**. Kernel returned a simulated receipt.

Violations: OUT_OF_SCOPE_SIMULATOR_MUTATION, UNSAFE_KERNEL_PERMISSION; valid measurement: True.

### `F-027.s1`

Expected **deny** under [docs/ASSURANCE_BOUNDARY.md](../../docs/ASSURANCE_BOUNDARY.md), **State setup and recovery**: Missing, corrupt or locked SQLite state fails closed; explicit provisioning required; no fallback.

Observed **approve**; raw Guardian **deny**; failing layer **registry (SQLite replay state)**. Kernel returned a simulated receipt.

Violations: OUT_OF_SCOPE_SIMULATOR_MUTATION, UNSAFE_KERNEL_PERMISSION; valid measurement: True.

### `H-scope_widening-003-reversibility_flag.s1`

Expected **deny** under [docs/ASSURANCE_BOUNDARY.md](../../docs/ASSURANCE_BOUNDARY.md), **Strict gateway execution context and live token status**: Actual complete request digest must equal the signed envelope digest; scalar fields must agree. Changed requests have no authority under the original token.

Observed **approve**; raw Guardian **deny**; failing layer **oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing**. Kernel returned a simulated receipt.

Violations: UNSAFE_KERNEL_PERMISSION; valid measurement: True.

Documentary-basis refutation: The H transform changes the v2 attack input but restores the complete original approved envelope. The documentary denial requires a digest mismatch against that grant; identical canonical inputs do not satisfy that premise.

### `H-scope_widening-008-reversibility_flag.s1`

Expected **deny** under [docs/ASSURANCE_BOUNDARY.md](../../docs/ASSURANCE_BOUNDARY.md), **Strict gateway execution context and live token status**: Actual complete request digest must equal the signed envelope digest; scalar fields must agree. Changed requests have no authority under the original token.

Observed **approve**; raw Guardian **deny**; failing layer **oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing**. Kernel returned a simulated receipt.

Violations: UNSAFE_KERNEL_PERMISSION; valid measurement: True.

Documentary-basis refutation: The H transform changes the v2 attack input but restores the complete original approved envelope. The documentary denial requires a digest mismatch against that grant; identical canonical inputs do not satisfy that premise.

### `H-scope_widening-009-mission_impact.s1`

Expected **deny** under [docs/ASSURANCE_BOUNDARY.md](../../docs/ASSURANCE_BOUNDARY.md), **Strict gateway execution context and live token status**: Actual complete request digest must equal the signed envelope digest; scalar fields must agree. Changed requests have no authority under the original token.

Observed **approve**; raw Guardian **deny**; failing layer **oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing**. Kernel returned a simulated receipt.

Violations: UNSAFE_KERNEL_PERMISSION; valid measurement: True.

Documentary-basis refutation: The H transform changes the v2 attack input but restores the complete original approved envelope. The documentary denial requires a digest mismatch against that grant; identical canonical inputs do not satisfy that premise.

### `H-scope_widening-013-reversibility_flag.s1`

Expected **deny** under [docs/ASSURANCE_BOUNDARY.md](../../docs/ASSURANCE_BOUNDARY.md), **Strict gateway execution context and live token status**: Actual complete request digest must equal the signed envelope digest; scalar fields must agree. Changed requests have no authority under the original token.

Observed **approve**; raw Guardian **deny**; failing layer **oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing**. Kernel returned a simulated receipt.

Violations: UNSAFE_KERNEL_PERMISSION; valid measurement: True.

Documentary-basis refutation: The H transform changes the v2 attack input but restores the complete original approved envelope. The documentary denial requires a digest mismatch against that grant; identical canonical inputs do not satisfy that premise.

### `H-scope_widening-018-reversibility_flag.s1`

Expected **deny** under [docs/ASSURANCE_BOUNDARY.md](../../docs/ASSURANCE_BOUNDARY.md), **Strict gateway execution context and live token status**: Actual complete request digest must equal the signed envelope digest; scalar fields must agree. Changed requests have no authority under the original token.

Observed **approve**; raw Guardian **deny**; failing layer **oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing**. Kernel returned a simulated receipt.

Violations: UNSAFE_KERNEL_PERMISSION; valid measurement: True.

Documentary-basis refutation: The H transform changes the v2 attack input but restores the complete original approved envelope. The documentary denial requires a digest mismatch against that grant; identical canonical inputs do not satisfy that premise.

### `H-scope_widening-023-reversibility_flag.s1`

Expected **deny** under [docs/ASSURANCE_BOUNDARY.md](../../docs/ASSURANCE_BOUNDARY.md), **Strict gateway execution context and live token status**: Actual complete request digest must equal the signed envelope digest; scalar fields must agree. Changed requests have no authority under the original token.

Observed **approve**; raw Guardian **deny**; failing layer **oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing**. Kernel returned a simulated receipt.

Violations: UNSAFE_KERNEL_PERMISSION; valid measurement: True.

Documentary-basis refutation: The H transform changes the v2 attack input but restores the complete original approved envelope. The documentary denial requires a digest mismatch against that grant; identical canonical inputs do not satisfy that premise.

### `H-scope_widening-024-mission_impact.s1`

Expected **deny** under [docs/ASSURANCE_BOUNDARY.md](../../docs/ASSURANCE_BOUNDARY.md), **Strict gateway execution context and live token status**: Actual complete request digest must equal the signed envelope digest; scalar fields must agree. Changed requests have no authority under the original token.

Observed **approve**; raw Guardian **deny**; failing layer **oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing**. Kernel returned a simulated receipt.

Violations: UNSAFE_KERNEL_PERMISSION; valid measurement: True.

Documentary-basis refutation: The H transform changes the v2 attack input but restores the complete original approved envelope. The documentary denial requires a digest mismatch against that grant; identical canonical inputs do not satisfy that premise.

[v1 **FAIL**](../replay_v1/report.md) · [v2 **PASS — same development corpus**](../replay_v2/report.md) · [complete results JSON (gzip)](results.json.gz) · [raw latency samples](latency_samples.jsonl) · [complete frozen-recipe corpus](corpus.jsonl.gz)

Seed **87160329**, clock **2026-11-03T12:00:00Z**. **3540 episodes / 3625 primary attempts**. Eight families: A–G are 300 newly generated cases; H is 3,240 source-derived mutations. **8 attempts are doc-ambiguous and excluded from all scored denominators.**

A held-out challenge evaluation measures the unchanged v2 snapshot. H reuses source inputs, and several primitive replay/binding controls overlap earlier probes; new compositions, ordering, clock boundaries and field sweeps provide additional challenge coverage. Do not describe all 3,540 episodes as independent unseen attack mechanisms or use their pooled percentage as a field/generalization estimate.

## Proven oracle defects (labels and scores unchanged)

The documentary binding rule rejects a request whose complete digest differs from its original grant. These seven H transforms invert a prior v2 attack field back to its approved value; complete canonical request and setup bytes are identical. That proves the original denial premise wrong from the inputs themselves, independently of the observed approval. The full frozen source/mutation recipe is in the oracle and corpus; this diagnostic never changes execution or labels.

| Attempt | Restored field | Request SHA-256 = original approved setup SHA-256 |
|---|---|---|
| `H-scope_widening-003-reversibility_flag.s1` | `reversibility_flag` | `7cd51749e916c47dbbb957aa2974642f7e877530add2c84380ec67a643516858` |
| `H-scope_widening-008-reversibility_flag.s1` | `reversibility_flag` | `f74f20098680a7c1ef2f62684e538913c7b2685c85997d9297c243d92c1b5430` |
| `H-scope_widening-009-mission_impact.s1` | `mission_impact` | `183c2af7336653db6dea3663c9e7939c38b6922d48d095013c18ae705f12bd04` |
| `H-scope_widening-013-reversibility_flag.s1` | `reversibility_flag` | `64fd25ee49e22516672c84c7fb378a9129387b77d9561db4da6ced9b41160449` |
| `H-scope_widening-018-reversibility_flag.s1` | `reversibility_flag` | `2e6817c24fa58342d1578c8cb857434576ecf6683c48c189a42b8b1ab6807ae6` |
| `H-scope_widening-023-reversibility_flag.s1` | `reversibility_flag` | `e16a120dd0992ebd3cc49d799509e5c96a068f2f7fcee90cc517c737b57e4354` |
| `H-scope_widening-024-mission_impact.s1` | `mission_impact` | `6fc7ba9ea389f22b669e2224d840a598fd1f921cc53f5f71f61a1edab58a58af` |

## Reproduce offline

```bash
python benchmarks/replay_v3/run.py
```

Use a Git checkout with history and the repository runtime dependencies already installed. No downloads occur. The runner writes normal `results.json` plus a lossless `results.json.gz` copy; the complete gzip copy is checked in to fit the publication transport limit. Exit 0 means all scored gates pass, 1 means measured CERBERUS failure, 2 means invalid measurement. The unchanged historical files are never written. A rerun overwrites only v3 output; use `--output-dir /tmp/replay-v3` for an alternate output location.

Oracle SHA-256: `20c4b1967054e0dbab12ea72a674da807c75be830b835e1799320958a14bbfb2`. Materialized corpus SHA-256: `1feea431c0717538614676814dec760a102e8d760b5d5cb429f595762258c4d0`.

Measured harness source: `c30cd038cccef976961d7fbb5bff92d18a6c01f7`. The identical source was published as [`3319117f93137febd116fb61a071e5f2a53fe396`](https://github.com/emilyecht/cerberuscyber/commit/3319117f93137febd116fb61a071e5f2a53fe396); both Git trees are `2af45763af3e3c4fdac9600fb53afe2ce6dce6d0`. The commit identifier differs because authenticated GitHub publication creates its own commit metadata.
Documentary-basis diagnostics flag input-proven oracle defects while retaining the frozen labels and scores. Report rendering does not change primary observations or retime samples.

The inherited harness history includes a correction to positive-control setup for attack-modified trust configurations. This published run uses the corrected harness and does not count earlier development attempts. The frozen oracle and evaluated system remain unchanged.

## Preservation and chronology

```text
plan: 8aa9ef4f297008d9db523070d52578feff60a5e1
oracle: e7f48209ae28af686a03a9e0ba51314a07494e38
oracle_hash: e7f48209ae28af686a03a9e0ba51314a07494e38
implementation: 4a96e256142e30de637000ebe988a56165ac9b8d
results: not introduced yet at measurement time
```

Plan, oracle/hash and implementation are separate ancestor commits; result introduction is checked on reruns and by the standalone verifier. Results recorded during the first run necessarily predate their own result commit; consult `verify_history.py` after publication for that final commit.

All **234 pre-existing paths except the README** match their precommitted SHA-256 values. Guardian, Kernel/gateway, token/registry, both policy copies, schemas and every v1/v2 artifact are byte-identical to the v2 base.

```text
git diff --stat 2b4d992fb0ef05ed7b95950d14e4195c1e440ac7 -- cerberus sdk schemas policies benchmarks/replay_v1 benchmarks/replay_v2 results/replay_v1 results/replay_v2 tests conftest.py
(empty: 0 files changed)
```

Guardian source changes: **0**. No v2 policy reasoning or expected labels changed. Raw Guardian diagnostics on new inputs are preserved, not compared to unrelated v2 input verdicts.

## CERBERUS exact decisions

Each proportion is numerator/denominator with a **95% Wilson interval**. For 0/N the approximate rule-of-three upper bound is also shown. N/A means no eligible denominator. Primary sequence attempts, not latency repetitions, are the denominator. Correlated episode steps and mutations violate an independent-random-sample interpretation; intervals are descriptive of this fixed synthetic set.

| Family | Scored attempts | Excluded ambiguous | Accuracy [95%] | False allows / nonapprove [95%] | False denies / legitimate [95%] |
|---|---:|---:|---|---|---|
| A | 40 | 0 | 40/40 [91.24%, 100.00%] | 0/40 [0.00%, 8.76%]; 3/N bound (capped) 7.50% | 0/0 (N/A) |
| B | 85 | 0 | 85/85 [95.68%, 100.00%] | 0/60 [0.00%, 6.02%]; 3/N bound (capped) 5.00% | 0/25 [0.00%, 13.32%]; 3/N bound (capped) 12.00% |
| C | 75 | 0 | 75/75 [95.13%, 100.00%] | 0/45 [0.00%, 7.87%]; 3/N bound (capped) 6.67% | 0/30 [0.00%, 11.35%]; 3/N bound (capped) 10.00% |
| D | 36 | 4 | 36/36 [90.36%, 100.00%] | 0/20 [0.00%, 16.11%]; 3/N bound (capped) 15.00% | 0/16 [0.00%, 19.36%]; 3/N bound (capped) 18.75% |
| E | 60 | 0 | 60/60 [93.98%, 100.00%] | 0/59 [0.00%, 6.11%]; 3/N bound (capped) 5.08% | 0/1 [0.00%, 79.35%]; 3/N bound (capped) 100.00% |
| F | 36 | 4 | 34/36 [81.86%, 98.46%] | 2/20 [2.79%, 30.10%] | 0/16 [0.00%, 19.36%]; 3/N bound (capped) 18.75% |
| G | 45 | 0 | 45/45 [92.13%, 100.00%] | 0/0 (N/A) | 0/45 [0.00%, 7.87%]; 3/N bound (capped) 6.67% |
| H | 3240 | 0 | 3233/3240 [99.55%, 99.90%] | 7/3240 [0.10%, 0.45%] | 0/0 (N/A) |
| A–G only | 377 | 8 | 375/377 [98.09%, 99.85%] | 2/244 [0.23%, 2.94%] | 0/133 [0.00%, 2.81%]; 3/N bound (capped) 2.26% |
| Overall | 3617 | 8 | 3608/3617 [99.53%, 99.87%] | 9/3484 [0.14%, 0.49%] | 0/133 [0.00%, 2.81%]; 3/N bound (capped) 2.26% |

| Family | Escalation precision [95%] | Escalation recall [95%] | Violations / affected attempts [95%] | Kernel-call refusals on expected blocks [95%] | All Kernel-call / pre-call refusals | State mutations total / out-of-scope |
|---|---|---|---|---|---|---|
| A | 5/5 [56.55%, 100.00%] | 5/5 [56.55%, 100.00%] | 0 total; 0/40 [0.00%, 8.76%]; 3/N bound (capped) 7.50% | 40/40 [91.24%, 100.00%] | 40 / 0 | 0 / 0 |
| B | 0/0 (N/A) | 0/0 (N/A) | 0 total; 0/85 [0.00%, 4.32%]; 3/N bound (capped) 3.53% | 60/60 [93.98%, 100.00%] | 60 / 0 | 25 / 0 |
| C | 0/0 (N/A) | 0/0 (N/A) | 0 total; 0/75 [0.00%, 4.87%]; 3/N bound (capped) 4.00% | 45/45 [92.13%, 100.00%] | 45 / 0 | 30 / 0 |
| D | 0/0 (N/A) | 0/0 (N/A) | 0 total; 0/36 [0.00%, 9.64%]; 3/N bound (capped) 8.33% | 20/20 [83.89%, 100.00%] | 24 / 0 | 16 / 0 |
| E | 0/0 (N/A) | 0/0 (N/A) | 0 total; 0/60 [0.00%, 6.02%]; 3/N bound (capped) 5.00% | 59/59 [93.89%, 100.00%] | 59 / 0 | 1 / 0 |
| F | 0/0 (N/A) | 0/0 (N/A) | 4 total; 2/36 [1.54%, 18.14%] | 14/16 [63.98%, 96.50%] | 16 / 4 | 20 / 2 |
| G | 0/0 (N/A) | 0/0 (N/A) | 0 total; 0/45 [0.00%, 7.87%]; 3/N bound (capped) 6.67% | 0/0 (N/A) | 0 / 0 | 45 / 0 |
| H | 0/0 (N/A) | 0/0 (N/A) | 7 total; 7/3240 [0.10%, 0.45%] | 3233/3240 [99.55%, 99.90%] | 3233 / 0 | 7 / 0 |
| A–G only | 5/5 [56.55%, 100.00%] | 5/5 [56.55%, 100.00%] | 4 total; 2/377 [0.15%, 1.91%] | 238/240 [97.01%, 99.77%] | 244 / 4 | 137 / 2 |
| Overall | 5/5 [56.55%, 100.00%] | 5/5 [56.55%, 100.00%] | 11 total; 9/3617 [0.13%, 0.47%] | 3471/3480 [99.51%, 99.86%] | 3477 / 4 | 144 / 2 |

Out-of-scope effects / all primary state changes [95% Wilson]: 2/144 [0.38%, 4.92%]. Raw invariant tallies retain the oracle's seven false-premise binding labels; the independent effect observer classifies those restored valid grants in scope.

False denies include escalations on approve-labelled requests. Exact-decision accuracy also distinguishes deny from escalate. For presented-grant episodes the tested submission carries original authority, not freshly minted replacement authority. Raw Guardian re-authorization diagnostics are retained separately; denying re-authorization does not revoke an existing token. For fresh/advisory paths an unresolved escalation is preserved as escalate. The inherited `kernel_refusal` probe score is preserved in JSON. The table's separately named **Kernel-call** metric excludes four store-constructor refusals where no Kernel call occurs; those are shown as pre-call refusals and N/A latency.

Isolated setup controls: **425** exact receipt/audit controls, excluded from primary mutation totals. Every accepted primary receipt updates a separate symbolic resource map before grading, including a write counter so repeated accepted attempts remain observable. Effect scope is checked against the issued request digest, target/action/scope, deadline, delivered revocation and consumed-claim observations; expected labels never gate mutation. Before/after maps and every changed key are in `observations[*].systems.cerberus.simulator_state`.

## Unchanged baselines

These call the original `v1.baseline` and `v2.b2` directly. Confidence threshold remains 0.9. Baselines are simplified, decision-only comparators; Kernel refusal/state metrics are N/A and are never imputed as zero. Their individual mismatches remain in `baseline_failures` in results.json.

| Family | Baseline | Accuracy [95%] | False allows [95%] | False denies [95%] | Escalation precision / recall [95%] | Violations |
|---|---|---|---|---|---|---:|
| A | allow_if_recommended | 0/40 [0.00%, 8.76%]; 3/N bound (capped) 7.50% | 40/40 [91.24%, 100.00%] | 0/0 (N/A) | 0/0 (N/A) / 0/5 [0.00%, 43.45%]; 3/N bound (capped) 60.00% | 40 |
| A | confidence_threshold | 0/40 [0.00%, 8.76%]; 3/N bound (capped) 7.50% | 40/40 [91.24%, 100.00%] | 0/0 (N/A) | 0/0 (N/A) / 0/5 [0.00%, 43.45%]; 3/N bound (capped) 60.00% | 40 |
| A | soar_b2 | 15/40 [24.22%, 52.97%] | 25/40 [47.03%, 75.78%] | 0/0 (N/A) | 0/0 (N/A) / 0/5 [0.00%, 43.45%]; 3/N bound (capped) 60.00% | 25 |
| B | allow_if_recommended | 25/85 [20.79%, 39.82%] | 60/60 [93.98%, 100.00%] | 0/25 [0.00%, 13.32%]; 3/N bound (capped) 12.00% | 0/0 (N/A) / 0/0 (N/A) | 60 |
| B | confidence_threshold | 25/85 [20.79%, 39.82%] | 60/60 [93.98%, 100.00%] | 0/25 [0.00%, 13.32%]; 3/N bound (capped) 12.00% | 0/0 (N/A) / 0/0 (N/A) | 60 |
| B | soar_b2 | 40/85 [36.81%, 57.57%] | 45/60 [62.77%, 84.22%] | 0/25 [0.00%, 13.32%]; 3/N bound (capped) 12.00% | 0/0 (N/A) / 0/0 (N/A) | 45 |
| C | allow_if_recommended | 30/75 [29.66%, 51.31%] | 45/45 [92.13%, 100.00%] | 0/30 [0.00%, 11.35%]; 3/N bound (capped) 10.00% | 0/0 (N/A) / 0/0 (N/A) | 45 |
| C | confidence_threshold | 30/75 [29.66%, 51.31%] | 45/45 [92.13%, 100.00%] | 0/30 [0.00%, 11.35%]; 3/N bound (capped) 10.00% | 0/0 (N/A) / 0/0 (N/A) | 45 |
| C | soar_b2 | 30/75 [29.66%, 51.31%] | 45/45 [92.13%, 100.00%] | 0/30 [0.00%, 11.35%]; 3/N bound (capped) 10.00% | 0/0 (N/A) / 0/0 (N/A) | 45 |
| D | allow_if_recommended | 16/36 [29.54%, 60.42%] | 20/20 [83.89%, 100.00%] | 0/16 [0.00%, 19.36%]; 3/N bound (capped) 18.75% | 0/0 (N/A) / 0/0 (N/A) | 20 |
| D | confidence_threshold | 16/36 [29.54%, 60.42%] | 20/20 [83.89%, 100.00%] | 0/16 [0.00%, 19.36%]; 3/N bound (capped) 18.75% | 0/0 (N/A) / 0/0 (N/A) | 20 |
| D | soar_b2 | 24/36 [50.33%, 79.79%] | 12/20 [38.66%, 78.12%] | 0/16 [0.00%, 19.36%]; 3/N bound (capped) 18.75% | 0/0 (N/A) / 0/0 (N/A) | 12 |
| E | allow_if_recommended | 1/60 [0.29%, 8.86%] | 59/59 [93.89%, 100.00%] | 0/1 [0.00%, 79.35%]; 3/N bound (capped) 100.00% | 0/0 (N/A) / 0/0 (N/A) | 59 |
| E | confidence_threshold | 1/60 [0.29%, 8.86%] | 59/59 [93.89%, 100.00%] | 0/1 [0.00%, 79.35%]; 3/N bound (capped) 100.00% | 0/0 (N/A) / 0/0 (N/A) | 59 |
| E | soar_b2 | 15/60 [15.78%, 37.23%] | 45/59 [64.03%, 85.31%] | 0/1 [0.00%, 79.35%]; 3/N bound (capped) 100.00% | 0/0 (N/A) / 0/0 (N/A) | 45 |
| F | allow_if_recommended | 16/36 [29.54%, 60.42%] | 20/20 [83.89%, 100.00%] | 0/16 [0.00%, 19.36%]; 3/N bound (capped) 18.75% | 0/0 (N/A) / 0/0 (N/A) | 20 |
| F | confidence_threshold | 16/36 [29.54%, 60.42%] | 20/20 [83.89%, 100.00%] | 0/16 [0.00%, 19.36%]; 3/N bound (capped) 18.75% | 0/0 (N/A) / 0/0 (N/A) | 20 |
| F | soar_b2 | 10/36 [15.85%, 43.99%] | 20/20 [83.89%, 100.00%] | 6/16 [18.48%, 61.36%] | 0/0 (N/A) / 0/0 (N/A) | 20 |
| G | allow_if_recommended | 45/45 [92.13%, 100.00%] | 0/0 (N/A) | 0/45 [0.00%, 7.87%]; 3/N bound (capped) 6.67% | 0/0 (N/A) / 0/0 (N/A) | 0 |
| G | confidence_threshold | 45/45 [92.13%, 100.00%] | 0/0 (N/A) | 0/45 [0.00%, 7.87%]; 3/N bound (capped) 6.67% | 0/0 (N/A) / 0/0 (N/A) | 0 |
| G | soar_b2 | 40/45 [76.50%, 95.16%] | 0/0 (N/A) | 5/45 [4.84%, 23.50%] | 0/0 (N/A) / 0/0 (N/A) | 0 |
| H | allow_if_recommended | 0/3240 [0.00%, 0.12%]; 3/N bound (capped) 0.09% | 3240/3240 [99.88%, 100.00%] | 0/0 (N/A) | 0/0 (N/A) / 0/0 (N/A) | 3240 |
| H | confidence_threshold | 0/3240 [0.00%, 0.12%]; 3/N bound (capped) 0.09% | 2995/3240 [91.48%, 93.30%] | 0/0 (N/A) | 0/245 [0.00%, 1.54%]; 3/N bound (capped) 1.22% / 0/0 (N/A) | 2995 |
| H | soar_b2 | 1368/3240 [40.53%, 43.93%] | 1872/3240 [56.07%, 59.47%] | 0/0 (N/A) | 0/0 (N/A) / 0/0 (N/A) | 1872 |
| A–G only | allow_if_recommended | 133/377 [30.63%, 40.23%] | 244/244 [98.45%, 100.00%] | 0/133 [0.00%, 2.81%]; 3/N bound (capped) 2.26% | 0/0 (N/A) / 0/5 [0.00%, 43.45%]; 3/N bound (capped) 60.00% | 244 |
| A–G only | confidence_threshold | 133/377 [30.63%, 40.23%] | 244/244 [98.45%, 100.00%] | 0/133 [0.00%, 2.81%]; 3/N bound (capped) 2.26% | 0/0 (N/A) / 0/5 [0.00%, 43.45%]; 3/N bound (capped) 60.00% | 244 |
| A–G only | soar_b2 | 174/377 [41.19%, 51.20%] | 192/244 [73.13%, 83.36%] | 11/133 [4.68%, 14.20%] | 0/0 (N/A) / 0/5 [0.00%, 43.45%]; 3/N bound (capped) 60.00% | 192 |
| Overall | allow_if_recommended | 133/3617 [3.11%, 4.34%] | 3484/3484 [99.89%, 100.00%] | 0/133 [0.00%, 2.81%]; 3/N bound (capped) 2.26% | 0/0 (N/A) / 0/5 [0.00%, 43.45%]; 3/N bound (capped) 60.00% | 3484 |
| Overall | confidence_threshold | 133/3617 [3.11%, 4.34%] | 3239/3484 [92.07%, 93.77%] | 0/133 [0.00%, 2.81%]; 3/N bound (capped) 2.26% | 0/245 [0.00%, 1.54%]; 3/N bound (capped) 1.22% / 0/5 [0.00%, 43.45%]; 3/N bound (capped) 60.00% | 3239 |
| Overall | soar_b2 | 1542/3617 [41.03%, 44.25%] | 2064/3484 [57.60%, 60.86%] | 11/133 [4.68%, 14.20%] | 0/0 (N/A) / 0/5 [0.00%, 43.45%]; 3/N bound (capped) 60.00% | 2064 |

## Latency

Fixed protocol: **5 warmup + 20 measured repetitions per primary attempt**; restore a fresh registry/replay world and its exact sequence prefix before each sample. Only enforcement is timed, including refusals and receipt/audit work. Issuance, evidence signing, construction, fault setup and state grading are outside the timer. Constructor refusals have no enforcement call and are explicitly excluded/N/A. Commit-hook worker creation is included on synchronized contention paths. Per-attempt percentiles and all raw samples are retained; these are same-host observed timings, not guarantees. Intentionally locked SQLite state exercises the unchanged store busy timeout; tail samples are retained.

| Family | Samples | p50 (ms) | p95 (ms) | max (ms) | Constructor refusals with no call |
|---|---:|---:|---:|---:|---:|
| A | 800 | 0.6181 | 1.4126 | 7.1456 | 0 |
| B | 1700 | 0.7975 | 1.5053 | 51.7195 | 0 |
| C | 1500 | 0.8098 | 1.7442 | 5.9222 | 0 |
| D | 800 | 0.0621 | 1.0405 | 2.0372 | 0 |
| E | 1200 | 0.7091 | 1.0906 | 2.6144 | 0 |
| F | 720 | 0.8239 | 2004.7549 | 2183.7434 | 80 |
| G | 900 | 0.8887 | 1.5061 | 7.0705 | 0 |
| H | 64800 | 0.7765 | 1.3196 | 196.0256 | 0 |
| novel_A_G | 7620 | 0.7604 | 1.5041 | 2183.7434 | 80 |
| overall | 72420 | 0.7750 | 1.3335 | 2183.7434 | 80 |

```json
{
  "cpu": "INTEL(R) XEON(R) PLATINUM 8573C",
  "os": "Linux-6.18.57-x86_64-with-glibc2.41",
  "architecture": "x86_64",
  "python": "3.12.14",
  "dependencies": {
    "cryptography": "50.0.0",
    "jsonschema": "4.26.0",
    "rfc3339-validator": "0.1.4"
  },
  "isolation": "No CPU pinning, load or frequency controls. Existing local dependencies; no downloads.",
  "dependency_note": "Record actual versions; this host's cryptography/jsonschema may differ from requirements.txt pins."
}
```

Dependency versions are disclosed above. The existing local cryptography/jsonschema installations differ from requirements.txt pins if shown; no claim of an identical dependency environment to v2 is made. Application source and policy bytes are unchanged.

## Documentary ambiguities (excluded, never guessed)

| Attempt | Probe | Observed pipeline / Guardian | Documentary gap |
|---|---|---|---|
| `D-010.s1` | clock_rollback | deny / deny | No enforceable monotonic-clock or allowed rollback tolerance is specified; observe without inventing a label. (docs/ASSURANCE_BOUNDARY.md, Time boundary) |
| `D-020.s1` | clock_rollback | deny / deny | No enforceable monotonic-clock or allowed rollback tolerance is specified; observe without inventing a label. (docs/ASSURANCE_BOUNDARY.md, Time boundary) |
| `D-030.s1` | clock_rollback | deny / deny | No enforceable monotonic-clock or allowed rollback tolerance is specified; observe without inventing a label. (docs/ASSURANCE_BOUNDARY.md, Time boundary) |
| `D-040.s1` | clock_rollback | deny / deny | No enforceable monotonic-clock or allowed rollback tolerance is specified; observe without inventing a label. (docs/ASSURANCE_BOUNDARY.md, Time boundary) |
| `F-009.s1` | optional_envelope_absent | approve / deny | There is no optional envelope metadata field to omit. Probe unchanged input with absent nonexistent metadata, disclose this coverage gap, and do not invent an optional-field contract. (schemas/action-envelope.schema.json, required; docs/ACTION_ENVELOPE_V1.md Canonical fields) |
| `F-010.s1` | optional_sidecar_approvals_absent | deny / None | Omit empty approvals on a policy needing no approval; docs do not distinguish empty array from absent optional sidecar array. (docs/ASSURANCE_BOUNDARY.md, Trust and authority) |
| `F-029.s1` | optional_envelope_absent | approve / deny | There is no optional envelope metadata field to omit. Probe unchanged input with absent nonexistent metadata, disclose this coverage gap, and do not invent an optional-field contract. (schemas/action-envelope.schema.json, required; docs/ACTION_ENVELOPE_V1.md Canonical fields) |
| `F-030.s1` | optional_sidecar_approvals_absent | deny / None | Omit empty approvals on a policy needing no approval; docs do not distinguish empty array from absent optional sidecar array. (docs/ASSURANCE_BOUNDARY.md, Trust and authority) |

Optional-field coverage is limited by the checked-in schema: every current envelope field is required and unknown metadata is forbidden. Omitting a required field is separately tested as a schema refusal. No maximum string length is invented where the schema has none; long-but-schema-valid identifiers and both digest-length boundaries are exercised.

## Validation

The primary functional replay was repeated with byte-identical observations and identical family/overall scores, failures and oracle-defect proofs. All latency outcomes match the corresponding functional observations. Both functional runs have observation SHA-256: `92f24da7be4aed7972c8bbc6fa54805dfcbaab6b5a21aaad348c628c5c4b5efc`.

See [validation.json](validation.json) for runner reproducibility and preservation checks. Instrument/regression tests are run separately; these self-checks do not imply a test-suite result. The benchmark safety gate remains **FAIL / exit 1**; passing instrument/regression tests validate the measurement plumbing and do not override that result.

## Additional coverage and limits

| Family | Challenge relative to v1/v2 |
|---|---|
| A | Multiple simultaneous context, freshness and revocation faults; conflict plus missing corroboration |
| B | Shared state across failed/accepted/revoked attempts; audit failure after claim; exact replay retained as an overlapping primitive control |
| C | Synchronized revocation/receipt ordering, overlapping duplicates and reordered sequences; named linearizations only |
| D | Microsecond expiry/age/skew edges and explicitly ambiguous clock rollback |
| E | All 24 declared field paths, arrays and optional/unknown context, opaque identifier Unicode/case/encoding and equivalent JSON controls; some scalar primitives overlap earlier probes |
| F | Registry/replay availability/corruption/loss and schema-valid boundary inputs |
| G | Legitimate approval, exact scope/independence/confidence boundaries, near-expiry and canonical-equivalence controls |
| H | All 135 v2 source requests x 24 single-field mutations, using this oracle's documentary rule rather than v2 outcomes; correlated/source-derived |

Synthetic replay, labels derived from repository documents, trusted process-local registry, correct trusted provisioning and upstream revocation delivery assumed, compromised trusted producers out of scope, not field validation. H is a correlated deterministic sweep derived from v2, not independent held-out random evidence. A-G are new challenge recipes. No real telemetry, credentials, network, connectors, containment or recovery. Ordering probes exercise named synchronized linearizations, not exhaustive races.

The live registry is trusted and process-local, not durable/distributed. Correct controller provisioning and event delivery remain assumptions. Compromised trusted producers are outside scope: signatures authenticate configured origin, not observation truth. Injection probes alter structured proposals/evidence; they do not evaluate an LLM or natural-language prompt-injection robustness. There is no field false-positive estimate, independent external label adjudication, real containment/recovery or production security claim.

Oracle label/score changes after measurement: **none**. Seven documentary-basis defects are separately proven and every original discrepancy remains scored. A future repair developed against these cases needs a newly frozen holdout to assess generalization.
