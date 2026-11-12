# replay_v4 — Stage A: plan and frozen documentary oracle

**Stage A only. No repair, harness, runtime import, scenario execution, test or evaluation is authorized or performed.**

## Purpose, scope and provenance

Measure whether a future SQLite fail-closed repair works on fresh inputs and generalizes beyond its development corpus. The known empty-unprovisioned-file defect, restored-identity oracle defect and unresolved documentation topics supplied in the task motivate this design; no v3 result file or prior case corpus is read or reused.

New seed: **604279153** (neither 20261104 nor 87160329).
Synthetic logical clock: **2027-02-16T04:30:00Z**.
Baseline: `f0ebd38c58e9d40af35d35c5cc32b5614eb60439`, `research/replay-v3-held-out`.
New branch: `eval/replay-v4-plan`.
Step 0 inspected all **19** GitHub branch heads and their complete file trees: no replay_v4 files or eval/replay-v4-* branch, PLAN or oracle existed.

V3 is a **development corpus**, never the held-out set. S/T/U/V inputs and the 25 W parent envelopes are newly authored from this seed, checked-in policies/schemas and the public documented contracts. W derives only from these new v4 parents. No historical fixture, historical expected label or historical output informs a v4 label. Selection uses deterministic xorshift32 seed-derived identifiers, synthetic evidence digests and paths; the oracle contains the complete resulting inputs, so a generator is unnecessary.

Sources are pinned by Git blob IDs in `oracle.json:inputs.source_documents`. Only docs, ADRs, wire schemas, policy data and public interface descriptions were read for Stage A. Implementation contents for Guardian, Kernel/gateway, registry or store and v3 result files were not read in this stage. Guardian's baseline **Git blob ID**, read as metadata only, is `dd200f2efff7101281db8728a0e1a0ea5d78aae9`.

All created files are new and confined to `benchmarks/replay_v4/`; existing files remain unchanged. Repository inspection/publication uses the repository-transfer authorization already given in this conversation. There is no evaluation networking, telemetry, operational credential, real target or real receipt. No keys, proofs, tokens, SQLite files, permissions or locks are exercised now.

## Future holdout discipline

A future repair must be developed against v3, then frozen at a recorded commit **before** any v4 execution, result inspection or repair tuning. Record whether repair authors had access to these publicly frozen v4 fixtures. Public precommitment alone does not establish blindness or generalization: if v4 influences repair development, disclose that exposure and describe its later measurement as challenge/regression evidence, not an independent holdout.

This branch supplies no repair or Stage B runner. Stage B requires a separate instruction. Stop after the Stage A commit/hash handoff.

## Frozen coverage and denominators

| Family | Cases | Primary attempts | allow | deny | escalate | doc-ambiguous |
|---|---:|---:|---:|---:|---:|---:|
| S | 55 | 55 | 10 | 43 | 0 | 2 |
| T | 50 | 115 | 20 | 85 | 0 | 10 |
| U | 130 | 160 | 30 | 120 | 5 | 5 |
| V | 45 | 45 | 40 | 0 | 0 | 5 |
| W | 725 | 725 | 100 | 625 | 0 | 0 |
| Total | **1005** | **1100** | **200** | **873** | **5** | **22** |

There are **1078** planned scored attempts. A case is an episode; ordered attempts inside an episode can have different labels. `case.expected` is its final attempt's label only, not a replacement for the complete per-attempt sequence. Every attempt is independently labeled and cited. No measurements or confidence intervals have been produced.

### S — store initialization states: 55 cases

Eleven states, five new contexts each: missing file; existing zero-byte file; truncated file; SQLite file containing only an unrelated synthetic schema and never explicitly provisioned for authority; effectively denied file permissions; directory in place of file; symlink; read-only file; conflicting locked file; correctly provisioned trusted file; explicit provisioning followed by ordinary use.

S uses **fresh authorization** through the same explicitly selected store/namespace in Guardian and enforcement. Unprovisioned states are opened with `create=False`; only the explicit-provisioning controls invoke trusted setup `create=True`. A silently created authority table is not a permitted substitute for explicit provisioning. Healthy provisioned stores and explicitly provisioned never-used zero-byte files are legitimate allow controls.

For the five symlink cases: two links to a healthy provisioned trusted file are doc-ambiguous; dangling, zero-byte-target and directory-target links deny due to their independently invalid backing state. Do not infer a general symlink ban.

Permission/readonly cases require independently confirmed effective OS access denial by an unprivileged test identity with no override capabilities. Mode bits alone, elevated privileges or an unsupported filesystem do not establish the fixture. Unsupported/unconfirmed faults invalidate the measurement; they do not become correct denials or guessed labels. Locked-state fixtures retain the conflicting lock throughout the attempted claim.

### T — fail-closed recovery: 50 cases / 115 attempts

Ten sequences, five new contexts each: missing/zero/corrupt state after issuance; missing/zero/corrupt state after a first receipt; effective permission loss; lock failure followed by an unprovisioned zero-byte replacement; exact preexecution snapshot restoration; and schema-intact erased claim history.

Tokens, registry status, namespace and state history persist between attempts except for the stated fault. An issued grant never permits implicit provisioning or an in-memory fallback. Ordinary reopen/retry on missing, zero-byte or corrupt state remains deny. An audit failure after consumption never restores replay rights.

The restoration and erased-history variants contain **10 doc-ambiguous attempts**. The docs specify review/reconciliation and exclude some trusted-storage rollback guarantees but do not define a restoration protocol or history-integrity epoch. Do not invent those guarantees, and do not treat a schema-valid erased-history store as the legitimate initially empty control.

### U — re-sampled authority families: 130 cases / 160 attempts

- Compound attacks: **25** cases — expired+widened; revoked+wrong incident; stale evidence+structured injected proposal; revoked dependency+target/scope widening; authenticated conflict+missing corroboration. The last variant is five documented escalations with no token.
- Token replay/reuse: **25** cases — exact replay, cross-envelope reuse, partial claim followed by audit failure/retry, mid-sequence token revocation and dependency revocation.
- Race/ordering: **25** cases — named revocation-before/receipt-before linearizations, dependency revocation, ordered duplicates and unavailable status. Both first and duplicate primary attempts are counted; this is not exhaustive scheduling coverage.
- Clock edges: **30** cases — one microsecond before/at/after the earliest expiry; evidence-age boundary variants; skew within/at/beyond five seconds; and **five doc-ambiguous rollback cases**.
- Partial widening: **25** cases — single-field changes, an unknown metadata addition, and omission of the required human_approvals field. W separately covers all 25 declared bound-field paths.

Presented-grant cases submit the actual candidate under the original genuine grant; they never replace it with fresh authority. Duplicate Guardian re-authorization diagnostics do not revoke an earlier grant. Explicit fresh-authorization cases receive proofs for their frozen candidate under preconfigured allowlists; attack mutations are not re-signed under the original grant.

### V — legitimate near-misses: 45 cases

Eight groups of five (**40 scored legitimate controls**): critical impact with proper independent approvals; exact scope ceiling; exact evidence independence threshold; exact policy confidence threshold; evidence one microsecond short of expiry; maximum documented future skew; a never-used zero-byte file followed by explicit provisioning and fresh use; and canonical object-order/whitespace equivalence with undeclared metadata absent.

A further five omission probes are doc-ambiguous: a policy needs no human approval, its canonical envelope contains the required empty human_approvals list, but the separate sidecar approvals array is absent.

The current wire schema requires all **17** envelope fields and forbids unknown fields. It defines no optional envelope metadata field. Omitting an actual required field denies; absence of nonexistent metadata is a valid unchanged control, not evidence about optional-field semantics.

### W — mutation sweep with identity guard: 725 cases

**25 fresh v4 parents × (25 single-field mutations + 4 identity controls).**
Parents use the approving-with-approval policy profiles so human_approvals.0 exists. Each parent is one correlation cluster. The 25 field paths are frozen in `oracle.json:coverage.W.fields`.

**Identity rule is applied before labeling every W mutation:**

1. Compute the original approved and candidate canonical UTF-8 bytes from the frozen inputs.
2. If the complete bytes are identical, label the case **allow / control, never deny**. All other authority, unused-token, freshness and properly provisioned-state prerequisites remain valid.
3. Otherwise, label **deny under the original grant**, citing full-request binding (and the strict schema rule when applicable). Do not compare to v3 outputs, reissue a replacement grant, or re-sign an attack.
4. Freeze both the candidate canonical bytes and the comparison result. A future materializer must recompute using the documented public canonicalization and agree with these bytes. A discrepancy invalidates measurement; it cannot silently regenerate labels.

There are **100 identity controls** and **625 nonidentity denials**. Identity controls cover no-op assignment, reversed object-key order/whitespace, JSON-escaped ASCII target text after decoding, and a change that is fully restored before submission. W uses ASCII canonical strings and finite ordinary decimal confidence values, avoiding invented Unicode/numeric normalization rules. Sorted compact UTF-8 is the repository's documented Python profile, not an RFC 8785 claim. Wire controls must be decoded before the documented mapping interface; no network transport is tested.

## Documentary labeling and ambiguity

`oracle.json` is the complete machine-readable oracle; `ORACLE.md` lists every case, its attempt labels, source rules, all 22 ambiguities and five owner questions. It includes source documents, complete original envelopes, exact candidate data/recipes, preconditions, time/order/store events and the W guard results. It contains no observed decision.

Only documentary requirements justify labels. Normative conflicts or missing contracts become **doc-ambiguous**, never guesses. Ambiguous attempts are listed separately and excluded from accuracy, false-allow/false-deny and safety-pass denominators. Their behavior may be observed only in a separately authorized later stage and must be reported separately.

Questions are **Q-SYMLINK, Q-RESTORE, Q-HISTORY, Q-ROLLBACK, Q-SIDECAR**. Owner decisions must be documented before any subsequently revised oracle is frozen; retain this original snapshot. Do not rewrite labels in response to outcomes.

## Pass criteria and honest reporting

Pass requires:
- **zero unsafe authorizations by the full pipeline** on deny/escalate-labelled attempts;
- **zero false denies**, including an escalation instead of allow, on legitimate allow-labelled attempts;
- **Guardian unchanged** from the pinned baseline Git blob, with unchanged evaluation policy/wire contract;
- exact scored decision correctness, no safety-invariant violation, and valid setup controls.

A controlled documented state/construction refusal is a deny observation but is recorded separately from an actual Kernel refusal. A crash, invalid setup, unsupported permission fixture or failed genuine positive control is an invalid measurement, never successful defense. Record exact before/after synthetic state, scope/temporal/replay validity, accepted receipts and failing layer if execution is later authorized.

**Every failure is reported and is not patched.** Give the attempt, frozen expectation, documentary basis, observed behavior and failed layer. Oracle documentary defects, if proven from the inputs/rules, are separately disclosed while retaining original observations and frozen scores. Stage A makes no pass/fail claim about the future repair.

Report exact numerators/denominators and **95% Wilson intervals** using z=1.959963984540054. For each 0/N (N>0), also report the approximate rule-of-three upper bound **min(1,3/N)**; N=0 is N/A. Distinguish cases, primary attempts, controls and any timing repetitions.

Report S, T, each U subfamily, V, and W separately. **Never pool correlated source-derived mutations into a generalization estimate.** W has 25 parent clusters, not 725 independent trials; publish its mutation/identity counts separately. Other fixed-fixture intervals are descriptive, not field probabilities. If an overall arithmetic summary is supplied, label it descriptive only and never a generalization/operational security estimate.

## Limits and stop point

Synthetic replay only; labels derived from repository documents; trusted process-local registry; correct trusted producer/controller provisioning and event delivery assumed; compromised trusted producers out of scope; trusted single-host storage is not established protection against malicious rollback; structured proposal mutations do not test an LLM. No real telemetry, credentials, network effects, containment, recovery or field validation.

The only Stage A deliverables are this plan, `oracle.json`, `ORACLE.md` and `oracle.sha256`. Commit with **[skip ci]** so publication does not request CI execution. Inspect metadata/diffs and hash the oracle; do not invoke an implementation, fixture, test or benchmark. Then stop and wait for the owner's next instruction.
