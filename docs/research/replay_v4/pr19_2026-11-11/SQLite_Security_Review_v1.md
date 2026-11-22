# SQLite Security Review, version 1

Reviewed target: PR #19, `fix/sqlite-fail-closed-init`, commit
`6fe417400ff4844d7647dddd9435288c3485ffc0`; base
`f0ebd38c58e9d40af35d35c5cc32b5614eb60439`. The two-file repair is reused,
not rewritten. The earlier implementation `7a386eaa1bc4bf96e600c846def848158276f285`
is already its parent. Review date: 11 November 2026, America/Chicago.

## Scope and provenance

Examined `cerberus/state.py`, `tests/test_state_initialization.py`, Guardian,
enforcement, token signing/verification, live authority registry, existing
assurance/Kernel tests and documented storage assumptions. Prior author/agent
self-review was not treated as independent. The main agent performed a new
self-review and reproduced the WAL fault and proposed fixes. A separate
clean-context AI reviewer examined the exact read-only PR #19 worktree before
seeing the v4 plan, inputs, runner or results. Its complete initial report,
scripts and raw observations are retained in `reviews/`, with original-file hashes.

No independent qualified human reviewer was available through the inspected
repository: no CODEOWNERS file, requested reviewers or submitted PR #19 reviews
were present. No human was contacted or represented as validating this work.
The separate AI reviewer subsequently examined the runner, corrected a missed
permission-fixture issue, and reviewed the followup fixes after v4 exposure.
Those later examinations are explicitly post-exposure AI reviews. A PR #19
COMMENT review (ID 5866919900) records the findings, not an approval.

## Repair behavior and threat scenarios

| Scenario | Examined mechanism and result | Evidence |
| --- | --- | --- |
| Missing or zero-byte unprovisioned file | Ordinary `mode=rw` open cannot create a missing file; canonical schema verification rejects zero-byte/unprovisioned state; no normal-open DDL | 25 storage regression cases; S/T frozen episodes; no-DDL trace tests |
| Corrupt/truncated main database | Page alignment and full integrity verification reject the tested faults | Header/page truncation, arbitrary corrupt bytes, open/consume index-corruption regressions |
| Wrong table, primary key, index, view or claim trigger | Exact canonical schema/index entries and absence of triggers are required under the same writer transaction | Wrong columns, absent/weakened PK, view, ignore-trigger, post-startup schema damage tests |
| Inaccessible or conflicting locked state | SQLite/OS errors become StateUnavailable; no token/receipt or memory fallback in the configured pipeline | Actual unprivileged O_RDWR denial and retained conflicting locks in v4; focused shared-store tests |
| Token or execution-key reuse after restart | Both uniqueness claims commit together; reopening retains claims | Existing assurance tests, atomic-conflict probe and eight-process duplicate race |
| Conflicting second key after first insert | Transaction rollback does not leave a partially consumed new token | Separate review probe reuses the new token with a different execution key after the conflicting attempt |
| Schema or store changes after startup | Reopen and verification occur before every atomic claim | Existing-object schema/index fault regressions and T fault sequences |
| Committed WAL corruption or schema-valid erased history | Structural verification cannot establish historical completeness | SQ-002 and SQ-004 below; do not generalize main-file corruption refusal to these cases |

The only schema-creating code path in this implementation is the explicit
`create=True` constructor. Ordinary open and claims issue no schema DDL. This is
an API discipline, not authenticated proof of who provisioned a file: an externally
constructed canonical database is indistinguishable from a legitimately provisioned
one. Trusted provisioning, namespace continuity and filesystem ownership are assumptions.

`PRAGMA integrity_check` is justified here. In the retained regression, replacing
two consumed keys only inside the UNIQUE index leaves quick_check reporting ok
while a duplicate can evade the old index lookup. integrity_check detects the
table/index mismatch. SQLite documents that quick_check omits uniqueness and
table/index correspondence checks. It also documents the additional whole-history
cost of integrity_check. This is structural checking, not cryptographic history
authentication. [SQLite PRAGMA contract](https://www.sqlite.org/pragma.html#pragma_quick_check).

## Findings

| ID / severity | Affected code and reproduction | Impact and remediation | Disposition |
| --- | --- | --- | --- |
| SQ-001 / Medium, introduced availability regression | `state.py` `_connect` obtains BEGIN IMMEDIATE with a two-second timeout; `_verify` scans full integrity at startup and each `_claim`. At 500,000 retained rows / 106,364,928 bytes, four of eight concurrent unique claims failed with StateUnavailable; parent accepted all eight. Latest median claim 0.399520 s vs parent 0.001897 s; ordinary open 0.420896 s vs 0.000501 s. | Healthy requests can be refused as history/load grows, across namespaces sharing a file. Establish history/latency/queue limits and realistic load tests; redesign verification if needed. Removing integrity_check without equivalent corruption refusal is not acceptable. | OPEN; no benchmark tuning or weaker check introduced. Single-host descriptive probe, no throughput guarantee. |
| SQ-002 / High conditional safety gap, pre-existing | `state.py` `_connect`/`_verify` accept persistent WAL mode and verify only the post-recovery logical snapshot. Abrupt child exit leaves an 8,272-byte committed WAL; flipping its last bit loses two independently observed committed claims. Reopen succeeds, integrity_check is ok, identical token/execution consumption succeeds. Main agent reproduced both parent and PR results. | Broad corrupt-state refusal is not established. Restrict and verify supported DELETE journal mode before claims, without silently converting recovered WAL; otherwise require trusted monotonic recovery/history evidence. | Minimal proposed refusal in draft [PR #20](https://github.com/emilyecht/cerberuscyber/pull/20); v4 target remains unchanged PR #19. WAL configuration plus injected post-commit corruption required; default DELETE path not shown to have this fault. |
| SQ-003 / Medium conditional temporal gap, pre-existing | `enforcement.py` captures time and checks expiry before durable consumption, then timestamps a receipt with that stale value. Real-clock genuine one-second token plus 1.25-second conflicting lock returned a simulated receipt about 0.35 s after expiry. | An expired simulated authorization can be acknowledged after a blocking claim; full integrity scans widen this window. Recheck real time after consume, refuse the receipt at/after expiry, retain the consumed claim and use refreshed time on success. | Minimal proposed repair in PR #20. Main agent reproduced post-fix real-clock refusal and healthy positive control. Caller-supplied fixed logical `now` remains trusted. |
| SQ-004 / High if storage adversary is in scope; documented excluded threat | `state.py` accepts canonical schema with erased/restored rows; there is no authenticated epoch or external monotonic anchor. Restoring a pre-execution snapshot can admit a token; erasing consumed history admits duplicate receipts. T-046–T-050 separately observe this under frozen ambiguous labels. | At-most-once history is conditional on trusted storage continuity. Require authenticated rollback-resistant history, external monotonic state and an explicit operator reconciliation/recovery protocol before broad deployment claims. | OPEN boundary assumption. Original ambiguous labels retained and excluded from accuracy, never turned into defensive passes. |
| SQ-005 / Medium if trusted path mutation is in scope; no in-scope receipt bypass demonstrated | `_connect` lstat precedes SQLite path open; `_verify` stats the path independently of its opened inode. Parent components/hard links and concurrent trusted-path replacement are not authenticated. Separate review installs a symlink between lstat/open: initialization accepts it, subsequent ordinary claim rechecks and refuses it. | Path checks are not a TOCTOU-proof filesystem identity boundary. Use protected immutable parent directories, least privilege and an appropriate no-follow/identity-pinned storage/VFS design if hostile path mutation must be supported. | OPEN documented filesystem trust limitation; do not equate static symlink refusal with arbitrary path-race protection. |

## Transactions, concurrency and denial of service

BEGIN IMMEDIATE spans verification, both execution uniqueness inserts and commit.
Separate writers serialize; an execution conflict rolls back the preceding token
insert. The authority registry's RLock spans its status check, consumption and
receipt/audit handling, establishing the tested process-local revocation ordering.
It is not durable or distributed. A failed audit after consumption withholds a
receipt but does not restore replay rights. External effects are absent; no atomic
transaction joins a real connector effect to the SQLite claim.

Full verification under the writer reservation protects against tested post-startup
index damage but creates SQ-001. The two-second busy timeout is not a request-wide
deadline or a bound on integrity-check work. Claims/history are retained without
a demonstrated safe rotation, pruning, capacity or recovery protocol. Namespace
selection is trusted configuration, not authenticated admission.

## Tests and limits

Original repair focused command:
`python -m pytest -q tests/test_state_initialization.py tests/test_assurance_hardening.py tests/test_kernel_binding.py`
— 107 passed on Python 3.12.14 / SQLite 3.53.1. Separate reviewer selection:
82 passed. Proposed followup adds six new cases: 113 focused passed on both
Python 3.10.22 and 3.12.14 / SQLite 3.53.1. Current-source, historical-source,
installed-artifact, CI and v4 outcomes are itemized separately in the evidence
package; a source-pin failure or unavailable kernel backend is never a pass.

The first six new followup test cases initially had exception-wrapper and shared-clock
fixture errors. Final tests inspect the chained DELETE-mode cause and use the same
advancing clock for signer and gateway; the initial failing development log is
retained. Existing tests and frozen labels were not weakened. One dirty-tree full
test attempt was refused by a benchmark's existing clean-source gate; clean committed
reruns passed. The artifact verifier also corrected its own mistaken token
not-before/skew calculation; this changed neither runner observations nor labels.

No independent human validation, power-loss durability experiment, hardware fsync
attestation, network-filesystem validation, real telemetry, real containment/recovery,
production throughput or compromised-producer resistance is demonstrated.
Portable reproduction entry point: `benchmarks/replay_v4/reproduce_reviews.py`.
