# Replay v4 post-repair instrument, version 2

Stage A's `PLAN.md`, `ORACLE.md`, `oracle.json` and `oracle.sha256` are byte-for-byte
copies of commit `93f70d4603d06d323675456f90f2629b6b0d3b52`. The evaluated system
is **unmodified PR #19**, `6fe417400ff4844d7647dddd9435288c3485ffc0`. New findings
and follow-up repairs must use another branch; this instrument refuses a changed
evaluated source, policy, wire contract, historical corpus or result.

This is a post-repair synthetic challenge, not a blinded holdout, independent
human validation, field validation, or an operational security probability.
The oracle was public before the repair; repair-author access cannot be ruled out.
The runner is developed after both artifacts were available. Original-template
positive controls and six instrument tests were exercised during runner development.
No v4 expected label is changed in this process.

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt -r requirements-build.txt
.venv/bin/python benchmarks/replay_v4/run.py --verify-inputs-only
.venv/bin/python -m pytest -q tests/test_replay_v4_instrument.py
.venv/bin/python benchmarks/replay_v4/run.py --output-dir /tmp/replay-v4-reproduction
```

Exit 0 = all scored CERBERUS decisions/invariants and repeated observations pass;
1 = recorded CERBERUS safety/correctness failure; 2 = invalid setup/measurement or
non-reproducible outcomes. Baseline errors are reported in their own coverage and
are not CERBERUS successes. Unsupported permission fixtures are invalid, never
defensive passes. Run as non-root with zero effective capabilities on Linux.
The runtime blocks Python socket creation and performs no evaluation networking.

The 1,005 episodes contain 1,100 primary attempts: 200 allows, 873 denials,
5 escalations, 22 separately observed documentary ambiguities. Each episode resets
only once; its original token, namespace, registry and file history survive all
ordered attempts unless a frozen event explicitly changes them. Both Guardian
and gateway use the same SQLite store. An exact authenticated positive receipt
control runs per unique original template in a separate correctly provisioned
world. Fresh candidates get proofs bound to candidate bytes **only** when the
frozen plan requests fresh authorization; trust always comes from frozen operator
allowlists. Presented-grant attacks never get replacement grants or new proofs.

Comparators call the unchanged v1 `baseline` and v2 `b2` functions. `confidence_0.9`
is the display alias for historical `confidence_threshold`, always with threshold
0.9. Baselines measure decision coverage only: no durable replay store, receipt,
external effects, or implicit defense against injected storage faults. Their
original-template grant context is isolated from CERBERUS fault/replay state.

The complete run executes one primary observation plus 5 warmup and 20 measured
repetitions per episode; every repetition rebuilds that episode and runs its full
ordered prefix. All repeated functional observations must match primary decisions,
invariants, Guardian decisions, claim counts and symbolic writes. Kernel-call
latency excludes signing/setup/controller events/snapshots/grading, matches the
v3 enforcement-call timing boundary, and is N/A on constructor refusals. Constructor
and fresh-Guardian calls are separately timed; baseline times cover decision
functions only. No baseline speedup claim is justified by these different tasks.
The optimization of running a full ordered episode per repetition instead of
restarting each prefix separately changes setup repetition counts, not the state
visible to any measured primary attempt. Raw nanoseconds are retained.

Wilson 95% intervals and 0/N rule-of-three bounds describe these fixed synthetic
fixtures. W contains 25 correlated parents, 625 mutations and 100 identity controls;
do not treat its 725 attempts as independent draws. Overall sums are descriptive.
All 22 ambiguities remain outside scored denominators, including the erased-history
probe that can demonstrate a limitation without changing its frozen ambiguous label.

Historical source pins remain intact. On repaired code, the original v3 instrument
tests intentionally reject changed `cerberus/state.py`; a distinct post-repair CI
path runs other tests on repaired code and runs those historical tests on their
original pinned tree. This does not make the original full test command pass.

Version 1 (runner commit `9fe0bf02ee6144aa8f5f2d6838646f1ac2ac385a`)
incorrectly required both separate read and write denial for `wrong_permissions`.
Frozen S-023/S-024 use modes 0200/0300, which deny the combined O_RDWR access
required by SQLite but permit write-only access. Its full run is retained under
`results/replay_v4/pr19_2026-11-11/` as invalid instrument evidence. Version 2
adds the actual O_RDWR probe and keeps separate read/write diagnostics; readonly
also requires readable/write-denied state. Ten additional instrument regressions
cover every frozen S permission mode. No oracle, expected label, source under
test, namespace, mode bit, permission override or comparison baseline changed.
