Separate AI examination of the proposed SQLite followups — version 1

This review occurred after exposure to the frozen replay_v4 plan/oracle and
runner. It is a separate post-v4-exposure AI examination, not blinded development,
independent human validation, or a change to PR #19's frozen evaluation target.
The reviewed source is `/workspace/scratch/379e5a226cc0/sqlite-followups`.
No source or test files were modified by this reviewer.

Reviewed changes: six lines in `cerberus/state.py` reject any current SQLite
`PRAGMA journal_mode` other than DELETE; six lines in `cerberus/enforcement.py`
refresh the real clock after successful durable consumption, deny if expiry has
been reached, and use the refreshed timestamp for a successful receipt. The
existing full integrity check remains intact. The performance/availability
regression documented in `sqlite_second_review.md` remains open.

I found no new blocking implementation defect in these narrowly scoped fixes.
The journal-mode guard runs in the same transaction as schema/integrity
verification and insertion, so an ordinary concurrent connection cannot switch
the journal mode between the guard and consume. It does not convert a recovered
WAL store to DELETE and bless its lost history. This intentionally refuses
healthy WAL databases too; it establishes a supported-mode boundary rather than
WAL recovery correctness. The existing trusted-path/rollback limitations remain.

The post-consume expiry check keeps consumed claims committed on timeout and
withholds a receipt/audit record. This preserves at-most-once attempted behavior
even though a request that waited too long cannot simply retry. Explicit `now`
arguments remain a fixed simulation time; `now=None` refreshes the real clock.
This is appropriate for the stated scope and does not establish connector-level
atomicity or an independent trustworthy-clock service.

Two test-harness defects were found in the first focused run. Four WAL tests
matched the inner DELETE-mode diagnostic against the generic outer
`StateUnavailable`; two clock tests patched only enforcement's clock and left
the signer's initial verification on the actual November clock, so the frozen
September token expired before consumption. The run was `6 failed, 82 passed in
9.18s`. Those were harness failures, not successful negative controls or proof
of a failed implementation. The owner corrected them without weakening existing
tests: tests now assert the outer exception type and inspect its
`StateUnavailable` cause; both signer and enforcement receive the same advancing
test clock. The retained cause confirms the intended refusal mechanism.

The corrected six new tests passed in 0.25 s. They cover ordinary open, an
existing store's claim and explicit provisioning of WAL state; the exact crashed
committed-WAL/checksum-corruption artifact; and both sides of the post-consume
expiry boundary. Healthy default DELETE mode and unused live authority remain
positive controls. Both successful and expiry-denied consumption retain replay
protection.

An additional small independent probe used actual wall time and private
temporary databases. Its script is `probe_followup_review.py`; complete output is
`followup_probe_results_v1.json`:

- A legacy WAL was committed with two claims independently observed before child
  `os._exit(0)`, then its final byte was changed by one bit. Ordinary open,
  existing-store consume and explicit provisioning all raised `StateUnavailable`
  with the DELETE guard as the cause. The post-recovery database was structurally
  `ok` with zero claims, but remained in WAL mode and was never accepted/converted.
- A genuine one-second token started enforcement at
  `2026-11-11T23:41:35.332699Z`, expired at `23:41:36.328455Z`, and waited behind a
  private SQLite write lock. At `23:41:36.668640Z` the gateway denied it as expired
  during durable consumption. No receipt was produced; the claim remained used.
- A genuine live 30-second token subjected to a shorter private lock wait
  produced one receipt with a refreshed timestamp and retained its used claim.

No large load or retention benchmark was rerun during the ongoing v4 latency
measurement. The independent probe creates only a few isolated SQLite files.

Commands:

```sh
# Initial regression run, before harness corrections:
env PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/379e5a226cc0/venv312/bin/python -m pytest -p no:cacheprovider --basetemp=/workspace/scratch/379e5a226cc0/ai-review/followup-pytest tests/test_sqlite_review_followups.py tests/test_state_initialization.py tests/test_assurance_hardening.py -q --tb=short
# 6 failed, 82 passed in 9.18s; failure causes recorded above.

# Final six only after the owner corrected the harness:
env PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/379e5a226cc0/venv312/bin/python -m pytest -p no:cacheprovider --basetemp=/workspace/scratch/379e5a226cc0/ai-review/followup-final-pytest tests/test_sqlite_review_followups.py -q --tb=short
# 6 passed in 0.25s

env PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/379e5a226cc0/venv312/bin/python /workspace/scratch/379e5a226cc0/ai-review/probe_followup_review.py
# All small real-clock and corrupted-WAL probes passed.
```

Reviewed file SHA-256 values:

| File | SHA-256 |
| --- | --- |
| cerberus/state.py | c67633f539f7fc7f0de75c2ceeb8fcb88e7f5b6b00c2a0ea8e188d9c8cfd8fdd |
| cerberus/enforcement.py | 8a0052f5230d5335ed75cb3cfc56b1d9bf4509799510306ef5fe93608731408d |
| tests/test_sqlite_review_followups.py | c7846c593f0a6936ddc92771ceea5934f677c8295b7ab01d98486813dcb439cb |

Environment: the same Python 3.12.14/SQLite 3.53.1 Linux environment as the initial
review. No hardware crash/fsync, network filesystem or real connector validation
was performed. The original PR #19 target and its frozen v4 labels are separate
from these later fixes; results for that target cannot be attributed to this
followup implementation.
