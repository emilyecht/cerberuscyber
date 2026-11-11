Separate AI security examination of CERBERUS Cyber PR #19

Reviewed implementation: `6fe417400ff4844d7647dddd9435288c3485ffc0`.
Parent baseline: `f0ebd38c58e9d40af35d35c5cc32b5614eb60439`.
Read-only source tree: `/workspace/scratch/379e5a226cc0/sqlite-review`.
This is a separate AI reviewer, not independent human validation. The initial
review did not read replay_v4 oracle data, runner results, or benchmark outcomes.

The patch fixes implicit normal-startup DDL and rejects the tested invalid schemas,
claim-altering triggers, truncated main databases and corrupted replay indexes.
The transaction still atomically claims both execution keys. I found no new replay
bypass under the stated trusted-filesystem boundary. I found a new availability
regression, plus two pre-existing security-property gaps that the new verification
does not close. All reproduction scripts and output below use temporary databases;
no worktree source, frozen files, or existing benchmark results were modified.

1. Medium — new full-history integrity scan under the writer lock can deny healthy concurrent requests.

Exact implementation: `cerberus/state.py:62` sets a two-second SQLite lock timeout;
`:65` obtains `BEGIN IMMEDIATE`; `:88` performs whole-database `PRAGMA
integrity_check`; `:95` repeats verification for every claim. Initialization also
performs that scan while holding the writer reservation. Every accepted claim
grows retained history, and every new claim or replay traverses that history.
This changes a claim from an indexed insert into a serialized full-state check.

Reproduction: `probe_sqlite_second_review.py` seeds valid claims into the exact
provisioned schema, compares the class loaded from the parent commit with the PR
class, then submits eight concurrent unique claims against one healthy 500,000-row
database (106,364,928 bytes). Both implementations use the same database and
digest/key formats. Latest observed medians:

| Retained rows | Parent claim | PR claim | Parent ordinary open | PR ordinary open |
| ---: | ---: | ---: | ---: | ---: |
| 10,000 | 0.002605 s | 0.014895 s | 0.000994 s | 0.024531 s |
| 100,000 | 0.002519 s | 0.079149 s | 0.000566 s | 0.079045 s |
| 500,000 | 0.001897 s | 0.399520 s | 0.000501 s | 0.420896 s |

The eight parent claims all succeeded; slowest was 0.057182 s. On the PR, four
succeeded and four raised `StateUnavailable` at approximately 2.01 s. There was
no corruption or external lock-holder. A separate earlier run measured 0.705185 s
per PR claim versus 0.002507 s on the parent at the same size, illustrating host
variance rather than a fixed throughput guarantee. Detailed latest values are
in `probe_results.json`.

Impact is denial of legitimate authorization/enforcement as history accumulates,
including serialization across unrelated namespaces in the same database.
Repeated valid registered replay attempts also pay the full check. No unauthorized
execution was demonstrated by this load test. The documentation disclaims an
availability guarantee and already identifies indefinite retention, so this is a
measurable regression/capacity issue rather than evidence that the prototype
promises production throughput.

Remediation: establish and enforce a supported history size, verification latency
and bounded request queue; test a realistic retained history and concurrent load.
If moving full verification to a controlled health gate or maintenance process,
retain fail-closed checking for corruption introduced after startup, including
table/index inconsistency. Simply removing the per-claim check would reopen the
index-corruption case this patch fixes. A different persistence/verification
design may be needed for larger retained histories.

2. High-impact conditional residual — corrupt committed WAL can lose consumed claims while integrity_check still passes (pre-existing).

Exact implementation: `cerberus/state.py:62-65` opens SQLite and begins a transaction
without restricting persistent journal mode; `:74-89` checks only the logical
post-recovery database. SQLite recovery may discard a corrupt WAL transaction
before those checks. The code never establishes that all previously acknowledged
claims survived recovery.

Reproduction is fully captured in `probe_wal_recovery.py` and
`wal_probe_results.json`. Provision the normal database. In a child process:
set persistent `PRAGMA journal_mode=WAL`, hold a read transaction to prevent
checkpoint cleanup, call `consume('used-token','used-execution',...)`, and verify
from a separate connection that both committed claims are visible. Exit with
`os._exit(0)` to simulate a process crash without SQLite close/checkpoint cleanup.
The remaining WAL is 8,272 bytes. Flip one bit in its last byte. Ordinary store
initialization succeeds; `PRAGMA integrity_check` returns `ok`; the claims count
is zero; consuming the identical token and execution key succeeds again. The
parent implementation reproduces the identical outcome.

This requires prior WAL configuration and post-commit WAL corruption. It does not
require a replacement database, namespace changes, schema changes, or deleting
the claims table. The probe deliberately injects a one-bit fault to make the
corruption deterministic. All receipts remain simulation-only. This is not a
new PR regression; it limits the broad statement that any corrupt state fails
closed. The default DELETE-journal path was not shown to have this particular
failure.

Remediation for the smallest supported scope: explicitly restrict and verify a
supported rollback-journal mode (for example DELETE) before permitting claims,
reject WAL-configured state rather than silently converting recovered WAL state,
and add a crashed-WAL/checksum-corruption regression. Alternatively, demonstrate
WAL recovery completeness with trusted external monotonic/checkpoint evidence.
SQLite structural consistency alone cannot establish rollback resistance. Keep
the existing trusted-storage rollback/replacement limitation explicit.

3. Medium contextual finding — real-clock expiry is checked before a potentially blocking consume, not before the receipt (pre-existing).

Exact unchanged caller: `cerberus/enforcement.py:110-117` captures `execution_time`
and checks expiry, calls durable consume, then uses that old timestamp in the
receipt without reading the clock again. The new full integrity scan increases
this interval, and the existing two-second write-lock wait already exposes it.

`probe_sqlite_second_review.py` creates a real currently valid envelope and genuine
one-second token, registers it while valid, and calls the gateway with `now=None`
while another connection holds `BEGIN IMMEDIATE` for 1.25 s. No frozen clock or
token mutation is used. Latest result:

- Call starts: `2026-11-11T23:30:40.245195Z`.
- Token expires: `2026-11-11T23:30:41.239540Z`.
- A successful simulated receipt returns: `2026-11-11T23:30:41.589069Z`.
- Receipt's `executed_at`: `2026-11-11T23:30:40.246014Z`.

The receipt is returned 0.349529 s after expiry. This contradicts a literal claim
that expiry is rechecked at the enforcement commit point. In this prototype there
are no actual connector side effects, so the demonstrated consequence is an
expired simulated authorization/receipt. The expiry placement is unchanged
between the parent and PR.

Remediation: after successful consume, read the real clock again and refuse the
receipt if expiry has been reached; retain the consumed claim on refusal to
preserve at-most-once behavior. Use the refreshed timestamp for the receipt.
For injectable clocks, prefer a callable clock source over treating a single
caller-provided timestamp as advancing wall time. Add a contention/expiry control
that retains a valid unexpired positive case.

Other examined boundaries and evidence:

- Atomic conflict rollback passed: an execution-key conflict after inserting a
  fresh token does not consume that fresh token; it can be used with another
  execution key. A reopened store still rejects used tokens.
- Eight separate processes racing the same token/execution produced exactly one
  acceptance and seven `ReplayDetected` outcomes.
- Static final-component symlinks are rejected by the patch. A deterministic
  lstat/open race can make initialization accept a symlink installed between
  those operations. The following ordinary claim rechecks lstat and rejects it.
  This requires modification of the trusted path and is not an independently
  demonstrated authority bypass within the stated threat model.
- Restoring a previously valid empty snapshot allows replay. This requires trusted
  storage replacement and is explicitly excluded by `docs/ASSURANCE_BOUNDARY.md`;
  it is not a new finding against the patch.
- Guardian only claims after assurance gates, maps `StateUnavailable` to denial
  without a token; gateway maps state/replay errors to `EnforcementDenied` before
  appending a receipt. Authority registry lock/revocation ordering is unchanged.

Commands that completed successfully:

```sh
env PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/379e5a226cc0/venv312/bin/python -m pytest -p no:cacheprovider --basetemp=/workspace/scratch/379e5a226cc0/ai-review/pytest-tmp tests/test_state_initialization.py tests/test_assurance_hardening.py -q
# 82 passed in 9.24s

env PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/379e5a226cc0/venv312/bin/python /workspace/scratch/379e5a226cc0/ai-review/probe_sqlite_second_review.py

env PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/379e5a226cc0/venv312/bin/python /workspace/scratch/379e5a226cc0/ai-review/probe_wal_recovery.py

git status --porcelain=v1
# empty output in the reviewed worktree

git diff --exit-code f0ebd38c58e9d40af35d35c5cc32b5614eb60439 6fe417400ff4844d7647dddd9435288c3485ffc0 -- cerberus/guardian.py cerberus/enforcement.py cerberus/authority.py
# no changes
```

Environment: Linux x86_64/glibc 2.41, Python 3.12.14, SQLite 3.53.1, pytest 8.3.5,
jsonschema 4.23.0, cryptography 50.0.1, rfc3339-validator 0.1.4. The default runtime
lacked pytest; the existing venv was used. An initial test attempt used a missing
temporary-directory parent and consequently had fixture setup errors; after
creating that parent outside the worktree, the complete focused rerun passed.

Limits: single Linux host and SQLite build; fault injection does not establish
real-world frequency; no power-loss/hardware fsync or network filesystem tests;
no distributed guarantees; no real connector effects. No external reviewer was
contacted. A later requested examination of replay_v4 runner code will be a
separate post-review exposure and must not be represented as preregistration or
blind/independent human validation.
