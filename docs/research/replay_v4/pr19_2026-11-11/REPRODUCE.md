# Reproduce the evidence package

Use a full Git clone, a Linux non-root identity with no effective capabilities,
Python 3.10 or 3.12, and the checked-in dependency requirements. Install dependencies
before evaluation; the evaluation process itself blocks Python socket networking.
Permission fixtures on a host that cannot establish OS denial are invalid, not passes.

```sh
git clone https://github.com/emilyecht/cerberuscyber.git
cd cerberuscyber
git switch eval/replay-v4-evidence
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt -r requirements-build.txt
.venv/bin/python benchmarks/replay_v4/restore_local_commits.py
.venv/bin/python benchmarks/replay_v4/run.py --verify-inputs-only
.venv/bin/python benchmarks/replay_v4/verify_results.py results/replay_v4/pr19_2026-11-11
.venv/bin/python benchmarks/replay_v4/verify_results.py results/replay_v4/pr19_2026-11-11_v2
.venv/bin/python -m pytest -q --ignore=benchmarks/replay_v3/test_instrument.py
.venv/bin/python benchmarks/replay_v4/run.py --output-dir /tmp/replay-v4-reproduction
```

The first recorded artifact is deliberately INVALID_MEASUREMENT, not a successful
benchmark. Its two setup failures and complete observations remain available.
The second artifact is a separate complete rerun using corrected instrument v2.
Both use the identical frozen oracle and original PR #19 implementation.
The final result report states the observed gate and every ambiguity; this guide
does not presume a passing benchmark. A fresh run may take roughly 15 minutes on
the measured host because each locked-store repetition retains a two-second
timeout and every episode is rebuilt for 5 warmup plus 20 measured repetitions.

The fixture seed is 604279153. Signer token IDs use UUIDs, clocks/timings and SQLite
file bytes vary between executions. Reproduce the functional observations,
request/corpus hashes and invariants, not byte-identical newly measured JSON.
Recorded gzip bytes and decompressed JSON have separate complete SHA-256 hashes.

## Exact commit and publication provenance

The CLI lacked GitHub push credentials. The connected GitHub app published commits
with connector-generated author/time/parent metadata while preserving every tested
Git tree exactly. `publication_map.json` maps local measurement commits to published
commits and shared tree IDs. `local_commit_objects.json` contains the exact original
commit object text and SHA. `restore_local_commits.py` validates and writes those
immutable objects into the local Git object store; it does not change a checkout,
branch, source file or oracle. Full clone history supplies the identical referenced
trees. This makes the original runner SHAs in recorded environment metadata directly
inspectable without pretending publication timestamps preceded measurement.

The original oracle/repair commits already existed on GitHub and are unchanged.
Freeze `93f70d4603d06d323675456f90f2629b6b0d3b52` and first repair
`7a386eaa1bc4bf96e600c846def848158276f285` are sibling children of v3 head
`f0ebd38c58e9d40af35d35c5cc32b5614eb60439`. Freeze timestamp precedes repair
timestamp, but the freeze is not an ancestor of repair. This does not prove an
externally trusted chronology or blindness. The new integration commit has the
original frozen branch and original PR #19 repair as parents before runner work.

## Historical checks and separate fixes

The original full `python -m pytest -q` rejects changed `state.py` through v3's
historical source pin. Do not edit that pin. To validate the historical instrument:

```sh
git worktree add --detach /tmp/cerberus-v3-history f0ebd38c58e9d40af35d35c5cc32b5614eb60439
cd /tmp/cerberus-v3-history
/absolute/path/to/cerberuscyber/.venv/bin/python -m pytest -q benchmarks/replay_v3/test_instrument.py
```

The original historical v3 benchmark gate remains FAIL (9/3,484 false allows),
including its seven documented oracle defects. Passing its instrument tests is
not a claim that its safety result passed. v1/v2/v3 corpora/oracles/results and
their source pins are preserved byte-for-byte. A protected-path diff is retained.

Draft PR #20 / `fix/sqlite-review-followups` adds the WAL-mode restriction and
post-consumption clock check. It is not the v4 target and has separate tests/CI.
Original review probes can be run with host-path relocation only:

```sh
.venv/bin/python benchmarks/replay_v4/reproduce_reviews.py wal --target . --output-dir /tmp/cerberus-wal-review
.venv/bin/python benchmarks/replay_v4/reproduce_reviews.py sqlite --target . --output-dir /tmp/cerberus-state-review
```

The second command creates a temporary large synthetic database to reproduce the
integrity-scan capacity finding. Use a checkout of the followup branch as `--target`
for the `followups` probe. Original probe files and original-output hashes are
retained unmodified; the launcher only relocates ROOT and OUT in a temporary copy.
