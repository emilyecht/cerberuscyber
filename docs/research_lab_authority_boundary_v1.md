# Local marker authority boundary review version 1

Reviewed 21 November 2026. Base is PR #20, commit
`c5fad3b3dc3fe5e214b143f9d43142d5466ac358`. This followup does not change the
implementation measured by replay v4 or any frozen oracle, benchmark or result.
CERBERUS Cyber remains a TRL 2-3 defensive research prototype.

## Findings and changes

The temporary-marker broker passed a captured `now` into the gateway. That
prevented PR #20's post-consumption clock check from observing elapsed real time.
The broker also released the registry lock after the simulated receipt and before
the marker write, allowing revocation to finish before the actual effect. Missing,
zero-byte and corrupt state raised an uncaught exception instead of a controlled
broker refusal. The exceptions did not authorize a write.

The broker now holds the same process-local registry RLock through authorization,
the temporary marker write and its audit append. It lets the gateway sample real
time, verifies token time again immediately before the marker write, and returns
a controlled refusal for authority-status and state-unavailability failures.
Claims consumed before expiry refusal stay consumed. A simulated receipt in the
audit chain does not prove that an effect occurred; `lab.marker_written` records
the separate observed effect.

## Regression evidence

`tests/test_lab_authority_boundary.py` has seven cases. Against unchanged #20,
six fail and one passes: two expired-effect cases, revocation ordering, and three
state-unavailability cases fail; pre-revoked authority already blocks the effect.
The same seven pass with this repair. Tests use deterministic advancing clocks
and bounded thread coordination, with no kernel-confinement claim from mocks.

`tests/test_durable_process_boundary.py` adds three real SQLite cases: eight
independent OS processes contend for one execution with one consumed claim and
seven replay refusals; a conflicting second insert rolls back the first token
insert; abrupt process death before commit preserves earlier committed replay
claims. These exercise trusted single-host state, not power-loss durability or
transactional external execution.

The focused existing-plus-new selection passed 146 cases with one unavailable
Landlock skip before the three process tests were added; the three process tests
then passed separately. The first broad run had 334 passes, one failure and one
Landlock skip because the older benchmark deliberately refuses uncommitted
production source. That result is retained; the clean-commit rerun must be reported
separately. No source pin was changed to bypass that refusal.

## Reproduce

```sh
python -m pip install -r requirements-dev.txt -r requirements-build.txt
python -m pytest -q tests/test_lab_authority_boundary.py tests/test_durable_process_boundary.py
python -m pytest -q --ignore=benchmarks/replay_v3/test_instrument.py
python -m cerberus.evaluation enforcement-demo --json
```

Use a clean committed tree for the broad suite. The original full workflow still
rejects repaired state through the frozen v3 source pin. Run that historical
instrument on `f0ebd38c58e9d40af35d35c5cc32b5614eb60439`; do not relax its pins.
The post-repair workflow now also triggers on broker and new regression changes.

## Remaining boundary

The clock check samples wall time immediately before a Python file syscall; it
cannot make wall-clock expiry atomic with filesystem completion. The registry,
broker, signer, clock, parent directory and all revocation delivery remain
trusted. A stalled write or audit can hold up revocation; no hard latency bound is
established. Claims, file effects and audit are not one atomic transaction.
Rollback, schema-valid history erasure/replacement, hostile path races, durable
registry recovery and crash reconciliation remain open. The gateway's optional
`now` is a trusted simulation interface and must not be exposed to a worker.

Local Landlock probing on this host returns ENOSYS. That is unavailable, not a
successful enforcement demonstration. A supported-host CI run must independently
execute the unchanged 14-case lab with five actual syscall refusals and one
authorized temporary marker write. No operational containment is implemented.

Review provenance is an AI-led review and local tests; no independent human
approval or external validation is asserted.
