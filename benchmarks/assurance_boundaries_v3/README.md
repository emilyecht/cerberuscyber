# Request-bound assurance assessment v3

V3 preserves all 19 envelope values from v2 but creates new signatures using
`cerberus.evidence.v2`, which binds each observation to the complete request.
Approval proofs still bind the complete request. Historical v1/v2 requests,
instruments and result packets remain unchanged in their directories.

Run `python benchmarks/assurance_boundaries_v3/prepare.py` to reproduce this
project-authored public-key fixture corpus. No key here is an operational credential.
Run `python benchmarks/assurance_boundaries_v3/run.py --target . --output
results/assurance_boundaries_v3/after.json --fail-on-violation` against committed code.
The runner records all 19 request outcomes plus three lifecycle episodes, source
hashes, exact target commit, corpus hash and instrumentation failures.

V3 is a configured-boundary diagnostic with new authentication inputs and shared
SQLite, not the unchanged raw-wire v1 benchmark. The original v1 runner cannot
supply valid authenticated setup to v1.2 code; failed setup must not count as
successful defense. New full-request evidence transfer tests and legacy-profile
rejection are in `tests/test_assurance_hardening.py`.

Review [trust assumptions, migration and residual risks](../../docs/ASSURANCE_BOUNDARY.md).
All receipts are simulated. No independent, held-out, continuous or adaptive
evaluation, real containment or overall security percentage is claimed.
