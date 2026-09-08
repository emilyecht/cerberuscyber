# Assurance boundaries v2

Project-authored, selected-corpus diagnostic. Not an independent or held-out evaluation.

`source-requests.json` preserves 19 exact envelope values and their input hashes from
the frozen v1 reviewer packet: 11 unsafe freshness/approval/evidence cases and eight
eligible controls. It records the source commit, corpus hash and external-fact labels.
`prepare.py` adds explicit operator trust and public test attestations in `cases.json`.
Each case discloses how its proofs were constructed. Three additional lifecycle
episodes exercise a new gateway, an actual fresh Python process, and a new Guardian.

This compares **configured boundaries**: the old v1.1 implementation consumes raw
envelopes with default memory state; v1.2 uses authenticated sidecars and shared
SQLite. It is not an unchanged-wire-only comparison. New trust fixtures and lifecycle
episodes extend the instrument; do not replace or relabel v1's original results.

## Reproduce

Install `requirements-dev.txt`, commit target production sources, and run from this
repository. Use a separate checkout of PR #8 commit
`651bd4a465661c7c54d58d3c60c279338b727c4f` for BEFORE.

```bash
python benchmarks/assurance_boundaries_v2/prepare.py
python -m pytest -q
python benchmarks/assurance_boundaries_v2/run.py --target /path/to/before --output results/assurance_boundaries_v2/before.json
python benchmarks/assurance_boundaries_v2/run.py --target . --output results/assurance_boundaries_v2/after.json --fail-on-violation
```

The runner launches a fresh interpreter for the target. Outputs include target
commit/tree, production-file hashes, policy/corpus/runner hashes, interface,
individual decisions, exact-action token/receipt checks and lifecycle outcomes.
Temporary state is isolated per case. Unexpected measurement errors invalidate
summaries and exit nonzero; they do not count as controlled refusal. The optional
failure flag also rejects unmet security or eligible-control expectations.

Eight legitimate controls must still produce exact, verified simulated receipts;
a deny-everything implementation fails. All effects are simulated. Public fixture
keys are not operational credentials. See [trust assumptions and residual risks](../../docs/ASSURANCE_BOUNDARY.md).
