# Combined-contract benchmark — release-candidate-v1

This is a separate runner for DecisionToken **1.3.0**. It reuses the byte-for-byte
prepared [v3 corpus](../assurance_boundaries_v3/cases.json), including trust
configuration and proofs frozen before adversarial changes. It does not replace
or rewrite any v1, v2, or v3 evidence.

## Run

From a clean, committed candidate checkout with `requirements-dev.txt` installed:

```bash
python benchmarks/release_candidate/run.py --target . --output /tmp/cerberus-rc-result.json --fail-on-violation
```

There are **19 requests** (11 ineligible and 8 eligible controls) plus **3 lifecycle
episodes** (new gateway, new process, new Guardian). A fresh interpreter imports
the named target. Per-case failures of the measurement apparatus are errors, not
successful defenses. A receipt must be simulated, side-effect-free and exactly
bound; lifecycle refusal is counted only after a successful initial authorization
and simulated execution. The corpus is selected and deterministic, not an
independent holdout or a continuous/adaptive adversarial campaign.

Output records raw observations, commit/tree, production-file hashes, policy hash,
runner hash and corpus hash. No overall security score is calculated. Fixed
assessment time and public benchmark credentials are fixture controls, not real
sensor authentication or production signing material.

## Difference from v3

The request/proof bytes and evidence-v2/approval-v1 signing profiles are unchanged.
The accepted token contract now requires **both policy and assurance digests**.
The receipt oracle also checks the signed policy/identity bindings; approved
tokens are checked against an independently computed canonical policy digest.
The target policy adds strict PolicyBundle `schema_version: 1.0.0` metadata, which
changes its file hash but not its behavioral rules. These are material interface
changes and are explicitly recorded in the result's benchmark name and limits.

For corpus generation and specific requests see the
[frozen v3 methodology](../assurance_boundaries_v3/README.md). See
[release contract](../../docs/RELEASE_CANDIDATE.md) for the residual trust assumptions.
