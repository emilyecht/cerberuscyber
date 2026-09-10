# Post merge evaluation of PR 11

PR #11 was reviewed and merged on 2026-09-10. The [raw rerun](main-after-pr11.json)
measures main code commit
[`59c6a29ac40448fe8c897dc5249c3f32e3e716cb`](https://github.com/emilyecht/cerberuscyber/commit/59c6a29ac40448fe8c897dc5249c3f32e3e716cb),
tree `0a94c972df9762ea4d6b36dc14c92d73f5a2762d`. Subsequent commits recording this
result change evidence/documentation only, not the measured production sources.

## Review and validation

The review examined request-bound signatures, freshness/expiry, issuer provisioning
and independence, exact policy/token bindings, post-approval action/scope checks,
durable replay claims, installed-package boundaries and evidence preservation.
No blocking issue was found for the explicitly simulation-only evaluation scope.
This was a project review, not an independent security audit. Known operational
limitations remain in [the assurance boundary](../../docs/ASSURANCE_BOUNDARY.md).

The exact PR head `13d3e2fd19f0f1baedc19e297b2c75e904acfac7` passed 222 local tests
before the guarded merge. Main passed the same **222 tests** after merging
(Python 3.12.14). [Main CI run 34427623770](https://github.com/emilyecht/cerberuscyber/actions/runs/34427623770)
passed on Python **3.10 and 3.12**, including the benchmark, building source/wheel
distributions and isolated installed-wheel verification. The original v1/v2/v3
packets and grant proposal were preserved.

## Observations on merged code

| Check | Candidate code | Merged main code |
|---|---:|---:|
| Unsafe requests receiving authority | 0 / 11 | 0 / 11 |
| Eligible requests with exact simulated receipts | 8 / 8 | 8 / 8 |
| Duplicate receipts across three lifecycle episodes | 0 | 0 |
| Measurement errors across 22 observations | 0 | 0 |

Candidate code is pinned at `64f08221a8f919cece4fa3554c000a3804ca9e64` in
[after.json](after.json). The main rerun has identical production-source, corpus,
runner and policy hashes. All per-case expectations were met. The result is now
reproduced on merged code; the merge itself does not reduce the already-zero
selected-case failure counts.

| Current assurance family | Unsafe authorizations | Selected request IDs |
|---|---:|---|
| Evidence freshness | 0 / 4 | F01 through F04 |
| Approval authenticity | 0 / 4 | H01 through H04 |
| Evidence authenticity | 0 / 3 | E01 through E03 |

Each replay episode first obtained a valid authorization and simulated receipt.
A new gateway, fresh process and new Guardian then each refused duplicate authority
or execution. Positive controls are necessary: a blanket refusal is not a pass.

## Reproduce and interpret

Check out the named main code commit and install `requirements-dev.txt`, then run:

```bash
python -m pytest -q
python benchmarks/release_candidate/run.py --target . --output /tmp/cerberus-main-after-pr11.json --fail-on-violation
```

The experiment was run on 2026-09-10; its fixed simulation clock remains
`2026-09-07T12:00:00Z`. It contains 19 selected requests and three lifecycle
episodes, not 22 independent attacks. Token/receipt IDs vary between reruns.
Production-source SHA-256:
`9e1411dd0376c8c0f6bdfe67e7566b790f18da4ab81b65a2f79dc16cd97a2f60`.
The raw file also records individual source hashes, request hashes and receipts.

Historical v1 measurements use a different interface and trust setup. Their
26/33 to 11/33 repair result must not be joined to the current 0/11 result as one
continuous security score. Request attestations bind a policy version; resulting
tokens/receipts bind exact evaluated policy bytes. Trusted issuer configuration,
clock, HMAC keys and single-host state are still assumptions.

No operational attack was detected or stopped by these tests. No independent,
held-out, continuous/adaptive evaluation, real containment, distributed/rollback-
resistant state, live revocation, field false-positive rate or production readiness
is claimed. This merge did not deploy a connector or publish a package registry release.
