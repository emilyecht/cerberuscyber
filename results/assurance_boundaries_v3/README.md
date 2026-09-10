# Request-bound assurance result

Measured code commit: `9845d1ec92e03df5522d505f74ba3ac87e2f51f3`.

| Measure | Observed |
| --- | ---: |
| Unsafe requests receiving usable authority | 0 / 11 |
| Eligible exact simulated receipts | 8 / 8 |
| Extra simulated receipts across lifecycle episodes | 0 / 3 |
| Measurement errors | 0 |

The complete [measurement](after.json) records each observation and source/corpus
hash. The combined suite passes 201 tests locally. New evidence proofs bind the
complete request; six added regressions exercise cross-request transfer with
eligible newly signed counterparts and refusal of legacy observation-only proofs.

Separately, the [post-merge v1 run](../guardian_authorization_v1/main-after-pr8.json)
pins main at `d9e58ecc2443e237c685e8510f864a343913723e` after merging #9 and #8.
It reproduces the original repaired result: 59 cases, 0 measurement errors,
0/22 existing-contract failures, 11/11 extended-assurance failures and 8/8 eligible
responses. The historical complete evidence packet and explicit non-claims remain
unchanged. Full-request attestation implementation is in PR #10, not yet merged.

V3 uses new request-bound signatures and explicit operator trust/shared state.
Its envelope values match v2, but its authentication inputs differ. V1's raw-wire
runner is not compatible with the new positive-control preconditions. Do not label
setup errors as defenses or combine these instruments into an overall security score.

All tests are selected, project-authored simulations. No real attack was stopped;
independent/adaptive evaluation, trusted-producer compromise, online revocation,
distributed state and production recovery remain open. See the
[method](../../benchmarks/assurance_boundaries_v3/README.md) and
[assurance boundary](../../docs/ASSURANCE_BOUNDARY.md).
