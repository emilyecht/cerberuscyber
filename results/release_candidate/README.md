# Combined evaluation candidate — measured result

Measured on 2026-09-09 against candidate code commit
[`64f08221a8f919cece4fa3554c000a3804ca9e64`](https://github.com/emilyecht/cerberuscyber/commit/64f08221a8f919cece4fa3554c000a3804ca9e64).
**This is a candidate-branch result, not a measurement of current main.** A future
merge requires a rerun pinned to its new main commit. [Raw observations](after.json)
and [local build/test verification](verification.json) accompany this summary.

| Exercised check | Observed result |
|---|---:|
| Unsafe requests receiving authority | 0 / 11 |
| Eligible requests with valid, exactly bound simulated receipts | 8 / 8 |
| Additional receipts across three restart/replay episodes | 0 |
| Measurement errors | 0 / 22 observations |
| Local unit/regression tests (Python 3.12.14) | 222 passed |
| Installed-wheel demo cases | 4 / 4 |
| Original reviewer-packet files checked byte-for-byte inside the sdist | 85 / 85 |

The 22 observations are 19 requests plus 3 lifecycle episodes; they are not 22
independent attacks. All expected outcomes were met. A zero result on these
selected fixtures is not proof of zero operational risk. No real containment,
independent review, held-out or adaptive campaign, field false-positive estimate,
overall security percentage, or production readiness is claimed.

## Reproduction and provenance

Use the [combined runner](../../benchmarks/release_candidate/README.md) with the
named clean code checkout. It reuses the exact v3 prepared corpus (SHA-256
`77cf7fa8fdae6eaf9626dd179137d5d309dc06a767f85edb1fa3f6656c9d6d38`).
Every output includes the target tree, production-file hashes, runner hash, policy
hash, individual outcomes and receipts. Tokens/receipt IDs vary between runs.

The policy file hash changed from v3's
`513e7cf4aeab40ee0b0a994fcfbc9e952aba562d85e49bbc92ab9060fe1b0125` to
`8d17f9c8c7fa1a04b026e6cd7e5658427341669b2d56400c35b871a91756ff55`
because strict PolicyBundle schema metadata was added. Behavioral policy rules
were unchanged. The 1.3.0 interface and stronger policy/receipt oracle are explicitly
different from the frozen v3 runner. V1/v2/v3 historical files remain unmodified.

The locally verified wheel was built from the source distribution, installed in
a fresh virtual environment, and exercised with isolated Python from outside the
source checkout. `pip check` reported no broken requirements. Checksums identify
the local verification build only: artifacts are not signed or registry-published,
and byte-identical rebuilds are not asserted.

GitHub Actions [run 34405533707](https://github.com/emilyecht/cerberuscyber/actions/runs/34405533707)
also passed for the code candidate. CI status is attached to its exact head;
subsequent commits must pass their own checks. See the
[release decision and limitations](../../docs/RELEASE_CANDIDATE.md).
