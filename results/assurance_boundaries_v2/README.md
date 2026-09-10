# Configured-boundary assessment — v2

## Key judgment

The tested configuration closes the exercised freshness, approval-authenticity,
evidence-authenticity and restart/replay paths while preserving all eight eligible
controls. This is a significant local improvement, not a completed defensive posture.

| Measure | Before | After |
| --- | ---: | ---: |
| Unsafe requests producing usable authority | 11 / 11 | 0 / 11 |
| Eligible requests producing exact simulated receipts | 8 / 8 | 8 / 8 |
| Extra simulated receipts across three lifecycle episodes | 3 / 3 | 0 / 3 |
| Measurement errors | 0 | 0 |

Before: `651bd4a465661c7c54d58d3c60c279338b727c4f` (PR #8).
After: `9a400042bc8845572195a791fea1edfaa076a73a`.
Local regression suite: **171 passed** on Python 3.12. These are suite results,
not 171 independent adversarial attacks.

## Evidence and interpretation

[before.json](before.json) and [after.json](after.json) contain every observation,
target/source hashes and instrument identifiers. See the
[reproduction procedure](../../benchmarks/assurance_boundaries_v2/README.md),
[raw requests and attestations](../../benchmarks/assurance_boundaries_v2/cases.json)
and [security assumptions](../../docs/ASSURANCE_BOUNDARY.md).

The 19 envelope values are carried forward from v1. V2 adds project-authored
authentication sidecars, trusted identity/domain configuration and three lifecycle
episodes. Before uses its legacy raw-input/default-memory interface; after uses
verified sidecars and explicit shared SQLite. Consequently this measures a changed,
configured boundary, not an unchanged-wire benchmark or a universal security score.

No actual attack was stopped and no real resource was quarantined. The corpus is
selected and not held out. Continuous/adaptive probing, independently crafted tests,
compromised trusted producers, revocation after issuance, time/storage rollback,
distributed execution and production crash recovery remain unproven. Zero observed
failures here must not be extrapolated to zero operational risk.
