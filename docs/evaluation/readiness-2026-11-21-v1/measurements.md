# Measurements and preserved chronology

All measurements are project-authored synthetic evidence or bounded local lab
observations. Fresh reproduction in this session is AI-led; it is not an
independent third-party assessment. Counts from different instruments are not
combined into a single security score.

## Automated tests and artifact checks

| Source or check | Result observed this round | Meaning |
| --- | --- | --- |
| Cyber default main c6894a5 | 257 passed, 1 skipped | Existing suite; Landlock unavailable locally |
| PR 20 c5fad3b current-source selection | 325 passed, 1 skipped | WAL/expiry followup with frozen v3 instrument run separately |
| PR 19 source plus PR 21 instrument | 335 passed, 1 skipped | Current-source selection on exact #21 tree |
| Historical v3 instrument on f0ebd38 | 10 passed | Instrument checks, not a passing historical safety gate |
| New broker tests against unchanged #20 | 6 failed, 1 passed | Demonstrates the new regression tests catch the repaired gaps |
| New focused broker/storage/authority selection | 146 passed, 1 skipped | Before adding three OS-process tests |
| Three new OS-process/atomicity cases | 3 passed | One of eight competing processes consumes the execution; prior committed claims survive process death |
| PR 22 clean local committed tree d14ad52, identical published tree d03ed58 | 335 passed, 1 skipped | Corrected current-source source validation |
| PR 22 initial dirty-tree broad run | 334 passed, 1 failed, 1 skipped | Older benchmark refuses uncommitted production changes; retained separately |
| PR 22 unmodified full historical-inclusive suite | 338 passed, 1 failed, 6 errors, 1 skipped | Frozen v3 source pin rejects repaired state/enforcement/broker; retained integration blocker |
| PR 22 supported-host CI at d03ed58 | 336 passed per Python 3.10 and 3.12; historical instrument 10 passed per job | Same current-source selection, with native Landlock integration available |
| PR 22 native enforcement CLI at d03ed58 | 14/14 cases, 5 kernel refusals, 1 authorized marker write, 0 unauthorized resource changes, both Python jobs | Host-specific real filesystem enforcement demonstration |
| Combined contract at d03ed58 | 22 cases, 0 measurement errors, 0/11 unsafe authorizations, 8/8 eligible successes, 0 duplicate effects, 3 lifecycle episodes | Separate synthetic instrument, not v4 |
| Local source/wheel build at d03ed58 | Both built successfully | Distribution generated; existing setuptools data-directory warning retained in log |
| Local isolated installed portable demo | 4/4 cases | Source checkout excluded by isolated Python invocation |
| Local full installed verifier | Stops with Landlock unavailable | Not a full pass; source imports/portable demo ran before native-lab requirement |
| Protocol initial main 48e62fd | 13 unittest methods passed | Existing implemented Boolean slice |
| Protocol PR 7 at 47cc290 | 16 unittest methods passed locally; green Python 3.10/3.12 CI | Ten original hand calculations, 60 seeded DAGs, new three-layer model and hash-seed checks |

The later PR 22 workflow-only commit `7f0174e14c710cd1d3834fc57af3e05ea110f37f`
adds clean installed-wheel verification on a supported host. Its production Python,
policy, schema and test files are identical to d03ed58. Its final supported CI passes on Python 3.10.22 and 3.12.16: 336 current-source
tests, 10 historical instrument tests, 14 native lab cases, both builds and an
isolated installed-wheel verifier with four portable plus 14 lab cases per job.
The original historical-inclusive workflow remains red. Exact check URLs and
filtered job-log evidence are recorded in `ci_evidence.json` and the logs.

## Frozen replay v4 reproduction

Original measured implementation: **6fe417400ff4844d7647dddd9435288c3485ffc0**.
Fresh runner/source: **94c5b746100bf82ad1d405cef0ef348c56667e4f**. Runner SHA-256
`1bb4b9250032f51b7d4c558e770cfd24dc4a63e3d31960342b6d011efa760521`.
Oracle SHA-256 `18539d829f7f95ef0a3e93bde607b253b76b15085c184816b862574c48b217a0`.
Seed 604279153; fixed logical time 2027-02-16T04:30:00Z. Measurement ran
21 November 2026, 05:55:26 to 06:08:10 Central Standard Time.

The fresh complete run and complete artifact verifier both pass: 1,005 episodes,
1,100 primary attempts, 1,078 scored, **0/878 false allows**, **0/200 false
denies**, zero invalid setups, zero scored invariant labels and zero repeated
outcome mismatches. False allow means allow on a frozen deny/escalate attempt;
false deny means any non-allow on a frozen legitimate allow. Exact decision
correctness also distinguishes deny and escalate.

The three unchanged decision-only baselines independently recalculate all 1,100
decisions each: allow-if-recommended 878/878 false allows; confidence 0.9 878/878
false allows and 1/200 false denies; SOAR B2 780/878 false allows. They have no
measured durable-effect pipeline; their unmeasured invariants are not zero.

Every episode is rebuilt for five warmups and 20 measured repetitions. There are
20,300 actual gateway-call timing samples; constructor refusals have no fake
zero-latency gateway call. New p50 is 0.619094 ms, p95 0.934239 ms and maximum
2010.849662 ms. Original recorded p50 0.961535 ms, p95 1.961274 ms and maximum
2117.932558 ms remain historical measurements. No speedup conclusion follows:
hardware, filesystem and scheduling differ, validation overlapped measurement,
and no affinity, frequency or host-load control was applied.

Fresh environment: Python 3.12.14, SQLite 3.53.1, AMD EPYC 9V74, Linux 6.18.57,
effective UID 1000, pinned pytest 8.3.5, cryptography 50.0.1, jsonschema 4.23.0,
rfc3339-validator 0.1.4. The complete environment, incidental installed packages,
raw nanoseconds, per-attempt observations and hashes are retained. Protocol was
installed as an incidental test package in this developer environment; neither
project acquires a runtime dependency on the other.

W is a source-derived set of 25 correlated parents, not 725 independent trials.
Overall rates and confidence intervals are descriptive for these fixtures, not
field failure probabilities. The public oracle and repair had prior-failure
exposure. This is a post-repair challenge, not a blinded generalization claim.

## All documentary ambiguities

| Frozen attempts | Count | Fresh reproduced observation | Interpretation |
| --- | ---: | --- | --- |
| S-031.s1, S-032.s1 | 2 | Denied healthy-target symlink opens | Docs did not define a general symlink contract |
| T-041.s2 through T-045.s2 | 5 | Unused original grant allowed after exact preexecution snapshot restore | No historical-completeness authentication established |
| T-046.s2 through T-050.s2 | 5 | Duplicate receipt after consumed-history erasure | Five replay-history violations and five out-of-scope symbolic mutations; concrete unresolved failures |
| U-K-026.s1 through U-K-030.s1 | 5 | Denied future-issued tokens | Exact not-before versus documentary time/skew boundary |
| V-041.s1 through V-045.s1 | 5 | Denied malformed tokens | Legacy fixture/trust-migration ambiguity |

All 22 remain outside the frozen accuracy score. All-primary symbolic writes are
210, including the five duplicates and five unused-grant restore effects; scored
symbolic writes are 200. A symbolic write is a harness-local mutation attached to
a simulated receipt, not operational containment. None of the 22 is silently
relabeled as a defensive success.

## Invalid first run and historical failures

The complete original instrument-v1 artifact remains **INVALID_MEASUREMENT**:
S-023.s1 and S-024.s1 did not establish the intended permission fixture. Its valid
subset had 0/876 false allows and 0/200 false denies, with two invalid attempts
and 22 ambiguities. The corrected instrument verifies O_RDWR denial for the
unchanged write-only mode bits. It changes no oracle label, mode bit, baseline or
production implementation. Both original artifacts and original measurement
commit objects were verified again this round; only the corrected full run may
be described as the complete recorded pass.

Fresh historical v3 **functional-only** execution on f0ebd38 reproduced 3,540
episodes / 3,625 attempts, 9/3,484 false allows and 0/133 false denies. Seven are
the documented restored-original-request oracle defects; two expose the zero-byte
initialization defect. All nine remain in the original FAIL gate. No new v3
latency claim is made. V1's 16/110 failure and v2's repaired 0/110 result remain
preserved in their original evidence, not rewritten by this evaluation round.

## Additional storage review

Fresh post-#20 real-clock probing withheld an expired receipt after a blocking
claim and retained the consumed claim; its healthy advancing-clock control
returned a receipt. Corrupt committed WAL artifacts were refused for ordinary
open, existing claim and explicit provisioning; no silent conversion occurred.

At 500,000 synthetic claims (106,364,928-byte DB), full integrity scans had a
0.411330182-second median claim time; an eight-process burst of distinct healthy
claims had six accepts and two unavailable refusals around 2.01 seconds. The
preserved older probe later crashes because it expects the now-repaired expiry
acceptance. This is a partially completed review with a known obsolete assertion,
not a wholly passing probe. Raw output is retained without weakening that probe.
