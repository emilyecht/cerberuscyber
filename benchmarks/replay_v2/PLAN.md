# replay_v2: frozen Kernel binding and live-authority plan

This plan is committed before implementation or v2 measurement. The starting
point is replay_v1 at upstream commit `48eefd82cee2c47c5ffc4f79de392ce3b0049ffe`
(tree `01ecf6493d4aec1f2a5bfb3963523e68d705a099`). Its recorded result is FAIL.

## Fixed inputs and forbidden changes

Use seed **20261104**, the same 135 labelled requests from 125 setups, the same
public fixture trust, clocks, sequences, baseline threshold and scoring functions.
Import v1's generator, oracle loader, receipt validator, decision baselines and
summary/scoring functions unchanged. Do not copy-edit their labels or behavior.

| Input | Required SHA-256 |
|---|---|
| v1 oracle file, inherited directly by v2 | `c73ef6ac1eead1efc7c97e3fd02c2f55893713ee3ce0b5d79373587139c58487` |
| v1 generated canonical corpus, inherited by v2 | `f4df28a32efa9cb011d6992788291aa022f781a8f7e2befd727a3a277007ff8a` |
| v1 generator | `7e81044082c5b33c07b2486a53bd1a2ed8ac2532c6c9d9edabad31a271733749` |
| v1 runner / inherited scoring | `dcf7c1ab8694a277bf8bc6bae70d55b16efd02680c3bcaf555f32de22e659717` |

Before replay, print both v1 and v2 oracle hashes and both corpus hashes. Compare
the current files and regenerated inputs with these constants and v1's recorded
result; abort with an invalid-measurement status on any disagreement.

Never edit `benchmarks/replay_v1/**`, `results/replay_v1/**`, or
`tests/test_replay_v1.py`. Guardian logic, both policy copies, envelope contract
and schema, corpus generator, oracle labels and scoring rules remain unchanged.
No change may identify a case ID, variant, seed or benchmark in production code.
No policy reasoning, new action capability or operational connector enters Kernel.

## Enforcement change

The token already commits to the complete approved ActionEnvelope digest. Keep
that issuance contract and recompute/compare the full digest at enforcement.
Require the actual expected envelope for every gateway call; missing, malformed,
changed or unverifiable input fails closed. Retain signature, key, expiry, exact
action/target/scope and one-time replay checks. Binding includes incident,
reversibility, mission impact, actor, nonce and issuing policy version.

Add a small trusted in-process token-authority registry, consulted live during
enforcement. A trusted issuer/controller explicitly registers a genuinely issued
token, its fingerprint, purpose and upstream authority-key dependencies; requests
cannot register themselves. Unknown, revoked, wrong-purpose, mismatched or
unavailable status refuses execution. Explicit token and authority-key revocation
updates affect already-issued tokens. Use a lock spanning status verification
and receipt/replay commit so revocation has an explicit linearization boundary.
This is not a network revocation service, durable registry, distributed consensus
or key-compromise defense. After registry loss, unknown authority fails closed.

Revocation events in replay are derived generically from the input trust
configuration's revoked key IDs, never case names or expected labels. Register
only the original approved setup/current approved token with the original proof
key dependencies. Do not re-sign attacks. The observer supplies each full request
to the strict gateway without filtering decisions using the oracle.

Existing non-benchmark callers and test fixtures may receive only the context and
registry plumbing needed by the strict interface; their policy/assertions remain
intact. Frozen v1 instrument tests target their pinned original source tree, with
the original failing safety gate explicitly retained as historical FAIL. Current
tests enforce v2's zero-violation gate. No unbound compatibility fallback is allowed.

## Pass criteria and failure reporting

- Zero unsafe full-pipeline authorizations and zero invariant violations.
- All 25 legitimate requests still succeed; zero new false denies.
- No change to raw Guardian verdicts, input-schema refusals or Kernel-only cases
  relative to the saved v1 observations.
- Identical oracle/corpus/scoring inputs; all old v1 files remain byte-identical.
- Every disagreement, invalid measurement and remaining failure is listed with
  its reason, not repaired by adjusting labels, policy or scoring.

Use v1's numerator/denominator definitions and N/A handling. Preserve all its
per-class, overall, observation and failure fields; add v1/v2 comparison, B2,
latency and observed simulator-state records. Baseline failures are comparisons,
not reasons to disable the CERBERUS gate. Invalid measurements exit 2; CERBERUS
failures, new false denies or changed Guardian verdicts exit 1.

## B2: fixed SOAR-style comparator

In addition to the unchanged v1 baselines, B2 checks the original setup token's
signature/expiry, a fixed allowlist and exact requested action/target/scope
against that grant. The allowlist is `revoke_sessions:single_identity`,
`isolate_endpoint:single_endpoint`, `temporary_egress_hold:single_workload`, and
`quarantine_workload:single_workload`. Missing/expired/invalid tokens and
unlisted/incompatible/broader requests deny; otherwise approve. It checks no
evidence independence, full-envelope digest, impact/reversibility/incident
context or live revocation. It is decision-only and receives the same cases,
clock and labels. Define it once here; never tune it after measurement.

## Simulator-state observations

Maintain a separate in-memory resource-state map for the measured request path.
Apply every accepted simulated receipt before grading; never gate mutation on an
expected label. Observe before/after maps independently. Count changed resources
and classify them against the original authorized request context; non-approved
requests have no authorized mutation scope. Report total, authorized and
out-of-scope mutations, by class and overall, plus every changed key. Isolated
setup controls and latency repetitions are separate worlds and not added to the
135-request functional totals. These are model-state observations, not host,
network, account or filesystem effects.

## Fixed latency protocol

Compare the frozen original gateway source with the hardened gateway on the
same host, inputs, original/current tokens and logical execution times. Preserve
the original source as a hash-verified benchmark reference; never modify v1.
For each of 135 requests: **20 warmup pairs**, then **100 measured pairs**.
Alternate old/new order by repetition parity. Construct fresh isolated replay
caches/gateways outside the timer; issuance, fixture generation, revocation
updates and state-map grading are also outside it. Time only the enforcement
call with `perf_counter_ns`, including normal verification, binding, status,
replay and receipt/audit work. Refusals are timed too, not dropped.

Report p50/p95/max for old and new calls and paired new-minus-old differences,
per request, class and overall, with an additional matched legitimate-allow
subset. Mixed outcomes are explicitly labelled: an old allow/new deny is not
equivalent useful work. Use nearest-rank percentiles; retain negative differences
and all samples. Record CPU, architecture, OS, Python and dependency versions.
Latency is observed, varies across runs and is not part of deterministic decision
hashes. Fixed inputs make decision/state outcomes repeatable, not wall time.

## Validation and claims

Test full-digest mismatch, changed incident/impact/reversibility/scope, unknown and
revoked tokens, wrong purpose, missing/unavailable registry, missing envelope,
replay, and successful unchanged requests. A removed check must cause its tests
to fail. Run current regression tests with interface plumbing only; separately
verify the unchanged historical v1 checks against their original implementation.
Show `git diff --stat` for protected v1 paths and verify content hashes.

The report and README must link both versions, leave **v1 FAIL** visible, and
state: synthetic replay in a simulator, labels derived from this repository's own
documents, not field validation; baselines are simplified stand-ins. Claim only
observed fixture results. No system-security, independent-validation, production,
real containment, rollback or distributed/durable revocation guarantee is made.
