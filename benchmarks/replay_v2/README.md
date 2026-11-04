# replay_v2: strict Kernel execution context

With runtime dependencies installed, run from a Git checkout containing its history:

```bash
python benchmarks/replay_v2/run.py
```

This writes [results.json](../../results/replay_v2/results.json),
[report.md](../../results/replay_v2/report.md) and
[raw paired latency samples](../../results/replay_v2/latency_samples.jsonl).
It makes no network calls or downloads. The functional result must have zero
unsafe authorizations, no new legitimate false denies and no changed Guardian
verdicts. Failures exit 1; invalid measurements exit 2, with reasons reported.

## Preserved instrument

The [plan](PLAN.md) was committed before implementation or v2 execution. V2
imports v1's generator, labels, oracle loader, receipt validator, baseline
functions and scoring functions unchanged. Both oracle hashes and both corpus
hashes are printed and compared before replay. Protected-source hashes and
`git diff --stat` verify that v1's code/results and Guardian/policy/envelope
contracts have not changed. The [v1 report remains FAIL](../../results/replay_v1/report.md).

There are 135 requests from 125 setups, with the same seed 20261104 and logical
clock as v1. No scenario, expected label, policy or score is tuned after execution.
The gateway receives the actual full request, not a reconstructed old approval.
It verifies the already-signed envelope digest and live token registration;
registration and authority revocation are trusted-controller operations, not
policy decisions in the Kernel. Generic revoked-key events come from the input
trust configuration and are applied to registered token dependencies.

## Comparators

The original recommendation and confidence-threshold baselines are unchanged.
The separately labelled `soar_b2` gate was fixed in PLAN.md: signature/expiry,
the four-action allowlist and exact scalar action/target/scope. It has no evidence
independence rule, full-envelope binding or live revocation. Baselines are
decision-only simplified stand-ins, not measured security products.

## State and latency

Every accepted simulated receipt changes a separate symbolic resource map before
grading. Before/after snapshots and changed keys expose both authorized and
out-of-scope mutations. Isolated setup-control worlds are counted separately;
the measured primary-request totals exclude them and latency repetitions.
No host, account, network or filesystem containment operation is performed.

For each request, the original hash-verified gateway and current gateway receive
the same candidate token, scalar request and logical time on the same host.
There are 20 warmup pairs and 100 measured pairs, alternating old/new order.
Gateway construction, issuance, revocation delivery and state-map grading are
outside the timer. Nearest-rank p50/p95/max and all raw paired samples are kept;
negative overhead samples are not clipped. The legitimate-allow subset compares
matched useful work. Other groups can include old-allow/new-deny outcomes.
CPU, OS, architecture, Python and dependency versions accompany the results.
Decision/state observations are repeatable; wall-time measurements naturally vary.

## Tests and historical compatibility

```bash
python -m pytest -q
python benchmarks/replay_v2/verify_history.py
```

The strict gateway rejects old calls without an expected envelope or known live
token status. Existing current callers/tests receive that transport plumbing
without changing their policy assertions. `tests/test_replay_v1.py` is immutable
and uses the old API, so `conftest.py` routes its checks through a separate pinned
historical source tree. Fourteen original instrument checks must pass and its
original safety gate must still FAIL; neither file nor result is rewritten or
marked passing. Current security gates require zero v2 violations.

Direct tests cover changed digest/incident/impact/reversibility/scope, unknown
and revoked tokens, wrong purpose, unavailable status, missing envelope, expiry
at commit, replay and successful unchanged requests. Temporarily removing the
digest or live-status check must make the targeted tests fail; the implementation
is restored byte-for-byte after those mutation checks.

The registry is trusted, shared-process and in-memory. It is not a remote or
durable revocation service, and upstream event delivery/provisioning remain
assumptions. Losing it fails closed on unknown tokens. Evidence truth and actual
organizational independence are not established. These are synthetic replay
results in a simulator, with labels derived from this repo's own documents,
not field validation or a claim that the system is secure.
