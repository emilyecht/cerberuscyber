# replay_v3: frozen held-out challenge evaluation

From a Git checkout with history and runtime dependencies already installed:

```bash
python benchmarks/replay_v3/run.py
```

The command is offline. Exit 0 means pass, 1 means measured CERBERUS failure,
2 means an invalid measurement. It writes only `results/replay_v3/**`.
Use `--output-dir /tmp/replay-v3` to preserve checked-in v3 observations on rerun.

- [Frozen plan](PLAN.md), committed first.
- [Documentary oracle](oracle.json) and [SHA-256](oracle.sha256), committed before
  reading Kernel/gateway implementation or running the evaluated pipeline.
- [Measured report and status](../../results/replay_v3/report.md).
- [Historical v1 FAIL](../../results/replay_v1/report.md).
- [Historical v2 PASS on its development corpus](../../results/replay_v2/report.md).

Seed 87160329; 300 new A-G episodes plus 135 x 24 = 3,240 H mutations. Steps
share replay/revocation state. H is derived from v2 inputs, not an independent
held-out random sample. Primitive replay/binding controls can overlap v2 probes;
new sequences, compound faults, timing boundaries and field sweeps are disclosed
in the report. Do not treat all generated variants as independent attack classes.

Every label cites a frozen document/rule. Eight attempts are `doc-ambiguous` and
excluded from scored denominators. No post-observation relabelling or production
fix is allowed. The original three baseline functions and v1 scoring are imported
unchanged; Wilson intervals and explicit ambiguity exclusions are added for v3.

Fresh authorization paths traverse Guardian and Kernel. Presented-grant episodes
test an already-issued original token against the actual supplied request, with
raw Guardian re-authorization diagnostics retained separately. A rejected repeat
authorization does not itself revoke an earlier token. Only the selected grant
is submitted; the harness does not replace it with fresh authority to repair an
attack. Every accepted receipt mutates a symbolic map before grading; independent
binding/time/replay/status observations determine effect scope.

Latency is 5 warmup and 20 measured repetitions per primary attempt, restoring
the sequence prefix and state each time. Constructor refusals have no enforcement
call and are explicitly N/A; they are not zero-time Kernel samples. Exact counts,
95% Wilson intervals, 0/N rule-of-three bounds, raw samples, hardware and actual
dependency versions are in the report/results.

```bash
python -m pytest -q benchmarks/replay_v3/test_instrument.py
python benchmarks/replay_v3/verify_history.py
```

The standalone history verifier requires committed results. Protected-source
hashes cover every pre-existing path except the root README, including Guardian,
Kernel/gateway/registry/token, both policies and every v1/v2 artifact. The complete
materialized corpus is retained as deterministic gzip JSONL in the results.

Synthetic replay; repository-derived labels; trusted process-local registry;
correct issuer provisioning and revocation delivery assumed; compromised trusted
producers out of scope; no network, real telemetry/credentials, operational
effects or field validation. No system-security or production-readiness claim.
