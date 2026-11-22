Separate AI examination of replay_v4 runner — version 1

This examination began only after the separate PR #19 SQLite review was finalized
in `sqlite_second_review.md`. The reviewer then received explicit permission to
read the frozen replay_v4 plan and oracle for runner review. The SQLite review had
not read those artifacts. This later examination is post-review exposure, not
preregistration, blindness, independent human validation, or a held-out security
assessment of any repair developed afterward.

Source: `/workspace/scratch/379e5a226cc0/cerberuscyber/benchmarks/replay_v4/run.py`.
The initial static source hash was
`83170b487970e29f8beda47031228e868591d905d7c40ee545ebc62ca8f9c5a0`.
The final smoke test loaded and finished with identical source SHA-256
`aa955897e20b20f0669a991eacd790f4b423b873016f86d7f076c5de10095ef8`.
The runner owner changed instrumentation during review; this reviewer did not
modify the runner, production sources, oracle, frozen plan, or existing results.
No full replay_v4 run was executed by this reviewer.

I found no blocking recipe or scoring defect in the final examined runner.
Three reporting/instrumentation issues found during static review were corrected
by the runner owner before the final smoke test:

1. `guardian_ns` originally bracketed input parsing, cached material lookup/proof
   creation, Guardian construction, evaluation, audit-chain verification and
   controller token registration. This did not match a Guardian decision-call
   latency label. It now brackets only `g.evaluate(...)`, with setup, verification
   and registration outside that timer. HMAC token issuance performed internally
   by the real Guardian remains naturally part of that call; synthetic producer
   proof construction is outside it. This is an instrumentation correction, not
   a changed observed pipeline decision.
2. `constructor_ns` originally reused the most recent constructor duration on
   every attempt, including attempts without reopening the database. It is now
   consumed once for each actual construction/reopen. In the final probe,
   T-016.s1 recorded startup, T-016.s2 recorded `None` because no constructor ran,
   and T-016.s3 recorded the actual zero-byte reopen. U-R-011's second replay
   similarly had `constructor_ns=None`. An omitted-sidecar input refusal had
   `guardian_ns=None` because no Guardian call occurred.
3. Baseline `invariant_violations_scored`, `symbolic_writes_scored` and
   `constructor_refusals_scored` originally defaulted to numeric zero despite
   those effects not being measured for decision-only baselines. The final code
   returns `None` for those baseline metrics. Baseline decisions, thresholds and
   functional implementations remain unchanged.

The owner also corrected the initial S explicit-provisioning recipe, which had
touched a zero-byte file before setup even though that S recipe starts missing.
The final S case provisions from its specified missing path. V's distinct
zero-byte-then-explicit-provision control still touches the file as required.

Static checks against the frozen PLAN and machine-readable recipes:

- Coverage distinguishes 1,005 episodes, 1,100 primary attempts, 1,078 scored
  attempts and 22 doc-ambiguous attempts. The runner iterates every ordered
  attempt rather than using a case's terminal label for earlier attempts.
- S ordinary opens use `create=False`; setup alone provisions. Constructor
  refusals are recorded separately from actual enforcement calls. Healthy and
  explicit-provisioning controls still require genuine authorization and an
  exact receipt. The two healthy-target symlink cases remain ambiguous.
- Effective permission fixtures require a non-root identity with zero effective
  capabilities, then independently probe `os.open` for actual read/write denial.
  Failed/unsupported probes invalidate setup. Mode bits alone are not treated as
  sufficient evidence. The held lock persists through the attempted operation.
- T uses one World with the same token, authority registry, namespace and replay
  history across attempts. Its missing, zero, corrupt, permission, lock,
  replacement, restoration and history-erasure event names have implementations.
  Restoration uses the saved exact preexecution bytes; erasure retains schema.
- U presented-grant candidates are submitted under the original genuine grant;
  they are not re-signed. Explicit fresh-authorization candidates receive proofs
  under the already frozen producer allowlists. Fresh candidate labels do not
  determine trust. The partial-audit-failure event occurs after durable consume
  and before a returned receipt; consumed history remains recorded for retry.
- Ordered revocation/receipt cases implement the named linearization rather than
  claiming exhaustive scheduling coverage. The receipt-before-revocation case
  delivers revocation after the successful call.
- W recomputes candidate canonical bytes/identity guards from frozen inputs.
  Object order/whitespace and escaped ASCII wire controls are decoded before
  the mapping API. Change-then-restore and no-op cases retain identical complete
  canonical data. Changed requests are submitted to the real gateway without a
  label-based prefilter; successful receipts would mutate symbolic state before
  grading. W remains 25 correlated parent clusters, not 725 independent trials.
- Baselines call the unchanged v1 allow/confidence functions and v2 B2 function.
  The confidence threshold remains 0.9. The compatibility `expected='approve'`
  argument affects only the old functions' unused violation annotations; it does
  not affect their decisions. Baselines remain decision-only and do not inherit
  CERBERUS durability or effect measurements.
- Positive setup controls verify a genuine original authorization, exact bound
  receipt and audit chain. Setup errors or unexpected runtime errors become
  invalid measurements, not successful denials. Receipt binding, temporal,
  authority-status and retained replay-history invariants are graded after
  observing the actual receipt/effect.
- Doc-ambiguous attempts remain in raw observations and are excluded from scored
  correctness, false-allow/false-deny and invariant denominators. The final gate
  rejects invalid measurements or repeat mismatches. Wilson z and formula match
  the frozen plan; zero-event denominators receive the stated rule-of-three
  approximation, and zero-size denominators return N/A.
- Timing repetitions reset entire episodes and retain prefixes inside each
  repeated episode. Kernel time brackets the actual gateway call; construction
  refusals have no Kernel sample. Baseline timings bracket their decision-only
  calls. Host-load/frequency/affinity limitations are stated. Raw samples retain
  family/attempt identity; the aggregate latency is a mixture of fixed fixture
  outcomes and must not be described as operational performance.

The final small smoke set used 30 episodes and 38 attempts, including 35 scored
attempts and three ambiguous attempts. All 38 were valid measurements and all
35 scored expectations matched. This is an instrument check, not a full v4
performance/security result or a generalization estimate. Selected cases:

```text
S-001 S-011 S-016 S-021 S-036 S-041 S-046 S-051
T-001 T-016 T-031 T-036 T-041 T-046
U-C-021 U-R-011 U-O-011 U-K-016 U-K-017 U-K-022 U-K-023 U-P-025
V-021 V-031 V-041
W-0010 W-0026 W-0027 W-0028 W-0029
```

Permission controls ran as euid/egid 1000 with
`CapEff=0000000000000000`. Wrong-permission fixtures produced EACCES on both
read and write; read-only fixtures permitted read and produced EACCES on write.
S locked state produced a constructor refusal with no Kernel sample; T's held
lock produced an actual blocked Kernel call before the specified zero-byte
replacement/reopen. The four selected W identity controls allowed and its
nonidentity confidence mutation denied under the original grant. T's ambiguous
snapshot restoration and history erasure both allowed; the latter recorded
retained replay-history and symbolic-scope violations but remained unscored.
The ambiguous omitted-sidecar probe denied. Those ambiguous observations have
not been relabeled.

Reproduction command, executed from the repository root:

```sh
env PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/379e5a226cc0/venv312/bin/python /workspace/scratch/379e5a226cc0/ai-review/probe_runner_review.py
```

The script imports exactly captured source bytes, executes only the listed
episodes under the offline socket guard, and writes
`runner_probe_results_v2.json`. It does not invoke `run()` or load prior result
files. The earlier 26-episode smoke had 33 attempts, not 35 as a progress message
initially stated; the complete counts above are the final checked values. The
earlier `runner_probe_results.json` recorded the runner's disk hash at completion
while the owner was editing, so it should not be used to identify the exact
loaded source. Version 2 captures the loaded source bytes and records both
loaded and finish hashes, which match.

Limits: the examination is static plus a selected smoke set on one Linux/SQLite
environment; it does not replace the full fixed-fixture run or its repeated
measurement checks. New runner or source changes after the final hash require
their own review. No field evidence, real connector effect, independent human
review, or claim of blinded repair development follows from this examination.
