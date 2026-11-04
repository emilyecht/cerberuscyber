# Five-class synthetic replay v1

With the repository's runtime dependencies already installed, run from its root:

```bash
python benchmarks/replay_v1/run.py
```

The command makes no network calls or downloads. It writes
[`results.json`](../../results/replay_v1/results.json) and a
[`human-readable report`](../../results/replay_v1/report.md), then returns the
safety-gate exit status. **The current snapshot fails the gate**; do not interpret
the report's existence as a passing security assessment.

Run the tests with the repository's existing framework:

```bash
python -m pytest -q tests/test_replay_v1.py
```

The safety test is deliberately unwaived: any observed CERBERUS violation fails
it. Instrument checks independently verify denominators, errors, baseline
scoring, authentic positive controls, unapproved Kernel acceptance, label
integrity, offline behavior and identical repeated output. Baseline failures
are comparisons, not causes for skipping or weakening the CERBERUS gate.

## Inputs and precommitted labels

- Fixed seed: **20261104**; fixed logical clock: **2026-11-01T12:00:00Z**.
- 25 setups per class; 135 requests total because five widening sequences have
  three steps each. All steps share their original grant and sequence state.
- Four existing allowlisted action profiles, all four mission-impact labels,
  varying fabricated targets, confidence and evidence counts.
- [`oracle.json`](oracle.json) records every expected decision and input hash,
  plus the policy and complete corpus digests. It was committed before replay.
- The generator and runner reuse `ActionEnvelope`, `Evidence`, `PolicyBundle`,
  `GuardianDecision`, `AssuranceBundle`, the existing fixture attestations,
  `DecisionTokenSigner`, `EnforcementGateway` and explicit `ReplayCache` objects.
  They introduce no alternate policy engine or production request contract.
- Trusted fixture evidence/approvals are signed before adversarial mutation.
  Attacks are not re-signed to make their authority valid.

To inspect the exact generated structured cases without executing the system:

```bash
python -c 'import json; from benchmarks.replay_v1.generate import generate; print(json.dumps(generate(), indent=2))'
```

For another seed, explicitly freeze a new oracle before running that instrument:

```bash
python benchmarks/replay_v1/generate.py --seed 42 --output /tmp/replay-42-oracle.json
python benchmarks/replay_v1/run.py --oracle /tmp/replay-42-oracle.json --output-dir /tmp/replay-42
```

Oracle creation refuses to overwrite an existing file. Replay refuses changed
labels, case hashes, policy content or v1's fixed 0.9 confidence threshold.
Custom runs have their own input hashes; never replace a historical record to
present them as the same measurement.

## What is measured

| Class | Coverage | Expected |
|---|---|---|
| Legitimate | Fresh, independently attested, in-scope reversible actions with required approvals | approve |
| Malicious | Forbidden recovery/outbound actions, a synthetic credential-field marker, structured injection signals, poisoned observation digest | deny |
| Ambiguous | One source, shared independence domains, conflicting/missing signals, stale observation | escalate; documented freshness failures deny |
| Expired authority | Expired request/approval/token, revoked evidence/approval keys, wrong incident and already-issued token revocation | deny |
| Scope widening | Host-to-segment, identity-to-enterprise, irreversible/impact metadata changes and incremental widening | deny |

Accuracy uses exact frozen labels. False allows use all non-approve-labelled
requests; false denials include legitimate requests escalated or denied.
Escalation correctness is precision, with recall reported separately. Every
metric exposes its numerator/denominator; missing denominators are N/A.

The combined pipeline verdict includes observed Kernel acceptance under an old
grant. Raw Guardian verdicts and their own accuracy are separately preserved.
Expected-block Kernel checks include missing/forged tokens, changed action,
target and scope, consumed-token reuse and case-specific old-grant attempts.
Setup authorization and a separate isolated-cache exact receipt must succeed;
an unavailable or broken positive control is an error, never a defensive pass.
This does not evaluate SQLite/restart durability.

Both baselines see the same requests and labels: allow any recommendation, and
approve confidence >= 0.9 / otherwise escalate. They do not mint tokens, exercise
the Kernel, or represent mature security products. Their Kernel metric is N/A.
No new policy, revocation service or request prefilter is inserted to help scores.

## Current findings and interpretation

The current source snapshot has no API argument for expected envelope/incident,
impact or reversibility at execution, and no online check of already-issued
token revocation. Old, unconsumed, unexpired tokens can therefore still receive
simulated receipts when action/target/scope match, despite a later Guardian
denial under changed context. Those task-level capability gaps remain scored as
failures and are listed individually. They are not claims of real irreversible
effects, real containment failures or newly introduced policy regressions.

Stale evidence's deny label and these broader execution-context requirements
were identified in the frozen plan before measurement. No labels were changed
after observing the results. The rest of the production code and policy remain
unchanged.

This is **synthetic replay, not field validation**. Confidence is a numeric field,
not natural-language persuasion. Injection/poisoning fixtures test structured
signals and corrupted request-bound proofs, not arbitrary malicious language or
lies correctly signed by compromised trusted producers. Target criticality is
declared metadata, not measured mission risk. No live model, real telemetry,
real credentials, network access, connectors or defensive effects are used.
Reproducibility omits volatile token IDs and audit timestamps/hashes after
checking them in memory; it does not disable production randomness or validation.

See the [frozen plan](PLAN.md) for label bases, scoring, exit statuses and limits.
