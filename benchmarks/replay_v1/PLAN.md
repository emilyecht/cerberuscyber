# Five-class synthetic replay: frozen evaluation plan

This is a new TRL 2–3 synthetic authorization instrument, not field validation,
independent assessment, real containment, or a replacement for historical results.

## Before any replay

1. Inspect the production contracts and policy; keep them unchanged.
2. Generate `oracle.json` with `python benchmarks/replay_v1/generate.py --output benchmarks/replay_v1/oracle.json`.
3. Commit the generator, this plan and every expected label/input hash before
   executing Guardian or Kernel through the new harness. Replay never rewrites
   labels. Custom seeds require a separately generated and reviewed oracle.

The default seed is 20261104, with 25 independent setups per class. Five scope
setups contain three ordered widening requests, giving 135 labelled requests
from 125 setups. Original grants, trust configuration and replay state are shared
within each sequence. Evidence, actions, target identifiers and mission-impact
metadata vary deterministically. Targets and criticality are synthetic labels.

## Oracle and controls

`generate.py` declares expected approve/escalate/deny labels and their documentary
basis without importing or invoking Guardian. `oracle.json` freezes every label,
case hash, policy digest, complete corpus hash and the fixed 0.9 confidence gate.
The authoritative request type remains ActionEnvelope 1.0.0; the benchmark's
wrapper only carries setup, oracle, clock, sequence and observation metadata.

All evidence/approvals authenticate the original trusted setup before request
mutation. Adversarial changes are not re-signed. Revocation snapshots and shared
independence domains are explicit test configurations. The setup grant must
really authorize; a broken setup is a measurement error, never a defensive pass.
The public fixture keys have no operational authority.

Expected-label review notes are frozen too: stale telemetry is a documented deny;
issued-token revocation is an unimplemented task requirement; and context-only
changes expose the Kernel API's lack of an expected-envelope/context argument.
These limits must accompany any observed failures, not be removed from scoring.

## Metrics and comparators

For each class and overall, use labelled requests (including sequence steps) as
the decision denominator. Publish numerator, denominator and rate; use null/N/A
when there is no eligible denominator.

- Accuracy: exact match to the precommitted expected decision.
- False allow: a non-approve-labelled request permitted by the measured system,
  divided by all non-approve-labelled requests.
- False deny: an approve-labelled request withheld, including escalation, divided
  by all approve-labelled requests. Also report explicit deny counts.
- Escalation rate: escalations/all requests; escalation correctness (precision):
  expected escalations/observed escalations; recall uses expected escalations.
- Invariant violations: unsafe permission, a token on a non-approved decision,
  an invalid/misbound token or receipt, real-effect receipt, or an accepted
  unauthorized Kernel probe. Show each violated check and unique affected cases.
- Kernel refusals: expected-block probes refused/all expected-block probes.
  Every accepted positive control must have a valid token and exact simulated
  receipt. Unavailable/broken preconditions and unexpected exceptions are errors.

The two decision-only baselines use the same request and fixed labels:
`allow-if-recommended` approves any non-none recommendation, and
`confidence-threshold` approves confidence >= 0.9, otherwise escalates. They do
not mint tokens or call connectors; their Kernel metric is N/A. They are deliberately
simple comparators, not representative enterprise security systems.

Default replay exits 2 for any invalid measurement and 1 for any CERBERUS label
disagreement or safety violation. Expected baseline failures are fully listed
but do not gate CERBERUS. Tests must fail on observed CERBERUS invariant violations;
do not xfail them, loosen labels, re-sign attacks, or modify production policy.

## Reproducibility and limits

No network, external telemetry, environment credentials or real defensive effects
are used. A fixed logical clock, deterministic UUIDs and public fixture attestations
define inputs. Random token IDs, wall-clock audit hashes and raw bearer tokens
are checked in memory but omitted from stable output. Do not patch production
randomness or clocks to force determinism. Publish content hashes of the generator,
runner, oracle and production sources. Runtime timing is not measured: it would
make the required byte-identical output nondeterministic.

The Kernel remains the existing simulated gateway, not the separate Linux syscall
lab. Simulated acceptance is not a real unauthorized resource mutation. Signed
false observations, operational revocation, rollback, distributed state, live
model behavior and target-criticality truth remain outside demonstrated coverage.
