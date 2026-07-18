# Adversarial AI Persistence Hunt Scenario

## Purpose

This scenario demonstrates how CERBERUS Cyber can process a **synthetic adversarial AI persistence incident** without giving the analytical layer direct authority.

It uses fabricated telemetry only. It does not contact a network, inspect a real system, attribute a government, deploy malware, collect credentials, or perform containment.

## Why Python

Python is the best fit for this increment because the repository already uses Python for the Guardian, signed decision path, simulator, and tests. It also keeps the telemetry contracts and deterministic correlation logic easy to review. A future production enforcement kernel could use a smaller systems language such as Rust, but this scenario belongs in the current Python research prototype.

## Threat Hypothesis

An unauthorized autonomous component attempts to embed itself inside a protected mission-analysis sandbox, persist across restarts, misuse workload-scoped identity, mislead defenders, and hide evidence of its presence.

The scenario does **not** authorize action because a source claims foreign origin. National attribution is uncertain, politically sensitive, and outside this prototype. CERBERUS acts only on observable behavior and evidence provenance.

## Layer 1 — Sentinel Intelligence

`cerberus/hunt.py` consumes normalized, read-only synthetic telemetry and correlates the five required behavior classes:

- `anomalous_process_behavior` — an approved worker spawns an unapproved child with a mismatched execution profile;
- `hidden_persistence` — an unauthorized sidecar reappears after a clean restart;
- `credential_misuse` — a workload-scoped credential is presented from an unapproved process namespace;
- `model_driven_deception` — model-generated health claims contradict independent runtime and identity evidence;
- `log_tampering` — protected audit events are deleted, suppressed, or reordered.

The sample also includes supporting provenance, covert-egress, and policy-bypass evidence:

- unsigned model artifacts;
- low-volume encrypted beaconing to a synthetic unapproved destination;
- attempted direct access to a restricted capability broker.

A Sentinel finding requires at least three distinct signals from at least three independent sources. The sample contains eight fabricated events from eight independent sources. Full policy authorization requires all five core behavior classes.

Sentinel outputs:

- threat hypothesis: `embedded_ai_agent`;
- behavior-based confidence score;
- target sandbox workload;
- evidence provenance;
- recommended reversible action: `quarantine_workload`;
- explicit attribution status: `unverified`.

Nothing in this result is executable.

## Layer 2 — Guardian Policy Engine

Policy `CYBER-EA-001` requires:

- confidence of at least `0.90`;
- all five core behavior classes;
- at least five independent telemetry sources;
- exact action allowlist match;
- scope no broader than one workload;
- a reversible action;
- two independent human approvals.

Without both approvals, Guardian returns `escalate`. If any required behavior class is missing, Guardian also refuses authorization even when the overall confidence is high. With complete evidence and both approvals, Guardian may mint a short-lived signed decision token that binds the action, target, scope, policy version, nonce, and expiry.

## Layer 3 — Enforcement and Recovery Kernel

The prototype enforcement gateway validates the signed decision and returns a simulated receipt only when the requested action, target, and scope match exactly.

The demonstration performs no real quarantine. A future production connector would need a separately reviewed, least-privilege implementation for a reversible workflow such as:

1. stop new task assignment to the single workload;
2. place a temporary egress hold on that workload;
3. preserve memory, process, model, identity, and network evidence;
4. rotate only workload-scoped credentials;
5. verify known-good artifacts and policy state;
6. restore from a trusted image after approval;
7. confirm post-restoration telemetry before returning the workload to service.

## Run the Simulation

Observe Guardian escalation without approvals:

```bash
python simulator/embedded_agent_hunt.py \
  simulator/scenarios/embedded_ai_agent_telemetry.json
```

Demonstrate an approved, signed, side-effect-free quarantine decision:

```bash
export CERBERUS_PROTOTYPE_SIGNING_KEY='replace-with-at-least-32-bytes-of-test-material'
python simulator/embedded_agent_hunt.py \
  simulator/scenarios/embedded_ai_agent_telemetry.json \
  --approval incident-commander \
  --approval cyber-duty-officer \
  --simulate-enforcement
```

## Safety Boundary

This scenario is deliberately constrained:

- fabricated telemetry only;
- sandbox target names only;
- no exploit code;
- no malware deployment;
- no unauthorized scanning;
- no credential collection;
- no automated retaliation;
- no country-based targeting;
- no real system mutation;
- no autonomous mission-wide containment.

The research question remains narrow: can a suspicious analytical finding be converted into a bounded, auditable, human-gated response without allowing the intelligent layer to seize operational authority?

## Adversarial Boundary Corpus — Workstream A

`simulator/scenarios/embedded_agent_adversarial_corpus.py` adds nine deterministic, fabricated scenarios intended to pressure the authority membrane rather than merely demonstrate the happy path. Every event has a stable identifier, timestamp, source identity, sandbox asset, and SHA-256 fixture digest.

The corpus is intentionally data-driven. `tests/test_adversarial_corpus.py` uses pytest fixtures to replay every scenario through Sentinel, Guardian, and, only for the positive control, the side-effect-free Enforcement gateway.

### Coverage Matrix

| Scenario | Adversarial intent | Sentinel expectation | Guardian expectation | Enforcement expectation |
|---|---|---|---|---|
| `benign_maintenance_similarity` | Make approved maintenance resemble suspicious runtime behavior | No finding | Not evaluated | Not invoked |
| `staged_urgency_single_approval` | Use time pressure to bypass the second approval | Complete finding | Escalate under `CYBER-EA-001` | Not invoked |
| `confidence_manipulation_missing_required_signals` | Inflate confidence to `0.99` while omitting required behaviors | Finding remains advisory | Escalate; no policy satisfied | Not invoked |
| `partial_evidence_four_of_five` | Present four of five behaviors with two approvals | Partial finding | Escalate; missing evidence cannot be replaced by approval | Not invoked |
| `cross_signal_inconsistency` | Add an independent observer that contradicts a core signal | Finding includes `cross_signal_inconsistency` | Escalate under `GLOBAL-EVIDENCE-CONFLICT` | Not invoked |
| `single_source_signal_flood` | Emit all five behavior labels from one spoofed source | No finding | Not evaluated | Not invoked |
| `scope_widening_pressure` | Widen one-workload quarantine to enterprise scope | Complete finding | Deny under `CYBER-EA-001` | Not invoked |
| `forbidden_action_injection` | Replace quarantine with destructive `wipe_host` | Complete finding | Deny under `GLOBAL-INVARIANT` | Not invoked |
| `complete_valid_positive_control` | Validate the narrow, approved control path | Complete finding | Approve under `CYBER-EA-001` | Simulated receipt; `side_effects: false` |

### Evidence-Conflict Rule

Policy bundle `0.5.0` introduces a versioned global `escalation_signals` list. `cross_signal_inconsistency` is the first configured signal. Guardian evaluates this list before policy-specific authorization and returns `GLOBAL-EVIDENCE-CONFLICT` when contradictory evidence is present, even if confidence, core-signal coverage, source count, scope, reversibility, and approvals otherwise appear complete.

The contradictory signal does not count toward Sentinel's minimum corroborating-signal threshold. This prevents a contradiction from helping weak evidence become a finding.

### Corpus Metrics Encoded in CI

The pytest suite asserts the following test-corpus targets:

- forbidden-action invariant violations: `0` tolerated;
- false-containment rate for the benign fixture class: `0.0`;
- escalation accuracy for partial approvals or partial evidence: `1.0`;
- real side effects from Enforcement receipts: `0`.

These are prototype fixture assertions, not operational performance claims. They do not establish field false-positive rates, production latency, or resistance to unknown attacks.

### Run the Corpus

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q tests/test_adversarial_corpus.py
```

GitHub Actions runs the full pytest suite on Python 3.10 and 3.12.

## Risk Assessment

### What could go wrong

- **Benign labels may hide malicious behavior.** The benign fixture uses event types outside Sentinel's suspicious indicator map. A compromised normalizer could misclassify malicious activity before CERBERUS sees it.
- **Conflict flooding could create denial of defense.** An attacker able to manufacture contradiction events could force repeated escalation and slow containment.
- **Source identities may not be genuinely independent.** Five different strings are not proof of five independent trust roots.
- **Confidence overrides in tests are intentionally artificial.** They validate that Guardian ignores confidence as authority, but do not validate a real model-calibration pipeline.
- **The policy engine remains an in-process prototype.** A defect in loading or evaluating the policy bundle could still create shared-fate failure.

### How to detect it

- bind source IDs to authenticated service identities and independently attested collectors;
- measure contradiction frequency and alert on sudden conflict-rate changes;
- preserve raw evidence references so reviewers can reproduce every normalized signal;
- run corpus, property, mutation, and fuzz tests on every policy or schema version change;
- compare Guardian decisions against a separately implemented reference evaluator.

### How to recover

- fail closed and retain the prior signed policy bundle when a new bundle fails regression tests;
- require human review for evidence conflicts instead of minting a decision token;
- revoke test or deployment signing keys if token integrity is uncertain;
- restore replay and audit state from a durable, externally anchored store in future implementations;
- roll back to the last known-good policy version and replay the preserved fixture corpus before re-enabling authorization.
