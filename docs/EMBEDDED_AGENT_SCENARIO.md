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
