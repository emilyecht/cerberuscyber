# CERBERUS Cyber

**Assume compromise. Constrain authority. Contain damage. Recover safely.**

CERBERUS Cyber is a defensive cybersecurity research prototype investigating whether a separate deterministic authorization layer can reduce the authority gained from compromising or deceiving an intelligent defensive component.

The project applies a three-layer runtime assurance pattern:

1. **Sentinel Intelligence** observes telemetry, correlates suspicious behavior, and recommends a response.
2. **Guardian Policy Engine** deterministically authorizes, constrains, escalates, or rejects proposed actions using explicit rules, evidence thresholds, scope limits, reversibility requirements, and human gates.
3. **Enforcement & Recovery Kernel** executes only approved, least-privilege, reversibility-preferred actions.

> Intelligence may recommend. Policy authorizes. The enforcement layer acts.

## Current Maturity

CERBERUS Cyber is a **TRL 2–3 research prototype**, not a production defensive platform.

What exists today:

- a deterministic Python policy simulator
- a documented threat model
- explicit safety invariants
- versioned Guardian policies
- four safe simulated attack scenarios
- automated tests proving specified forbidden actions are blocked
- GitHub Actions CI
- transition, integration, and evaluation plans

What does **not** exist yet:

- production connectors
- operational validation
- formal verification
- scale or latency evidence
- independent red-team validation
- accreditation for classified or mission deployment

The current simulator is side-effect free and performs no real containment.

## Core Research Question

Modern defensive systems increasingly combine detection, reasoning, and response. That creates a dangerous failure mode: manipulation of the analytical layer may become a path to privileged defensive action.

CERBERUS asks a narrower, testable question:

> Can consequential defensive actions remain bounded, auditable, and reversible even when the intelligent layer is wrong, compromised, or adversarially manipulated?

The project does not claim to prevent prompt injection, telemetry poisoning, insider misuse, or supply-chain compromise. It investigates whether those failures can be prevented from automatically conferring operational authority.

## Architecture

### Layer 1 — Sentinel Intelligence

Sentinel is advisory and untrusted by design. It may ingest identity, endpoint, network, cloud, AI-agent, privileged-access, software-supply-chain, and recovery telemetry.

It produces:

- threat hypotheses
- confidence scores
- ATT&CK-aligned behavior labels
- blast-radius estimates
- recommended actions
- human-readable evidence summaries

Nothing Sentinel produces is executable by itself.

### Layer 2 — Guardian Policy Engine

Guardian evaluates proposed actions against deterministic policy.

Authorization may depend on:

- evidence count and provenance
- confidence band
- asset criticality
- mission impact
- action scope
- reversibility
- blast-radius limits
- data classification
- enclave
- approval status
- continuity-of-operations constraints

Guardian may return:

- **approve**
- **approve with constraints**
- **escalate**
- **deny**

Model confidence is treated as evidence input, never as authorization.

### Layer 3 — Enforcement & Recovery Kernel

The kernel is intended to remain small and least-privileged. In future phases it may mediate actions such as session revocation, step-up authentication, host isolation, key disablement, quarantine, evidence preservation, snapshotting, rollback, and tested recovery workflows.

The current prototype does not execute those actions.

## Technical Differentiation

### Not a SOAR Replacement

CERBERUS does not attempt to replace SIEM, SOAR, XDR, EDR, IAM, or cloud-security platforms.

Its proposed contribution is an independent, cross-platform assurance boundary between recommendation and consequential action. Existing platforms may support approvals and safeguards, but those controls are commonly embedded within vendor-specific playbooks. CERBERUS investigates whether authorization can be made separately testable, globally constrained by invariants, and resistant to shared-fate failure.

### Not an Autonomous AI Defender

Some agentic security products permit models to plan or invoke tool-mediated actions. CERBERUS adopts a stricter design:

- the model does not hold enforcement credentials;
- model output is treated as untrusted input;
- action arguments are policy-validated;
- high-impact actions remain human-approved or human-on-the-loop;
- prompt injection may corrupt recommendations, but should not automatically grant authority.

### Runtime-Assurance Inspiration

CERBERUS is inspired by the architectural separation used in Simplex-style runtime assurance: a powerful but unverified component is bounded by a smaller assurance mechanism.

The analogy is limited. Cyber operations are partially observed, adversarial, context-dependent, and mission-sensitive. The current Guardian is tested, not formally verified, and no physical-safety-style guarantee is claimed.

## Safety Invariants

The prototype encodes actions that remain forbidden regardless of model confidence, including:

- autonomous deletion or modification of backups
- automated retaliation or offensive exploit execution
- destructive remediation without explicit authorization
- direct AI-layer access to enforcement credentials
- execution without a logged authorization decision

Formal verification is not yet claimed. See [Guardian Formal Assurance Path](docs/FORMAL_ASSURANCE_PATH.md).

## Correlated-Failure Analysis

CERBERUS treats shared models, telemetry, credentials, vendors, update channels, administrators, and recovery dependencies as potential common-mode failure paths.

The project now includes a repeatable dependency-graph audit and proposed Shared-Fate Exposure metric. See [Correlated-Failure Audit Method](docs/CORRELATED_FAILURE_METHOD.md).

## Skeptical Review

The project documents its strongest unresolved objections:

- “This is SOAR with extra steps.”
- “Deterministic policy will not scale.”
- “Guardian becomes a single point of failure.”
- “There is no operational evidence yet.”
- “Single-developer validation is insufficient.”

These are treated as evaluation requirements, not dismissed as messaging problems. See [Skeptical Technical Review](docs/RED_TEAM_REVIEW.md).

## 90-Day Evaluation Path

The next meaningful milestone is not a broader claim. It is a sponsor-visible comparison between:

```text
Detection → response playbook → simulated execution
```

and:

```text
Detection → proposed action → Guardian authorization → simulated execution
```

using identical synthetic telemetry and adversarial scenarios.

The evaluation measures:

- false-containment rate
- denial-of-defense resistance
- invariant integrity
- containment latency versus blast radius
- auditability
- policy-authoring burden
- policy conflict and exception growth

See [90-Day Sponsor Evaluation Design](docs/NINETY_DAY_EVALUATION.md).

## Current Scenarios

- ransomware-like behavior
- stolen administrator session
- prompt injection against an AI agent
- suspicious data exfiltration

Run the simulator with Python 3.10 or newer:

```bash
python simulator/cerberus_sim.py simulator/scenarios/ransomware.json
python simulator/cerberus_sim.py simulator/scenarios/stolen_admin_session.json
python simulator/cerberus_sim.py simulator/scenarios/prompt_injection.json
python simulator/cerberus_sim.py simulator/scenarios/data_exfiltration.json
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Roadmap

### Phase 0 — Threat Model and Governance

Define protected assets, approval boundaries, safety invariants, unacceptable failure modes, and recovery constraints.

### Phase 1 — Read-Only Observer

Add normalized telemetry replay, representative read-only connectors, evidence-backed recommendations, and benchmark reporting. No actions are taken.

### Phase 2 — Human-Approved Containment

Introduce reversible lab actions such as session revocation, host isolation, quarantine, step-up authentication, and evidence preservation. Every action requires explicit approval.

### Phase 3 — Bounded Automation

Preauthorize only a narrow set of low-impact, reversible actions under strict evidence, scope, and mission-impact thresholds.

### Phase 4 — Recovery Assurance

Add tested rollback, restoration, credential rotation, configuration recovery, and post-action verification.

### Phase 5 — Mission Integration

Potential future work, only under sponsorship and accreditation, may include local inference, signed policy attestation, hardware-backed identity, disconnected deployment, classified policy packs, and SCIF-compatible engineering.

## Research and Transition Documents

- [Threat Model](docs/THREAT_MODEL.md)
- [Safety Invariants](docs/SAFETY_INVARIANTS.md)
- [Architecture](docs/architecture.md)
- [Gap-Closure Plan](docs/GAP_CLOSURE_PLAN.md)
- [Integration Strategy](docs/INTEGRATION_STRATEGY.md)
- [Evaluation Framework](docs/EVALUATION_FRAMEWORK.md)
- [90-Day Sponsor Evaluation](docs/NINETY_DAY_EVALUATION.md)
- [Correlated-Failure Audit Method](docs/CORRELATED_FAILURE_METHOD.md)
- [Guardian Formal Assurance Path](docs/FORMAL_ASSURANCE_PATH.md)
- [Skeptical Technical Review](docs/RED_TEAM_REVIEW.md)
- [One-Page Pitch](docs/ONE_PAGE_PITCH.md)

## Security Posture

CERBERUS Cyber is defensive-only.

The project does not include exploit development, credential theft, destructive payloads, unauthorized scanning, automated retaliation, counterattack capability, or autonomous irreversible remediation.

## Core Principle

**Intelligence is not authority.**

An adversary may deceive an intelligent layer. That deception must not automatically grant operational control.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 Emily Echt.