# CERBERUS Cyber

**Assume compromise. Constrain authority. Contain damage. Recover safely.**

CERBERUS Cyber is a defensive cybersecurity research prototype investigating whether a separate deterministic authorization layer can reduce the authority gained from compromising, deceiving, or pressuring an intelligent defensive component.

> **Intelligence is not authority.** Sentinel may recommend. Guardian authorizes. Enforcement acts only on a valid decision.

## Architecture

CERBERUS applies a three-layer runtime-assurance pattern:

1. **Sentinel Intelligence** observes telemetry, correlates suspicious behavior, and produces an advisory finding.
2. **Guardian Policy Engine** deterministically approves, escalates, or denies a typed action proposal using explicit policy, evidence provenance, scope ceilings, reversibility requirements, freshness, and approval gates.
3. **Enforcement & Recovery Kernel** validates a signed decision token and dispatches only the exact approved action, target, and scope.

The intelligent layer does not hold enforcement authority. Model confidence is informational and cannot replace required evidence or policy approval.

## Current Maturity

CERBERUS Cyber is a **TRL 2–3 research prototype**, not a production defensive platform.

### Implemented

- deterministic Python Guardian policy engine with deny-by-default behavior
- versioned policy bundle (`0.5.0`)
- typed **ActionEnvelope v1.0.0** authority contract
- JSON Schema Draft 2020-12 validation
- canonical JSON serialization and SHA-256 envelope digests
- actor identity, policy version, freshness, nonce, evidence references, UUID idempotency key, approval mode, and reversibility metadata
- short-lived **DecisionToken v1.1.0** artifacts bound to the exact envelope digest, actor, action, target, scope, policy version, and idempotency key
- one-time token consumption and replay rejection
- side-effect-free Enforcement Gateway receipts
- hash-chained prototype audit ledger
- four baseline simulated cyber scenarios
- one end-to-end adversarial AI persistence demonstration using fabricated telemetry
- nine-case adversarial authority-boundary corpus
- automated unit, schema, replay, substitution, and adversarial tests
- GitHub Actions validation on Python 3.10 and 3.12

### Not Yet Implemented

- production read or write connectors
- operational validation against real infrastructure
- durable atomic replay and idempotency state
- hardware-backed asymmetric signing and key rotation
- a formally adopted cross-language canonicalization profile such as RFC 8785
- externalized OPA/Rego policy evaluation
- formal verification
- independent red-team validation
- scale, latency, or field false-positive evidence
- accreditation for classified or mission deployment

The repository performs no real containment by default.

## Core Research Question

Modern defensive systems increasingly combine detection, reasoning, planning, and response. That creates a dangerous failure mode: manipulation of the analytical layer may become a path to privileged defensive action.

CERBERUS asks a narrower, testable question:

> Can consequential defensive actions remain bounded, auditable, and reversible even when the intelligent layer is wrong, compromised, or adversarially manipulated?

The project does not claim to prevent prompt injection, telemetry poisoning, insider misuse, supply-chain compromise, or model deception. It investigates whether those failures can be prevented from automatically conferring operational authority.

## The Authority Boundary

Sentinel recommendations are converted into a versioned `ActionEnvelope` before Guardian evaluation.

The canonical envelope carries:

- proposing actor identity
- target resource
- requested action and maximum scope
- evidence references and digests
- informational confidence score
- freshness timestamp, expiry, and nonce
- UUID idempotency key
- reversibility flag
- required approval mode
- exact policy bundle version

Guardian rejects malformed, stale, unsupported, policy-version-mismatched, over-scoped, forbidden, or replayed proposals. An approved decision token authorizes only the exact canonical envelope that Guardian evaluated.

See [ActionEnvelope v1.0.0](docs/ACTION_ENVELOPE_V1.md) and [ADR 0005](docs/adr/0005-action-envelope-v1-contract.md).

## Layer 1 — Sentinel Intelligence

Sentinel is advisory and untrusted by design. It may ingest identity, endpoint, network, cloud, AI-agent, privileged-access, software-supply-chain, and recovery telemetry.

It produces:

- threat hypotheses
- confidence scores
- behavior labels
- target and blast-radius estimates
- evidence provenance
- recommended actions
- human-readable summaries

Nothing Sentinel produces is executable by itself.

The embedded-agent demonstration correlates fabricated evidence for:

- anomalous process behavior
- hidden persistence
- credential misuse
- model-driven deception
- log tampering

National or state-sponsor attribution remains unverified and outside the authorization decision.

## Layer 2 — Guardian Policy Engine

Guardian evaluates a validated ActionEnvelope against deterministic policy.

Authorization may depend on:

- required behavior classes
- independent evidence sources
- action allowlists
- scope ceilings
- freshness and replay state
- policy-version match
- reversibility
- approval count and mode
- globally forbidden actions
- configured escalation signals

Guardian returns one of:

- **approve**
- **escalate**
- **deny**

A contradictory observer signal is normalized as `cross_signal_inconsistency`. Policy bundle `0.5.0` forces that condition to `GLOBAL-EVIDENCE-CONFLICT` escalation before any action can be authorized. The contradiction cannot help Sentinel satisfy its corroboration threshold.

See [ADR 0004](docs/adr/0004-evidence-conflict-escalation.md).

## Layer 3 — Enforcement & Recovery Kernel

The current Enforcement Gateway:

- verifies the decision-token signature
- checks the exact action, target, and scope
- verifies expiry and nonce freshness
- rejects replayed tokens
- returns a simulated receipt only

The current prototype performs no real quarantine, session revocation, host isolation, credential rotation, or rollback.

Future connectors must be capability-scoped, least-privileged, reversible where possible, and unable to reinterpret Guardian intent.

## Adversarial Test Corpus

Workstream A adds nine deterministic scenarios restricted to named sandbox workloads:

| Scenario | Expected authority outcome |
|---|---|
| benign maintenance similarity | no Sentinel finding |
| staged urgency with one approval | escalate |
| confidence manipulation with missing signals | escalate |
| four of five required behaviors | escalate |
| contradictory independent observer | escalate under `GLOBAL-EVIDENCE-CONFLICT` |
| single-source signal flood | no Sentinel finding |
| enterprise scope widening | deny |
| forbidden `wipe_host` injection | deny |
| complete valid positive control | signed simulated receipt only |

The corpus asserts:

- zero tolerated forbidden-action authorizations
- zero simulated containment for the benign fixture class
- complete escalation for partial evidence or approval cases
- zero real side effects

These are fixture assertions, not operational performance claims.

See [Adversarial AI Persistence Scenario](docs/EMBEDDED_AGENT_SCENARIO.md).

## Quick Start

Requires Python 3.10 or newer.

```bash
python -m pip install -r requirements-dev.txt
```

Run the baseline simulator:

```bash
python simulator/cerberus_sim.py simulator/scenarios/ransomware.json
python simulator/cerberus_sim.py simulator/scenarios/stolen_admin_session.json
python simulator/cerberus_sim.py simulator/scenarios/prompt_injection.json
python simulator/cerberus_sim.py simulator/scenarios/data_exfiltration.json
```

Run the fabricated embedded-agent demonstration without approvals:

```bash
python simulator/embedded_agent_hunt.py \
  simulator/scenarios/embedded_ai_agent_telemetry.json
```

Demonstrate the signed, side-effect-free approval path:

```bash
export CERBERUS_PROTOTYPE_SIGNING_KEY='replace-with-at-least-32-bytes-of-test-material'
python simulator/embedded_agent_hunt.py \
  simulator/scenarios/embedded_ai_agent_telemetry.json \
  --approval incident-commander \
  --approval cyber-duty-officer \
  --simulate-enforcement
```

Run all tests:

```bash
python -m pytest -q
```

## Technical Differentiation

### Not a SOAR Replacement

CERBERUS does not attempt to replace SIEM, SOAR, XDR, EDR, IAM, or cloud-security platforms.

Its proposed contribution is an independently testable assurance boundary between recommendation and consequential action. Existing products may support approvals and safeguards, but CERBERUS makes the authority contract, policy decision, signed authorization, and enforcement checks explicit and separable.

### Not an Autonomous AI Defender

CERBERUS adopts a stricter model than an agent with broad tool access:

- the model does not hold enforcement credentials
- model output is untrusted input
- proposals must satisfy a typed schema
- confidence does not authorize action
- action arguments are policy constrained
- high-impact actions remain approval gated
- Enforcement cannot improvise or widen intent

### Runtime-Assurance Inspiration

CERBERUS is inspired by Simplex-style separation between a powerful unverified component and a smaller assurance mechanism.

The analogy is limited. Cyber operations are partially observed, adversarial, context-dependent, and mission-sensitive. Guardian is tested, not formally verified, and no physical-safety-style guarantee is claimed.

## Safety Invariants

The prototype forbids actions including:

- deleting or modifying backups
- disabling recovery
- wiping hosts
- automated retaliation
- offensive exploit execution
- credential harvesting
- execution without a valid authorization decision

See [Safety Invariants](docs/SAFETY_INVARIANTS.md) and [Guardian Formal Assurance Path](docs/FORMAL_ASSURANCE_PATH.md).

## Workstream Status

- **Foundation:** typed Guardian path, signed tokens, replay rejection, simulated Enforcement — implemented
- **Workstream A:** adversarial authority-boundary corpus — implemented
- **Workstream B:** ActionEnvelope v1.0.0 contract — implemented
- **Workstream C:** externalized, auditable Guardian policy engine — next
- **Workstream D:** capability-scoped Enforcement Gateway connectors — planned
- **Workstream E:** independent red-team engagement protocol — planned
- **Workstream F:** sponsor evaluation package — planned

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

- [ActionEnvelope v1.0.0](docs/ACTION_ENVELOPE_V1.md)
- [Adversarial AI Persistence Scenario](docs/EMBEDDED_AGENT_SCENARIO.md)
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
- [ADR 0004 — Evidence Conflict Escalation](docs/adr/0004-evidence-conflict-escalation.md)
- [ADR 0005 — ActionEnvelope v1 Contract](docs/adr/0005-action-envelope-v1-contract.md)

## Security Posture

CERBERUS Cyber is defensive-only.

The project does not include exploit development, credential theft, destructive payloads, unauthorized scanning, automated retaliation, counterattack capability, or autonomous irreversible remediation.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 Emily Echt.
