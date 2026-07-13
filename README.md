# CERBERUS Cyber

**Assume compromise. Constrain authority. Contain damage. Recover safely.**

CERBERUS Cyber is a defensive cybersecurity research prototype for high-threat environments in which advanced persistent threats, compromised credentials, malicious insiders, supply-chain compromise, and AI-enabled attack paths must be treated as expected conditions rather than exceptional events.

The project applies a three-layer runtime assurance model to defensive cyber operations:

1. **Sentinel Intelligence** observes telemetry, correlates suspicious behavior, maps activity to threat patterns, and recommends a response.
2. **Guardian Policy Engine** deterministically authorizes or rejects proposed actions using explicit rules, evidence thresholds, scope limits, reversibility requirements, and human approval gates.
3. **Enforcement & Recovery Kernel** executes only approved, least-privilege, reversible containment and recovery actions.

> Intelligence may recommend. Policy authorizes. The enforcement layer acts.

## Executive Summary

Mission-critical networks increasingly depend on cloud workloads, automated response systems, identity platforms, software supply chains, and AI agents with access to sensitive data and operational tools. These systems can increase speed and resilience, but they also expand the attack surface and create new failure modes when automation is manipulated, misconfigured, or granted excessive authority.

CERBERUS Cyber is designed as a next-generation Zero Trust enforcement and autonomous containment architecture for high-threat, nation-state environments. It assumes that an adversary may obtain valid credentials, compromise an endpoint, poison telemetry, manipulate an AI agent, or gain access through a trusted dependency. The system's purpose is not to promise perfect prevention. Its purpose is to preserve positive control, limit blast radius, and prevent a compromised component from gaining unrestricted authority.

CERBERUS Cyber separates analytical intelligence from operational authority. AI-assisted analysis may identify threats and propose action, but only a deterministic Guardian layer may authorize execution. High-impact actions remain human-on-the-loop or human-approved according to policy. This architecture is intended to reduce the risk of rogue automation, false-positive containment, adversary-induced response, and prompt-injection attacks against defensive AI systems.

The current repository is a **research prototype**, not a production defensive platform. It includes a working deterministic Python simulator, formal threat model, safety invariants, versioned Guardian policies, automated tests, and four safe attack scenarios. No real containment actions are executed.

## Current Gap-Closure Program

CERBERUS Cyber is now following a defined transition plan from simulator to measurable defensive research platform.

The active workstreams are:

- normalized telemetry replay
- read-only identity, cloud, endpoint, and SIEM connectors
- externalized Guardian policy artifacts
- measurable evaluation and benchmark reporting
- human-approved reversible lab actions
- browser-based visualization of the three-layer decision path

See:

- [Gap-Closure Plan](docs/GAP_CLOSURE_PLAN.md)
- [Integration Strategy](docs/INTEGRATION_STRATEGY.md)
- [Evaluation Framework](docs/EVALUATION_FRAMEWORK.md)

## Problem Statement

Traditional security architectures often rely on perimeter controls, detection alerts, analyst review, and broad administrative tooling. In high-threat environments, that model can fail in several ways:

- Advanced persistent threats may operate with valid credentials and legitimate administrative paths.
- Identity compromise can allow an attacker to bypass network-centric controls.
- Automated response systems may act too broadly, disrupt mission operations, or be manipulated by poisoned telemetry.
- AI agents may be vulnerable to prompt injection, excessive permissions, compromised plugins, or malicious retrieval sources.
- Software supply-chain compromise can enter through trusted update paths and signed dependencies.
- Insider threats may exploit authorized access while remaining within nominal policy boundaries.
- Recovery systems and backups may themselves become targets, eliminating the ability to restore operations.
- Air-gapped and high-side environments may require local, auditable decision-making without reliance on external services.

The core challenge is therefore not only detection. It is maintaining **resilient command and control over defensive action** after compromise is assumed.

## Solution

CERBERUS Cyber introduces a three-layer runtime assurance architecture that continuously evaluates whether a proposed defensive action is permitted, justified, bounded, and reversible.

### Layer 1 — Sentinel Intelligence

The Sentinel layer ingests and correlates security-relevant telemetry from sources such as identity systems, endpoint tools, network sensors, cloud control planes, AI-agent tool calls, privileged access workflows, software supply-chain signals, and recovery infrastructure.

It produces threat hypotheses, confidence scores, blast-radius estimates, ATT&CK-aligned behavior mappings, recommended actions, and human-readable evidence summaries.

The Sentinel layer is advisory. It is explicitly treated as fallible and potentially vulnerable to model error, adversarial manipulation, prompt injection, or compromised data sources.

### Layer 2 — Guardian Policy Engine

The Guardian layer is the core safety and positive-control mechanism. It evaluates every proposed action against deterministic policy.

Authorization may depend on independent evidence count, confidence thresholds, asset criticality, mission impact, action scope, reversibility, blast-radius limits, data classification, network enclave, human authorization requirements, and continuity-of-operations constraints.

The Guardian may approve, approve with constraints, escalate, or deny.

This separation ensures that intelligence does not become authority merely because it is confident.

### Layer 3 — Enforcement & Recovery Kernel

The enforcement layer is deliberately minimal. It uses least-privilege connectors to execute only approved actions such as revoking a session, requiring step-up authentication, isolating a host, disabling a compromised key, blocking a malicious destination, preserving evidence, snapshotting state, restoring configuration, or initiating a tested recovery workflow.

The kernel does not independently interpret threats. It enforces signed, authorized decisions and records each action in an auditable log.

## Technical Differentiation

### Separation of Intelligence from Authority

Most autonomous defensive concepts combine detection, reasoning, and response in one system. CERBERUS Cyber separates those functions so that an intelligent model cannot directly exercise unrestricted operational control.

### Deterministic Policy Enforcement

The Guardian Policy Engine uses explicit, machine-testable rules rather than opaque model judgment. This makes authorization behavior reproducible, auditable, and suitable for formal verification efforts.

### Safety Invariants

CERBERUS Cyber defines actions that remain forbidden regardless of model confidence, including autonomous backup deletion, automated retaliation, offensive exploit execution, destructive remediation without authorization, direct AI access to enforcement credentials, and execution without a logged authorization decision.

### Reversible-First Containment

The platform favors actions that can be safely reversed: isolation, suspension, token revocation, quarantine, snapshotting, and rollback.

### Human-on-the-Loop Control

High-impact actions remain subject to human approval, while narrowly bounded, low-impact actions may be preauthorized under strict policy.

### Resilience Against Adversary Manipulation

The architecture is designed to reduce the impact of prompt injection, telemetry poisoning, compromised connectors, malicious updates, insider misuse, supply-chain compromise, adversary-induced false positives, and rogue automation.

## Security Posture

CERBERUS Cyber is defensive-only and safety-first.

The project does not include exploit development, credential theft, destructive payloads, unauthorized scanning, automated retaliation, counterattack capability, or autonomous irreversible remediation.

The current simulator is side-effect free. It does not connect to operational systems or execute real containment.

Security design goals include least-privilege service identities, signed policy artifacts, immutable decision logs, policy versioning, dual authorization for high-impact changes, connector isolation, local deployment, no mandatory public-cloud dependency for core decisions, and compatibility with disconnected or high-side environments.

## Mission-Relevant Use Cases

- **Identity compromise:** revoke sessions or require step-up authentication without destructively deleting accounts.
- **Ransomware containment:** isolate a host and protect shares only after independent evidence thresholds are met.
- **AI-agent prompt injection:** deny tool use outside signed scope or without trusted authorization context.
- **Supply-chain compromise:** correlate provenance, runtime behavior, and policy violations before rollback.
- **Insider threat:** require corroborating evidence and mission-aware scope controls.
- **Recovery infrastructure protection:** block attempts to disable backups, delete snapshots, or alter recovery policy.

## Why This Matters to the Intelligence Community

IC and DoD environments require defensive systems that can operate under persistent adversary pressure while preserving mission continuity, chain of command, and accountability.

CERBERUS Cyber emphasizes assume breach, blast-radius limitation, positive control, auditable decisions, human-on-the-loop authority, deterministic policy, resilience to prompt injection and supply-chain compromise, protection of AI agents and identity systems, and deployment paths for disconnected or high-side networks.

The architecture is especially relevant where AI-assisted systems are expected to support analysts or operators but cannot be permitted to independently exercise unrestricted authority.

## Current Prototype

The repository currently includes:

- a deterministic Python policy simulator
- a formal threat model
- explicit safety invariants
- versioned Guardian policies
- four safe simulated attack scenarios
- tests proving forbidden actions are blocked
- GitHub Actions CI
- a gap-closure plan
- an integration strategy
- a measurable evaluation framework

Supported scenarios:

- ransomware behavior
- stolen administrator session
- prompt injection against an AI agent
- suspicious data exfiltration

No claim of production readiness is made.

## Try the Simulator

Requires Python 3.10 or newer.

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

Define protected assets, mission owners, operator roles, approval boundaries, safety invariants, privacy constraints, emergency procedures, and unacceptable failure modes.

### Phase 1 — Read-Only Observer

Integrate representative telemetry sources, normalize events, correlate suspicious behavior, generate evidence-backed recommendations, and measure false-positive rates without taking action.

### Phase 2 — Human-Approved Containment

Introduce reversible defensive actions such as session revocation, endpoint isolation, workload quarantine, step-up authentication, and evidence preservation. Every action requires explicit approval.

### Phase 3 — Bounded Automation

Preauthorize a narrow set of low-impact, reversible actions under strict evidence, scope, and mission-impact thresholds. Maintain human-on-the-loop oversight.

### Phase 4 — Recovery Assurance

Add tested rollback, restoration, credential rotation, configuration recovery, and post-action verification.

### Phase 5 — Classified and Mission Integration

Potential future extensions may include integration with existing IC or DoD security tooling, SCIF-compatible deployment, support for air-gapped enclaves, classified policy packs, local model inference, hardware-backed identity, signed policy attestation, and deployment-specific accreditation evidence.

Any classified extension would require sponsorship, accreditation, and deployment-specific security engineering.

## Transition and Funding Paths

Natural transition paths may include a government-sponsored prototype, SBIR/STTR topic alignment, Zero Trust modernization efforts, AI assurance programs, identity and cloud security pilots, and mission-partner integration with existing SOC and SIEM/SOAR tooling.

A practical first government engagement would be a limited-scope, unclassified evaluation using synthetic telemetry and existing agency-approved defensive tools.

## Repository Structure

```text
cerberuscyber/
├── .github/workflows/tests.yml
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
├── docs/
│   ├── architecture.md
│   ├── SAFETY_INVARIANTS.md
│   ├── THREAT_MODEL.md
│   ├── ONE_PAGE_PITCH.md
│   ├── GAP_CLOSURE_PLAN.md
│   ├── INTEGRATION_STRATEGY.md
│   └── EVALUATION_FRAMEWORK.md
├── policies/
├── simulator/
└── tests/
```

## Core Principle

**Intelligence is not authority.**

An adversary may deceive an intelligent layer. That deception must not automatically grant operational control.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 Emily Echt.
