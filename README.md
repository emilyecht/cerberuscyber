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

The Sentinel layer ingests and correlates security-relevant telemetry from sources such as:

- identity and access systems
- endpoint detection and response tools
- network and DNS telemetry
- cloud control-plane logs
- AI-agent tool calls and retrieval activity
- privileged access workflows
- software supply-chain signals
- backup and recovery infrastructure

It produces:

- threat hypotheses
- confidence scores
- likely blast-radius estimates
- ATT&CK-aligned behavior mappings
- recommended containment or recovery actions
- human-readable evidence summaries

The Sentinel layer is advisory. It is explicitly treated as fallible and potentially vulnerable to model error, adversarial manipulation, prompt injection, or compromised data sources.

### Layer 2 — Guardian Policy Engine

The Guardian layer is the core safety and positive-control mechanism. It evaluates every proposed action against deterministic policy.

Authorization may depend on:

- independent evidence count
- confidence thresholds
- asset criticality
- mission impact
- action scope
- reversibility
- blast-radius limits
- user or system identity
- data classification
- network enclave
- time-bounded approval
- human authorization requirements
- continuity-of-operations constraints

The Guardian may return one of several outcomes:

- **Approve** — action is within policy and may proceed.
- **Approve with constraints** — action is narrowed in scope or duration.
- **Escalate** — human review is required.
- **Deny** — action violates policy or a safety invariant.

This separation ensures that intelligence does not become authority merely because it is confident.

### Layer 3 — Enforcement & Recovery Kernel

The enforcement layer is deliberately minimal. It uses least-privilege connectors to execute only approved actions, such as:

- revoke a session or token
- require step-up authentication
- isolate a host or workload
- disable a compromised key
- block a known malicious destination
- quarantine a suspicious automation path
- preserve forensic evidence
- snapshot a system state
- restore a known-good configuration
- initiate a tested recovery workflow

The kernel does not independently interpret threats. It enforces signed, authorized decisions and records each action in an auditable log.

## Technical Differentiation

### Separation of Intelligence from Authority

Most autonomous defensive concepts combine detection, reasoning, and response in one system. CERBERUS Cyber separates those functions so that an intelligent model cannot directly exercise unrestricted operational control.

### Deterministic Policy Enforcement

The Guardian Policy Engine uses explicit, machine-testable rules rather than opaque model judgment. This makes authorization behavior reproducible, auditable, and suitable for formal verification efforts.

### Safety Invariants

CERBERUS Cyber defines actions that remain forbidden regardless of model confidence. Example invariants include:

- no autonomous deletion of backups
- no automated retaliation or counterattack
- no offensive exploit execution
- no destructive remediation without explicit authorization
- no direct access by the AI layer to enforcement credentials
- no execution without a logged authorization decision
- no broad-scope containment without mission-impact checks

### Reversible-First Containment

The platform favors actions that can be safely reversed: isolation, suspension, token revocation, quarantine, snapshotting, and rollback. This reduces the operational cost of false positives.

### Human-on-the-Loop Control

High-impact actions remain subject to human approval, while narrowly bounded, low-impact actions may be preauthorized under strict policy. This supports speed without surrendering positive control.

### Resilience Against Adversary Manipulation

The architecture is designed to reduce the impact of:

- prompt injection against AI agents
- telemetry poisoning
- compromised connectors and plugins
- malicious software updates
- insider misuse of valid credentials
- supply-chain compromise
- adversary-induced false positives
- rogue or misconfigured automation

## Security Posture

CERBERUS Cyber is defensive-only and safety-first.

The project does not include:

- exploit development
- credential theft
- destructive payloads
- unauthorized scanning
- automated retaliation
- counterattack capability
- autonomous wiping or irreversible remediation

The current simulator is side-effect free. It does not connect to operational systems or execute real containment.

Security design goals include:

- least-privilege service identities
- signed policy artifacts
- immutable decision logs
- policy versioning
- dual authorization for high-impact changes
- connector isolation
- local deployment options
- no dependence on public cloud services for core decision-making
- compatibility with disconnected, air-gapped, or high-side environments
- explicit data-retention and privacy controls

## Mission-Relevant Use Cases

### Identity Compromise

A valid administrator session begins performing unusual privilege changes. Sentinel correlates behavior across identity, cloud, and endpoint telemetry. Guardian authorizes session revocation and step-up authentication but rejects destructive account deletion.

### Ransomware Containment

A host begins rapid file modification, attempts to disable recovery mechanisms, and accesses sensitive shares. Guardian allows reversible host isolation and share protection only after independent evidence thresholds are met.

### AI-Agent Prompt Injection

An AI assistant receives malicious instructions embedded in a document or web result and attempts to access secrets or invoke administrative tools. Guardian denies tool use that exceeds the agent's approved scope or lacks a signed authorization context.

### Supply-Chain Compromise

A trusted component introduces suspicious behavior after an update. CERBERUS Cyber correlates provenance, runtime behavior, and policy violations before allowing containment or rollback.

### Insider Threat

A valid user begins accessing sensitive data outside normal mission patterns. Sentinel raises the event, but Guardian requires corroborating evidence and mission-aware scope controls before any disruptive action.

### Recovery Infrastructure Protection

An attacker attempts to disable backups, delete snapshots, or modify recovery policies. Safety invariants block destructive actions and escalate the event for human review.

## Why This Matters to the Intelligence Community

IC and DoD environments require defensive systems that can operate under persistent adversary pressure while preserving mission continuity, chain of command, and accountability.

CERBERUS Cyber is aligned with those needs because it emphasizes:

- **assume breach** rather than trust perimeter integrity
- **limit blast radius** rather than rely on perfect prevention
- **positive control** over every high-impact action
- **auditable decisions** suitable for after-action review and oversight
- **human-on-the-loop authority** for mission-sensitive operations
- **deterministic policy** instead of opaque automation
- **resilience to prompt injection, insider threats, and supply-chain compromise**
- **protection of AI agents, cloud workloads, identity systems, and recovery infrastructure**
- **deployment paths for air-gapped, disconnected, or high-side networks**
- **defensive cyber operations without offensive capability**

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

Potential future extensions may include:

- integration with existing IC or DoD security tooling
- deployment inside SCIF-compatible infrastructure
- support for air-gapped and disconnected enclaves
- classified threat-model and policy packs
- local model inference
- hardware-backed service identity
- policy signing and attestation
- cross-domain guard integration subject to accreditation
- audit and evidence formats aligned to agency requirements

Any classified extension would require sponsorship, accreditation, and deployment-specific security engineering.

## Transition and Funding Paths

Natural transition paths may include:

- a government-sponsored prototype or pilot
- SBIR/STTR topic alignment
- defensive cyber operations research programs
- Zero Trust modernization efforts
- AI assurance and autonomous-system safety initiatives
- identity and cloud security pilot programs
- mission partner integration with existing SOC and SIEM/SOAR tooling

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
│   └── ONE_PAGE_PITCH.md
├── policies/
│   ├── README.md
│   ├── examples.yaml
│   └── policies.json
├── simulator/
│   ├── README.md
│   ├── cerberus_sim.py
│   └── scenarios/
└── tests/
    └── test_simulator.py
```

## Core Principle

**Intelligence is not authority.**

An adversary may deceive an intelligent layer. That deception must not automatically grant operational control.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 Emily Echt.
