# CERBERUS Cyber

**Assume compromise. Constrain authority. Contain damage. Recover safely.**

CERBERUS Cyber is a defensive cybersecurity research project that applies the CERBERUS three-layer runtime assurance model to cyber defense.

The project separates intelligence from authority:

1. **Sentinel Intelligence** observes telemetry, correlates suspicious behavior, maps activity to known attack patterns, and proposes a response.
2. **Guardian Policy Engine** checks every proposed action against deterministic rules, evidence requirements, scope limits, reversibility, and human-approval boundaries.
3. **Enforcement and Recovery Kernel** executes only approved containment and recovery actions through tightly scoped integrations.

> Intelligence may recommend. Policy authorizes. The enforcement layer acts.

## Why CERBERUS Cyber

Most security platforms focus on detecting and preventing intrusion. CERBERUS Cyber begins from a harsher assumption: some attacks will get through.

The question becomes:

**How do we stop a compromised account, endpoint, cloud workload, or AI agent from gaining unrestricted authority?**

CERBERUS Cyber is designed around damage containment, reversible response, evidence preservation, and deterministic control.

## Initial Scope

- credential theft and session abuse
- ransomware behavior
- suspicious persistence
- lateral movement
- cloud privilege escalation
- data exfiltration
- prompt injection and AI-agent tool abuse
- compromised connectors, plugins, and automation systems

## Repository Structure

```text
cerberuscyber/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── docs/
│   └── architecture.md
├── policies/
│   ├── README.md
│   └── examples.yaml
└── simulator/
    └── README.md
```

## Project Status

CERBERUS Cyber is currently an early-stage architecture and simulation project. The first milestone is a read-only observer and policy simulator. Autonomous destructive actions are explicitly out of scope.

## Safety Boundaries

This project is defensive only.

CERBERUS Cyber will not include:

- exploit development
- credential theft
- destructive payloads
- offensive scanning of systems without authorization
- automated retaliation or counterattack
- autonomous deletion, wiping, or irreversible remediation

## Roadmap

### Phase 0 — Threat Model and Governance
Define assets, operator roles, action boundaries, approval rules, privacy limits, and emergency procedures.

### Phase 1 — Read-Only Observer
Ingest telemetry, normalize events, identify suspicious patterns, and generate evidence-backed explanations.

### Phase 2 — Human-Approved Containment
Add reversible actions such as session revocation, endpoint isolation, and step-up authentication with mandatory approval.

### Phase 3 — Bounded Automation
Preauthorize a narrow set of low-impact actions under strict evidence and policy thresholds.

### Phase 4 — Recovery Assurance
Add tested rollback, restoration, credential rotation, and verification.

## Core Principle

**Intelligence is not authority.**

An attacker may fool the intelligent layer. They still should not gain unrestricted control.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 Emily Echt.
