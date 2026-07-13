# CERBERUS Cyber

**Assume compromise. Constrain authority. Contain damage. Recover safely.**

CERBERUS Cyber is a defensive cybersecurity research project that applies the CERBERUS three-layer runtime assurance model to cyber defense.

The project separates intelligence from authority:

1. **Sentinel Intelligence** observes telemetry, correlates suspicious behavior, maps activity to known attack patterns, and proposes a response.
2. **Guardian Policy Engine** checks every proposed action against deterministic rules, evidence requirements, scope limits, reversibility, and human-approval boundaries.
3. **Enforcement and Recovery Kernel** executes only approved containment and recovery actions through tightly scoped integrations.

> Intelligence may recommend. Policy authorizes. The enforcement layer acts.

## Current Status

**Research prototype with a working deterministic policy simulator.**

The repository now includes:

- a formal threat model
- explicit safety invariants
- versioned Guardian policies
- four safe simulated attack scenarios
- a Python policy evaluator
- unit tests proving forbidden actions are blocked
- GitHub Actions CI

No real containment actions are performed. The simulator is intentionally side-effect free.

## Try the Simulator

Requires Python 3.10 or newer.

```bash
python simulator/cerberus_sim.py simulator/scenarios/ransomware.json
python simulator/cerberus_sim.py simulator/scenarios/stolen_admin_session.json
python simulator/cerberus_sim.py simulator/scenarios/prompt_injection.json
python simulator/cerberus_sim.py simulator/scenarios/data_exfiltration.json
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

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
├── .github/workflows/tests.yml
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
├── docs/
│   ├── architecture.md
│   ├── SAFETY_INVARIANTS.md
│   └── THREAT_MODEL.md
├── policies/
│   ├── README.md
│   ├── examples.yaml
│   └── policies.json
├── simulator/
│   ├── README.md
│   ├── cerberus_sim.py
│   └── scenarios/
│       ├── data_exfiltration.json
│       ├── prompt_injection.json
│       ├── ransomware.json
│       └── stolen_admin_session.json
└── tests/
    └── test_simulator.py
```

## Safety Boundaries

This project is defensive only.

CERBERUS Cyber will not include:

- exploit development
- credential theft
- destructive payloads
- offensive scanning of systems without authorization
- automated retaliation or counterattack
- autonomous deletion, wiping, or irreversible remediation

See [Safety Invariants](docs/SAFETY_INVARIANTS.md) and [Threat Model](docs/THREAT_MODEL.md).

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
