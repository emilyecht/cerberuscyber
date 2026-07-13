# CERBERUS Cyber Gap-Closure Plan

## Purpose

This plan turns the current deterministic simulator into a credible defensive research platform without overstating production readiness.

## Current Gaps

1. No operational telemetry integrations.
2. Side-effect-free simulator only.
3. Python prototype without deployment packaging.
4. Limited scenario and policy coverage.
5. No measured benchmark dataset or evaluation report.
6. No browser-based demonstration.

## Workstreams

### Workstream A — Telemetry Replay

Convert the simulator from hand-authored scenario evaluation into a replay engine for normalized security events.

Deliverables:

- versioned normalized event schema
- JSONL replay adapter
- synthetic Windows, identity, cloud, DNS, and AI-agent event packs
- timestamp-aware correlation
- evidence provenance and sensor-health fields

Success criteria:

- at least 100 replayable synthetic events
- four end-to-end incident timelines
- reproducible decisions from identical input
- complete audit output for every decision

### Workstream B — Read-Only Integrations

Integrate with existing defensive systems rather than building a replacement EDR.

Priority sequence:

1. generic JSONL/syslog import
2. Microsoft Entra ID sign-in logs
3. AWS CloudTrail and GuardDuty findings
4. Microsoft Defender or Elastic Security export
5. Okta system logs

Initial connectors remain read-only and operate on exported or replayed data.

### Workstream C — Guardian Policy Language

Move policy logic out of Python conditionals and into versioned policy artifacts.

Required capabilities:

- explicit evidence thresholds
- asset criticality and mission-impact tags
- scope limits
- reversibility requirements
- human approval gates
- global safety invariants
- deterministic decision outcomes

### Workstream D — Evaluation

Measure the platform instead of relying on architectural claims.

Core metrics:

- mean time to detect
- mean time to authorize
- mean time to contain in simulation
- false-positive containment rate
- unsafe-action rejection rate
- rollback eligibility rate
- evidence completeness
- policy coverage by ATT&CK technique

### Workstream E — Human-Approved Containment Harness

Introduce a mock connector boundary before any real action integration.

Every action request must include:

- signed policy decision
- action scope
- expiration time
- rollback plan
- operator identity
- immutable audit record

The first live integrations should be reversible and narrowly scoped, such as revoking a test token or isolating a lab endpoint.

### Workstream F — Demonstration Layer

Build a browser-based dashboard that shows:

- incoming telemetry
- Sentinel recommendation
- Guardian decision
- applicable policy and safety invariant
- approved scope
- simulated enforcement result
- audit timeline

## Milestones

### Milestone 1 — Replayable Observer

- normalized event schema
- JSONL adapter
- synthetic event packs
- deterministic replay tests

### Milestone 2 — Policy Laboratory

- externalized policy format
- schema validation
- policy unit tests
- unsafe-proposal test corpus

### Milestone 3 — Read-Only Connectors

- one identity connector
- one cloud connector
- one endpoint or SIEM connector
- connector health and provenance logging

### Milestone 4 — Human-Approved Lab Action

- approval workflow
- mock enforcement connector
- reversible test action
- rollback verification

### Milestone 5 — Bounded Automation Experiment

- preauthorized low-impact actions
- hard scope and time limits
- operator override
- post-action verification

## Non-Goals

CERBERUS Cyber will not pursue exploit development, retaliation, destructive payloads, credential theft, or autonomous irreversible remediation.
