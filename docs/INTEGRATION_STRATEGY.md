# CERBERUS Cyber Integration Strategy

## Integration Principle

CERBERUS Cyber should coordinate and constrain existing defensive tools rather than attempt to replace endpoint, identity, cloud, SIEM, or backup platforms.

The transition path is:

1. exported telemetry
2. read-only APIs
3. recommendation mode
4. human-approved reversible actions
5. narrowly bounded automation

## Connector Trust Model

Every connector is treated as potentially faulty or compromised.

Required controls:

- least-privilege service identity
- explicit read and write scopes
- connector-specific allowlists
- signed action requests
- short-lived authorization tokens
- rate and blast-radius limits
- health and provenance reporting
- immutable audit output
- independent revocation and kill switch

The Sentinel layer never receives standing administrative credentials.

## Priority Integrations

### Tier 0 — Portable Research Inputs

- JSONL event replay
- CSV import
- syslog-compatible normalized input
- synthetic ATT&CK-aligned scenarios

Purpose: enable reproducible evaluation without vendor dependencies.

### Tier 1 — Identity and Cloud, Read-Only

- Microsoft Entra ID sign-in and audit exports
- Okta system logs
- AWS CloudTrail
- Amazon GuardDuty findings
- Azure activity logs

Purpose: demonstrate cross-domain correlation around credential compromise and privilege escalation.

### Tier 2 — Endpoint and SIEM, Read-Only

- Microsoft Defender export or API
- Elastic Security export
- Splunk search export
- OpenTelemetry security events

Purpose: correlate endpoint behavior with identity and cloud activity.

### Tier 3 — AI-Agent Control Plane

- signed tool-call envelopes
- tool allowlists
- argument validation
- secret-access policies
- retrieval provenance
- prompt-injection indicators

Purpose: prove that AI recommendations and tool calls can be separated from authority.

### Tier 4 — Human-Approved Reversible Actions

Candidate lab actions:

- revoke a test session
- require step-up authentication
- isolate a lab endpoint
- quarantine a workload
- disable a test API key
- block a lab destination
- preserve a forensic snapshot

No production action should be attempted until policy, rollback, and audit requirements are met.

## Normalized Event Contract

Every event should include:

- event ID
- timestamp
- source type
- source product
- subject identity or asset
- action
- outcome
- evidence provenance
- sensor health
- classification or sensitivity tag
- raw event reference

## Normalized Action Contract

Every proposed action should include:

- incident ID
- action type
- target
- requested scope
- duration
- reversibility
- rollback procedure
- evidence references
- policy decision
- policy version
- approval identity when required
- expiration time

## Deployment Modes

### Developer Mode

Local replay, synthetic telemetry, no external credentials.

### Evaluation Mode

Read-only connectors, local policy engine, full audit output.

### Lab Containment Mode

Human-approved reversible actions against isolated test assets.

### High-Side Candidate Mode

Future deployment profile requiring local dependencies, offline installation, signed artifacts, hardware-backed identity, accreditation evidence, and no mandatory external service.

## Exit Criteria for Read-Only Phase

CERBERUS Cyber should not advance to action execution until:

- at least three telemetry domains are correlated
- connector failures are surfaced
- event provenance is preserved
- safety-invariant tests pass
- false-positive analysis is published
- every proposed action has a policy trace
- rollback paths are documented for the first action set
