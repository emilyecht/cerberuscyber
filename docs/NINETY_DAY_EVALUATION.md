# 90-Day Sponsor Evaluation Design

## Objective

Determine whether a separate deterministic authorization layer reduces harmful automated response without making useful containment unacceptably slow.

## Test Environment

- isolated, unclassified cyber range
- synthetic enterprise of approximately 25–50 hosts
- mock identity provider
- synthetic cloud control-plane events
- endpoint, DNS, and audit telemetry
- simulated AI security agent
- no production connectivity
- CERBERUS side-effect free or restricted to simulated actions

## Baseline

Evaluate two pipelines using identical telemetry and proposed actions.

### Baseline A — Conventional Automation

```text
Detection event → response playbook → simulated execution
```

### CERBERUS B — Assured Automation

```text
Detection event → proposed action → Guardian authorization → simulated execution
```

## Scenario Families

Run multiple benign, malicious, and adversarial variants for:

- stolen administrator session
- ransomware-like behavior
- suspicious data exfiltration
- lateral movement
- cloud privilege escalation
- backup tampering
- insider misuse
- prompt injection against an AI agent
- telemetry poisoning
- adversary-induced false containment

Use ATT&CK for behavior labeling and D3FEND for defensive-technique mapping. Neither framework should be treated as proof of effectiveness.

## Schedule

### Days 1–15 — Instrumentation

- freeze the policy schema and safety invariants
- define baseline playbooks
- build a telemetry replay harness
- define ground truth and mission-impact scoring
- establish immutable experiment logs

### Days 16–35 — Benign and True-Positive Testing

- replay legitimate administration and maintenance windows
- replay true attack scenarios
- measure decision latency, action scope, and false containment

### Days 36–60 — Adversarial Manipulation

- poison one telemetry source
- inject malicious instructions into agent context
- create contradictory indicators
- spoof high confidence
- simulate a compromised connector
- attempt policy-routing and malformed-input bypasses

### Days 61–75 — Policy Stress

- introduce conflicting and stale policies
- test missing evidence
- test unavailable approval channels
- test degraded logging
- measure authoring effort, exception growth, and review time

### Days 76–90 — Independent Review

- external red-team attempts bypass
- independent analyst reconstructs decisions from logs
- policy reviewer evaluates maintainability
- compare results against baseline
- publish failures and unresolved risks

## Metrics

### False-Containment Rate

```text
harmful or unnecessary containment actions / benign scenarios
```

### Denial-of-Defense Resistance

```text
1 - (successful adversary-induced harmful actions / adversarial attempts)
```

### Invariant Integrity

Target: zero violations. A single violation is a critical failure, not an averaged metric.

### Containment Utility

Measure:

- time to approved action
- action scope
- mission assets affected
- mission downtime avoided
- mission downtime caused

### Auditability

An independent reviewer should be able to identify:

- initiating evidence
- policy version
- decision path and reason code
- approver, if required
- simulated execution
- outcome and rollback record

### Policy Verifiability

Track:

- total rules
- conflict count
- percentage exhaustively tested
- review time per change
- exception count
- unreachable rules

## Success Criteria

A credible Phase 1 result would include:

- zero invariant violations
- lower adversary-induced harmful response than baseline
- acceptable latency increase for true positives
- complete decision reconstruction
- manageable policy-authoring effort
- documented failure cases

Numerical thresholds should be agreed with the sponsor before testing rather than selected after results are known.