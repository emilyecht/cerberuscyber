# Correlated-Failure Audit Method

CERBERUS Cyber treats shared-fate dependencies as a first-class security problem. Redundancy is not meaningful when detection, authorization, enforcement, identity, logging, and recovery depend on the same models, credentials, vendors, update channels, or infrastructure.

This document defines a repeatable audit method.

## 1. Build a Defensive Dependency Graph

Represent each critical function as a node:

- sensors and telemetry sources
- telemetry pipelines
- detection models and rules
- Guardian policy engine
- policy repository
- identity provider
- secret store
- update service
- connector
- enforcement credential
- audit store
- backup and recovery system
- human approval channel
- cloud, vendor, or network dependency

Represent dependencies as directed edges:

- consumes telemetry from
- authenticates through
- is updated by
- shares credentials with
- runs on the same host as
- depends on the same vendor
- uses the same model or codebase as
- writes to the same audit store
- is administered by the same role
- depends on the same network path
- recovers through

## 2. Classify Shared-Fate Dependencies

For every pair of critical functions, record whether they share:

- model provider
- codebase
- build pipeline
- deployment platform
- identity root
- secret store
- telemetry source
- update channel
- administrator
- network path
- time source
- vendor
- recovery dependency

## 3. Calculate Shared-Fate Exposure

A prototype metric may be expressed as:

```text
SFE = Σ (dependency_weight × critical_function_count × authority_consequence)
```

Where:

- `dependency_weight` reflects the severity of the dependency class;
- `critical_function_count` is the number of control functions sharing the dependency;
- `authority_consequence` estimates the operational impact if the dependency is compromised.

This is an audit aid, not a universal security score.

A simpler sponsor-facing metric is:

> Percentage of critical defensive actions for which detection, authorization, and enforcement share at least one root of trust.

## 4. Flag Unacceptable Patterns

Examples include:

- Sentinel and Guardian updated through the same unsigned pipeline;
- Sentinel and Enforcement sharing an administrative credential;
- Guardian logs stored only on the Guardian host;
- all independent evidence originating from one vendor;
- human approval relying on the same identity session under investigation;
- backup policy and backup deletion using the same service account;
- model and policy artifacts fetched through the same unverified channel.

## 5. Test High-Centrality Dependencies

For each dependency with high centrality or authority consequence:

1. simulate compromise or failure;
2. identify which layers lose integrity or availability;
3. measure whether unauthorized action becomes possible;
4. measure whether audit reconstruction remains possible;
5. test recovery without the compromised dependency.

## 6. Report Measurable Outputs

The audit should report:

- maximum authority obtained from compromise of any one component;
- number of single-component compromises yielding cross-layer control;
- percentage of actions supported by genuinely independent evidence;
- number of shared administrative roots across layers;
- number of unmonitored update paths;
- percentage of audit records stored outside the component being audited;
- recovery success after compromise of each critical dependency.

## Exit Criterion

CERBERUS should not advance to human-approved or bounded automation until no single non-Guardian compromise grants unrestricted cross-layer authority, and until the Guardian itself has an explicit assurance and recovery plan.