# CERBERUS Cyber — Skeptical Technical Review

CERBERUS Cyber is a research prototype, approximately TRL 2–3. This document records the strongest technical objections to the architecture and the current, honest response to each.

## 1. “This is SOAR with an extra approval layer”

**Objection:** Commercial SOAR and XDR products already combine telemetry, playbooks, approvals, and automated containment. CERBERUS may only rename familiar components.

**Current response:** CERBERUS does not claim to replace SOAR or XDR. Its proposed contribution is a separate, cross-platform authorization boundary between analysis and consequential action. The distinction is architectural:

- the analytical layer does not hold enforcement credentials;
- safety invariants apply globally, not only inside one playbook;
- authorization is deterministic, versioned, and independently testable;
- adversary-induced defensive action is treated as a first-class threat.

This remains a hypothesis until evaluated against a representative SOAR baseline.

## 2. “Deterministic policy will not scale”

**Objection:** Real cyber operations are too contextual for maintainable deterministic rules. Policies may conflict, age poorly, or block urgent response.

**Current response:** Guardian policy is intentionally scoped to authorization properties rather than full threat interpretation. The Guardian should answer a narrower question:

> Even if the threat hypothesis is correct, is this action authorized under these conditions?

Policy should focus on action type, scope, protected assets, reversibility, evidence independence, mission impact, approval requirements, and forbidden combinations.

This risk cannot be argued away. Policy-authoring effort, conflict rate, exception growth, and review time must be measured.

## 3. “The Guardian is a single point of failure”

**Objection:** The architecture moves authority into a new high-value target. A compromised Guardian could authorize arbitrary action, suppress response, or falsify audit trails.

**Current response:** Correct. Determinism does not imply trustworthiness. The Guardian requires a separate assurance case built around:

- a minimal trusted computing base;
- signed and versioned policy bundles;
- dual authorization for policy changes;
- append-only external audit logs;
- hardware-backed service identity;
- reproducible builds;
- fail-safe behavior on integrity failure;
- recovery to a last-known-good signed policy set;
- independent monitoring of the Guardian.

Replication may improve availability, but shared code and policy can preserve common-mode failure.

## 4. “There is no evidence of operational advantage”

**Objection:** The current simulator proves only that a Python program can reject actions defined as forbidden.

**Current response:** Valid. The prototype does not yet prove better detection, lower false containment, acceptable latency, secure integration, or analyst usability.

The next evidence milestone is a controlled comparison against a baseline automation pipeline using identical synthetic telemetry, proposed actions, and mission-impact scoring.

## 5. “Single-developer provenance is insufficient”

**Objection:** Threat model, architecture, policies, and tests are self-authored. There is no independent validation.

**Current response:** Also valid. Open source, CI, and documented invariants make scrutiny possible, but do not replace independent review.

Required mitigations:

- external threat-model review;
- independent red-team attempts to bypass Guardian;
- review by a formal-methods practitioner;
- sponsor-defined acceptance criteria;
- publication of negative results;
- comparison to a reference SOAR implementation.

## Current Position

The strongest defensible claim is narrow:

> CERBERUS Cyber investigates whether a separate deterministic authorization layer can reduce the authority gained from compromising or deceiving an intelligent defensive component.

No claim of production readiness, formal verification, operational superiority, or complete cyber safety is made.