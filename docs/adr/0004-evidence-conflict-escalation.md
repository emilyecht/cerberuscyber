# ADR 0004: Escalate on Cross-Signal Evidence Conflict

- **Status:** Accepted
- **Date:** 2026-07-18
- **Policy bundle:** `0.5.0`

## Context

The adversarial persistence policy previously evaluated positive behavior labels, independent-source count, confidence, scope, reversibility, and human approvals. It did not have an explicit representation for a trusted observer contradicting another observer.

Without a conflict rule, a complete-looking evidence set could satisfy `CYBER-EA-001` even when one independent source reports that a required behavior did not occur. Treating the contradiction as merely another confidence input would give the analytical layer too much influence over authorization.

## Decision

1. Sentinel normalizes a contradictory observer report as `cross_signal_inconsistency`.
2. The contradiction is included in the advisory finding and evidence provenance.
3. The contradiction does **not** count toward Sentinel's minimum corroborating-signal threshold.
4. Guardian loads a versioned global `escalation_signals` list from the policy bundle.
5. Guardian checks configured escalation signals before policy-specific authorization.
6. Presence of `cross_signal_inconsistency` returns:
   - decision: `escalate`;
   - policy identifier: `GLOBAL-EVIDENCE-CONFLICT`;
   - no decision token;
   - human review required.
7. Enforcement remains unreachable because only an approved decision can mint a token.

## Rationale

This preserves the central authority rule: intelligence may describe uncertainty, but it may not resolve contradictory evidence in its own favor. The deterministic layer converts unresolved conflict into a review requirement rather than allowing model confidence, urgency, or approvals to erase it.

The rule is global because contradictory evidence is an authority-boundary concern, not a threat-specific optimization.

## Consequences

### Positive

- complete-looking but internally inconsistent evidence cannot authorize mutation;
- policy behavior is explicit, versioned, reproducible, and testable;
- the decision path records a stable reason code for audit and sponsor evaluation;
- contradiction events cannot help weak evidence meet Sentinel's finding threshold.

### Negative

- forged contradiction events could create denial-of-defense pressure;
- source independence is represented by identifiers in the prototype, not cryptographic trust roots;
- human review latency becomes part of the containment tradeoff;
- a global rule may be too coarse for future low-impact read-only actions.

## Detection and Recovery

- monitor conflict frequency and repeated contradiction sources;
- bind future source IDs to authenticated, attested collectors;
- preserve raw evidence references for replay and adjudication;
- fail closed to the last known-good signed policy bundle if regression tests fail;
- require a policy version bump before changing conflict semantics.

## Alternatives Considered

### Subtract confidence and continue evaluation

Rejected because confidence is informational and must not become an implicit authorization mechanism.

### Let Sentinel choose the trusted observer

Rejected because the untrusted intelligence layer would then control which evidence is authoritative.

### Deny all conflicted requests permanently

Rejected for the prototype because some conflicts may be sensor faults or benign synchronization errors. Escalation preserves safety while allowing human adjudication.
