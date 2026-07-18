# ADR 0003: Typed Action Envelopes and One-Time Decision Tokens

- Status: accepted for prototype implementation
- Date: 2026-07-13

## Context

The original simulator passed an untyped incident dictionary directly into Guardian policy evaluation. That was sufficient to demonstrate deterministic rules, but it did not make the authority boundary explicit. It also lacked freshness, replay resistance, target binding, evidence provenance, and a separately verifiable authorization artifact.

## Decision

All proposed actions cross the Sentinel-to-Guardian boundary as a versioned `ActionEnvelope`. An approved Guardian decision may mint a short-lived signed `DecisionToken` that binds the exact action, target, scope, policy version, envelope, nonce, and expiry. The enforcement gateway rejects mismatches and consumes each token once.

## Consequences

Positive:

- the model cannot convert free-form text directly into execution;
- authorization is replay-resistant and target-bound;
- policy and schema changes become testable artifacts;
- the evidence-to-decision-to-execution chain is reconstructable.

Costs and limitations:

- policy authors must maintain stable action and scope vocabularies;
- durable replay protection becomes an operational dependency;
- production signing requires real key management and rotation;
- schema evolution requires explicit compatibility rules.
