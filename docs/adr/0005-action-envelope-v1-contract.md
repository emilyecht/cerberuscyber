# ADR 0005: Versioned ActionEnvelope v1.0.0 Contract

- Status: Accepted
- Date: 2026-07-18

## Context

The first Guardian hardening increment introduced a typed Python envelope, but its wire form still used prototype field names and did not bind actor identity, exact policy version, idempotency, or a canonical envelope digest into the decision token. That left future Sentinel, Guardian, and Enforcement services vulnerable to contract drift and ambiguous migrations.

Workstream A also increased the adversarial fixture corpus. Before externalizing policy or adding connectors, CERBERUS needs one stable, machine-valid membrane that every test and service can share.

## Decision

Adopt `ActionEnvelope` v1.0.0 as the canonical proposal contract.

1. The public JSON representation is governed by JSON Schema Draft 2020-12.
2. The reference Python dataclass lives in `sdk/shared_types/action_envelope.py`.
3. Canonical JSON and SHA-256 digest computation are part of the contract.
4. Guardian requires an exact policy-version match and rejects reused idempotency keys.
5. DecisionToken v1.1.0 binds the envelope digest, idempotency key, and proposing actor.
6. The pre-v1 simulator representation remains available only through an explicit compatibility adapter.
7. Unknown actions, unknown scopes, malformed freshness, and unsupported schema versions fail closed.

Known destructive action names remain parseable solely to produce explicit Guardian denials and audit records. Their presence in the recognized vocabulary does not make them allowable.

## Consequences

### Positive

- Sentinel output cannot silently change shape at the Guardian boundary.
- Policy bundles and envelopes negotiate exact versions instead of assuming compatibility.
- Decision tokens are cryptographically bound to the precise envelope Guardian evaluated.
- Duplicate evaluation attempts become visible and deny-by-default.
- Cross-language implementations have a concrete schema and test oracle.

### Negative

- The Python object temporarily retains compatibility aliases such as `proposed_action` and `requested_scope`.
- The in-memory idempotency registry does not provide multi-process or restart durability.
- The repository's deterministic JSON encoding is not yet a formally standardized cross-language canonicalization profile.
- Token version changes from 1.0 to 1.1.0, requiring consumers to update in lockstep.

## Alternatives considered

### Keep the prototype Python-only contract

Rejected because type hints do not provide a stable wire protocol, version negotiation, or independent validation.

### Move directly to OPA/Rego first

Rejected because Rego policy would otherwise be written against an unstable input shape and immediately require migration.

### Accept arbitrary action strings and rely only on policy

Rejected because malformed or unknown action types should be rejected before reaching authorization logic.

### Make idempotency an Enforcement-only concern

Rejected because repeated Guardian evaluation can mint multiple valid tokens before Enforcement sees any of them. Exact-once semantics begin at the authority decision boundary.

## Follow-up

- Replace the in-memory idempotency registry with a durable atomic implementation.
- Add cross-language canonicalization vectors before non-Python services sign envelopes.
- Use this contract as the input to Workstream C's external policy decision point.
- Remove the pre-v1 adapter before operational write connectors are enabled.
