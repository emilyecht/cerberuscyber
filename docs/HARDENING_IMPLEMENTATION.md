# CERBERUS Hardening Implementation

This increment turns the original policy simulator into a clearer runtime-assurance prototype while keeping every action side-effect free.

## Implemented trust boundary

```text
untrusted incident / Sentinel proposal
                |
                v
        typed ActionEnvelope
                |
                v
     deterministic Guardian core
       | policy | invariants |
                |
        short-lived signed token
                |
                v
     strict EnforcementGateway
        (simulation only)
```

The Guardian remains the trusted decision point. It does not call a model, retrieve arbitrary data, or execute an action. The enforcement gateway does not reinterpret intent. It requires an exact match for action, target, and scope.

## Controls added

- Versioned, typed `ActionEnvelope` with freshness, nonce, target, scope, reversibility, evidence provenance, and approvals.
- Deny-by-default policy evaluation with globally forbidden actions.
- Evidence-independence checks so two signals from one source do not masquerade as corroboration.
- Scope ordering that prevents an approved single-endpoint action from widening to an enterprise action.
- Reversibility requirements and human-approval gates.
- Short-lived HMAC-signed decision tokens for the research prototype.
- One-time token consumption and replay rejection.
- Append-only hash-chained audit records for Guardian and simulated enforcement events.
- JSON Schemas for the action envelope and decision-token payload.
- Expanded tests for expiry, replay, target substitution, shared-source evidence, and scope expansion.
- CI hardening with read-only permissions, pinned action commits, a Python version matrix, compile checks, and JSON validation.

## Important claim boundary

The HMAC signer and in-memory replay/audit components are prototype mechanisms. They demonstrate the interface and invariants; they are not a production key-management or audit system. A production implementation should use hardware-backed asymmetric signing, durable atomic replay state, externally anchored tamper-evident logs, service identity, authenticated protected channels, and independently reviewed policy bundles.

## Next implementation increments

1. Replace legacy scenario adaptation with native `ActionEnvelope` producers.
2. Externalize Guardian policy to OPA/Rego and test equivalence against the Python reference evaluator.
3. Add a read-only telemetry replay service and connector contract tests.
4. Add a human approval service with authenticated approver identity and dual control for high-impact actions.
5. Move the trusted Guardian and enforcement gateway into a smaller independently deployable service.
6. Add SBOM, dependency review, release signing, and provenance attestations.
7. Run adversarial evaluation against prompt injection, telemetry poisoning, token replay, policy bypass, and connector compromise fixtures.
