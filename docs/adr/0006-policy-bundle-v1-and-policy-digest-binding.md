# ADR 0006: PolicyBundle v1 and Exact Policy-Digest Binding

- Status: Proposed
- Date: 2026-07-20
- Workstream: C — externalized, auditable Guardian policy

## Context

Guardian previously accepted an arbitrary Python dictionary and bound authorization artifacts only to the policy version string. That left two assurance gaps:

1. malformed or internally contradictory policy could reach the trusted authorization core;
2. two different policy documents could reuse the same version and produce tokens that were indistinguishable at the enforcement boundary.

Version labels remain useful for human release management, but they are not cryptographic identities.

## Decision

Introduce `PolicyBundle` schema version `1.0.0` as the closed-world input contract for Guardian.

The loader:

- parses UTF-8 JSON while rejecting duplicate object keys;
- rejects unknown and missing fields;
- requires SemVer policy versions;
- validates finite confidence and bounded integer values;
- requires unique policy IDs, evidence signals, scopes, and forbidden actions;
- rejects policies that authorize globally forbidden actions;
- rejects inconsistent approval settings;
- requires deny policies to authorize only `none` at scope `none`;
- rejects escalation signals that can also satisfy an allow policy;
- permits one policy per threat in v1, preventing order-dependent first-match authorization;
- canonicalizes the validated JSON and computes a SHA-256 policy digest.

Guardian accepts either a `PolicyBundle` or a compatibility dictionary that is immediately converted into one. It records the exact digest in every decision and audit record.

DecisionToken is advanced to `1.2.0` and binds both:

- the canonical ActionEnvelope digest; and
- the canonical PolicyBundle digest.

The simulated Enforcement receipt carries the policy version and digest so an authorization can be traced to the exact reviewed policy bytes.

## Consequences

### Positive

- Guardian fails before evaluation when policy is malformed or ambiguous.
- Reusing a version number cannot conceal a changed policy in audit or token artifacts.
- Policy identity is deterministic across JSON key ordering and whitespace.
- The trust core remains model-free, network-free, and side-effect-free.
- The contract is independently testable and represented by Draft 2020-12 JSON Schema.

### Costs and limitations

- PolicyBundle v1 deliberately allows only one policy per threat. More expressive matching requires a future precedence model with explicit conflict analysis.
- SHA-256 identifies policy content but does not establish publisher authenticity. Signed policy manifests and hardware-backed trust roots remain future work.
- The canonicalization profile is deterministic within this implementation but is not yet RFC 8785.
- Compatibility dictionaries cannot reveal duplicate keys already discarded by an upstream JSON parser; repository CLIs therefore use `PolicyBundle.load()` directly.

## Follow-up

1. add signed policy manifests and trusted publisher identities;
2. add explicit activation windows and rollback metadata;
3. evaluate an external OPA/Rego decision point without moving credentials into the policy layer;
4. add cross-language canonicalization vectors;
5. require Enforcement to verify an approved policy-digest allowlist before real connectors are introduced.
