# ADR 0007: Preserve the Exact Action Contract Through Authorization

- Status: Proposed
- Date: 2026-09-07

## Context

Three reproduced boundary defects could change a proposal's meaning before it was signed:

1. Action matching ran before an `escalate` policy transitioned to `approve`. A data-exfiltration request for `preserve_evidence` with the required approval could therefore authorize `temporary_egress_hold`.
2. Scope validation used only an ordered ceiling and approval emitted that ceiling. An endpoint-isolation proposal could supply `single_identity` and receive `single_endpoint` authorization.
3. Canonical parsing coerced values before validation. In particular, Python's `bool("false")` made a string-valued reversibility flag true. Missing or extra fields could also be defaulted or discarded.

The signer checked the envelope digest and idempotency key but did not independently verify that the decision's action, target, and scope matched that envelope.

## Decision

- Apply action matching to the final approval decision, including transitions after approval gates.
- Check supported action/scope pairs separately from the policy ceiling. Preserve the exact requested scope on approval.
- At signing, compare the decision's action, target, scope, reversibility, actor, envelope and incident IDs, and policy version to the validated envelope, in addition to existing digest and idempotency bindings. Reject unsupported action/scope pairs.
- Validate the original canonical dictionary against the existing v1.0.0 JSON Schema before conversion. Reject wrong types, absent required fields, unknown fields, and malformed nested evidence. Reject non-finite confidence and validate direct Python construction as well.
- Keep legacy fixture conversion explicit. `from_dict()` accepts only canonical v1.0.0; pre-v1 callers use `from_legacy_envelope_dict()`. Neither legacy adapter coerces supplied authority fields.
- Declare schema and date-time validation as runtime dependencies. Wire and token versions remain unchanged because valid canonical payloads retain their meaning.

## Compatibility and failure behavior

Callers that depended on automatic legacy detection, coercion, omitted fields, or ignored fields must migrate. Malformed input raises `ValidationError` before policy evaluation. A final approval that would change an action or use an incompatible scope becomes an audited denial with no token. A divergent decision passed directly to the signer raises `ValueError` before token creation.

Only the currently supported action/scope pairs are eligible for approval. Wider ceilings can constrain requests but cannot grant a wider scope. Known destructive proposals remain parseable for explicit policy denial.

The runtime loads the checked-in ActionEnvelope schema; deployments must include that file alongside the Python packages. Missing schema or validation dependencies prevent processing. There is no fallback to permissive parsing.

## Validation

The regression suite covers both single- and dual-approval transitions, incompatible resource scopes, exact scope retention under a broader ceiling, divergent signing inputs with otherwise correct digests, strict canonical types and fields, explicit legacy migration, and valid round trips. Existing baseline, replay, evidence-conflict, and adversarial-corpus tests remain required.

All enforcement tests use simulated receipts and have no operational side effects. Passing these tests demonstrates the exercised authorization behavior; it does not demonstrate that an actual attack was stopped.

## Recovery and remaining work

No deployed state or token format is migrated. If an integration sends rejected input, repair its producer or use the explicit offline migration adapter. Keep operational writes disabled while diagnosing compatibility failures.

Evidence-age enforcement, durable shared replay/idempotency state, authenticated evidence sources and approvers, asymmetric signing, and live connectors remain separate work. Target strings are still opaque. The existing policy-bundle validation work is complementary and must preserve these final approval and signing checks when integrated.
