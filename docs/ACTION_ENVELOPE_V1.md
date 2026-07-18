# ActionEnvelope v1.0.0

## Purpose

`ActionEnvelope` is the explicit membrane between untrusted Sentinel inference and trusted Guardian authorization. It carries a proposal, not permission. Nothing in an envelope is executable until Guardian validates the contract, evaluates the exact policy version, and issues a signed decision token.

The canonical implementation is:

- `sdk/shared_types/action_envelope.py` — typed Python contract, validation, canonical JSON, digest computation, and legacy adapter;
- `schemas/action-envelope.schema.json` — JSON Schema Draft 2020-12 wire contract;
- `cerberus/hunt.py` — Sentinel `HuntFinding` to `ActionEnvelope` adapter;
- `cerberus/guardian.py` — policy-version, freshness, scope, and idempotency validation;
- `cerberus/token.py` — decision-token binding to the canonical envelope digest;
- `tests/test_action_envelope_v1.py` — schema, digest, migration, replay, and policy-version tests.

## Canonical fields

| Field | Meaning | Authority treatment |
|---|---|---|
| `schema_version` | Exact contract version (`1.0.0`) | Unsupported versions fail closed |
| `actor` | Sentinel instance proposing the action | Audited and bound into the token |
| `target` | Exact scoped resource identifier | Must match the decision token and Enforcement request |
| `action` | Recognized proposed mutation | Must be policy-allowed; known destructive actions are deterministically denied |
| `scope` | Requested blast-radius ceiling | Must not exceed policy maximum |
| `evidence_refs` | Source IDs, digests, signals, and timestamps | Provenance and independent-source requirements remain policy inputs |
| `confidence` | Sentinel-reported score | Informational; never sufficient to authorize by itself |
| `freshness` | Timestamp, expiry, and nonce | Stale envelopes are denied |
| `idempotency_key` | UUID for exact-once evaluation | Reuse is denied by Guardian |
| `reversibility_flag` | Whether rollback is available | Policies may require it |
| `required_approval_mode` | `none`, `single`, `dual`, or `emergency_breakglass` | Cannot weaken the policy-required approval mode |
| `policy_version` | Exact policy bundle expected by Sentinel | Mismatch is denied before policy evaluation |

The envelope also retains `envelope_id`, `incident_id`, `threat`, `mission_impact`, and `human_approvals` as explicit context used by the current prototype.

## Canonical serialization and signing

`ActionEnvelope.canonical_json()` uses UTF-8 JSON with sorted object keys and no insignificant whitespace. `ActionEnvelope.digest()` computes SHA-256 over those exact bytes.

Guardian records that digest in its audit entry. DecisionToken v1.1.0 binds:

- envelope ID and SHA-256 digest;
- idempotency key and proposing actor;
- exact action, target, and scope;
- policy ID and policy version;
- nonce, issue time, and expiry;
- reversibility status.

Enforcement can therefore verify the signed authorization without calling Guardian and cannot substitute a different target, scope, or action.

## Migration path

### Phase 1 — compatibility (current)

- Canonical producers emit v1.0.0.
- `ActionEnvelope.from_legacy_incident()` converts original simulator fixtures.
- The compatibility adapter synthesizes evidence digests only for legacy in-memory fixtures.
- Legacy callers must supply the exact policy bundle version. The default `0.0.0-legacy` value is intentionally rejected by a current Guardian.

### Phase 2 — warning period

- Add structured deprecation warnings whenever the legacy adapter is used outside tests or the simulator.
- Require integrations to negotiate `schema_version=1.0.0` and a supported policy version before submitting envelopes.
- Freeze additions to the pre-v1 representation.

### Phase 3 — removal target

- Remove direct support for pre-v1 envelope dictionaries after two minor releases or before any operational connector is enabled, whichever comes first.
- Preserve only offline fixture-conversion tooling.
- Any incompatible field change requires ActionEnvelope v2.0.0.

## Fail-closed behavior

Guardian denies or refuses processing when:

- the schema version is unsupported;
- an action or scope is unknown;
- required fields are empty or malformed;
- the freshness window is invalid or expired;
- the policy version does not exactly match;
- an idempotency key was already evaluated;
- the requested scope exceeds the policy ceiling;
- the action is globally forbidden;
- evidence, provenance, reversibility, or approval requirements are unsatisfied.

## Prototype limitations and recovery

The current idempotency registry is in memory. A restart or multiple Guardian replicas could lose or race exact-once state. Production work requires a durable atomic store keyed by `idempotency_key`, with the envelope digest recorded as immutable context.

The canonical serializer follows deterministic JSON conventions used by this repository, but it is not yet a formally adopted external canonicalization standard such as RFC 8785. Interoperability testing is required before cross-language signing.

The HMAC decision signer remains a prototype. Hardware-backed asymmetric keys, rotation, trust-root distribution, and revocation are still required.

Detection and recovery controls:

1. audit every policy-version mismatch and duplicate idempotency key;
2. alert on repeated malformed-envelope submissions from one actor;
3. preserve the rejected canonical payload and digest without executing it;
4. rotate compromised Sentinel identities without granting them enforcement credentials;
5. restore Guardian idempotency state from a durable ledger before re-enabling mutation connectors.
