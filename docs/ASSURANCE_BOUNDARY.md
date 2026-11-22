# Assurance boundary: authenticated inputs and durable claims

## Assessment

This change hardens the authorization boundary, not the underlying detection system.
Guardian requires authenticated evidence and approvals before issuing authority.
Enforcement remains side-effect-free. Successful tests do not demonstrate that an
actual attack was detected or stopped.

## Trust and authority

Operators construct `AssuranceVerifier` with `EvidenceAuthority` and
`ApprovalAuthority` records. Public keys are Ed25519 raw 32-byte values. Evidence
authorities have exact source-ID, signal and target allowlists, plus a configured
independence domain. Approval authorities have an authenticated principal identity
and exact approval-label, action and target allowlists. No wildcard is implied.

Configuration is a trusted input: never construct these records from an incoming
proposal. Two credentials for one principal do not constitute two approvals; two
sources in one independence domain do not satisfy a two-source requirement.
Unknown, revoked or wrong-purpose keys are rejected. Revocation is a configuration
snapshot, not an online service.

Pass `assurance_verifier=verifier` to `Guardian`, then call
`guardian.evaluate(envelope, assurance=bundle, now=clock)`. Missing verifier or
proofs cannot approve a request. Earlier policy gates may deny or escalate first.
The `AssuranceBundle` sidecar contains `evidence` and `approvals` arrays, aligned
positionally with the canonical envelope's evidence and approval labels. Evidence
proofs contain `key_id` and lowercase hex `signature`; approval proofs additionally
contain `expires_at`. `AssuranceBundle.from_dict` rejects malformed structures.

Evidence signatures bind the domain `cerberus.evidence.v2`, key ID, full canonical envelope digest, target and
complete evidence record, including observation time and digest. Approval signatures
bind `cerberus.approval.v1`, key ID, approval label, complete canonical envelope
digest and approval expiry. Use `evidence_message` and `approval_message` from
`cerberus.assurance` for exact bytes; this is a Python canonicalization profile,
not a cross-language RFC 8785 claim. Private signing keys belong upstream, not in
the verifier. The decision token remains prototype HMAC, not hardware-backed signing.

## Time boundary

Every observation must have age **less than 60 seconds**; exactly 60 is expired.
Future clock skew of at most 5 seconds is accepted. Renewing the outer envelope
does not renew its evidence. Approval deadlines must be live and no later than the
envelope expiry. Token expiry is the earliest of evidence, envelope, approval and
configured token-lifetime deadlines. Execution at or beyond expiry is refused.
Operators must supply a trustworthy clock; time rollback is not independently detected.

## State setup and recovery

Provision `SQLiteStateStore("/explicit/trusted/path/authority.db", create=True)`
once. On ordinary startup reopen with `SQLiteStateStore(path)` (default
`create=False`). Pass the same database and namespace to Guardian via
`idempotency_registry=store` and EnforcementGateway via `replay_cache=store`.
All participating instances must share that trusted file. Missing, corrupt or
locked state fails closed; no in-memory fallback is used by the store.

Execution atomically claims both token ID and execution idempotency key before a
simulated receipt is produced. Claims survive process restart. An audit failure or
crash after consumption leaves the claim consumed: do not erase state to retry.
Recover through operator review and reconciliation. This is at-most-once attempted
simulation, not exactly-once real-world execution. Guardian's default registry and
an explicitly selected `ReplayCache` are still process-local simulation options.
The gateway requires an explicit store choice.

## Strict gateway execution context and live token status

The current gateway additionally requires the **actual complete request being
enforced**, via `expected_envelope=envelope`. It recomputes the canonical
ActionEnvelope digest and compares it with the signed token. Incident, impact,
reversibility, actor, nonce, policy version and all other envelope fields are
bound by that digest. The separately supplied action/target/scope must agree.
Missing or malformed context refuses execution; there is no unbound fallback.
Do not substitute the old approved envelope when a caller is asking to execute
a different request.

Token 1.3.0 already contains that full-envelope digest; its issuance/wire contract
and Guardian policy reasoning are unchanged. The new checks are at execution.

A trusted issuer/controller provisions `TokenAuthorityRegistry` after receiving
a genuine approved token. It registers the token fingerprint, intended purpose
and upstream authority-key dependencies. The gateway never self-registers a
requester's token. Operators must deliver revocation events to the registry
shared by every participating gateway:

```python
registry = TokenAuthorityRegistry()
registry.register(
    decision.decision_token, signer, now=clock,
    authority_key_ids=frozenset(p.key_id for p in proofs.evidence + proofs.approvals),
)
gateway = EnforcementGateway(signer, replay_cache=store, authority_registry=registry)
receipt = gateway.authorize_and_simulate(
    decision.decision_token, expected_envelope=envelope,
    action=envelope.action, target=envelope.target, scope=envelope.scope, now=clock,
)
registry.revoke_token(token_id)       # trusted controller event
registry.revoke_authority(key_id)     # issuer/evidence/approver dependency event
```

Unknown, revoked, wrongly purposed or mismatched registrations fail closed,
including signature-valid and unexpired tokens. Missing or unavailable registry
status also refuses. Registration cannot repurpose a token or undo revocation.
The registry lock covers the live check through replay consumption and receipt
commit. Revocation is ordered before or after that operation; it does not undo
an already completed action. Expiry is rechecked at the enforcement commit point.

This registry is **trusted and process-local**. It is not durable or distributed,
does not deliver upstream revocation events, and does not protect against a
compromised issuer/controller. Losing it makes prior tokens unknown; trusted
reprovisioning is needed before further enforcement. The existing SQLite replay
claims remain separate and must not be erased when reprovisioning. Controller
dependency records and revocation delivery must be correct; signatures alone do
not establish the truth of observations or organizational independence.

## Migration and test fixtures

Evidence v2 supersedes the observation-only v1 proof profile; obtain new evidence
attestations for each complete request. There is no legacy-signature fallback.
Issuers must verify observations and request context before signing; they must not
blindly sign requester-supplied data. These are request attestations, distinct from
reusable raw sensor reports. The combined release contract is Token **1.3.0**:
it signs both the evaluated policy digest and verified assurance digest. Both
earlier 1.2.0 branch profiles and old 1.1.0 tokens are rejected. Deploy compatible
signer/verifier together and obtain fresh authority. The integration preserves
PR #8's exact action/scope constraints and PR #7's strict PolicyBundle validation.
See [release contract and migration](RELEASE_CANDIDATE.md).

`simulator/assurance_fixtures.py` deliberately signs fabricated test claims with
public deterministic test keys. It is **not an authentication service** and must
never be exposed to requesters or used with operational signing credentials.
Simulator opt-in is `--assume-trusted-fixture`; historical telemetry also needs an
explicit simulation clock. Existing policy tests use `tests.assurance_support`
under this stated trusted-upstream assumption. New authenticity tests freeze trust
and proofs before adversarial mutation rather than re-signing altered claims.

## Residual risks and evidence limits

- Signatures authenticate configured producers, not the truth of their observations.
- Request attestations bind a policy version, not exact policy bytes. Trusted
  administrators must change that version when rules change; the decision token
  and receipt then record the exact evaluated policy digest.
- Principal identity and organizational independence depend on correct provisioning.
- Already-issued tokens now receive a live shared-process registry check. Cross-
  process/distributed status, durable registry recovery and reliable upstream
  revocation delivery remain unestablished; there is no remote revocation service.
- SQLite is single-host trusted storage, not distributed consensus or protection
  against malicious rollback, replacement, namespace changes or administrator deletion.
- Claims are retained indefinitely; quotas, storage exhaustion and production recovery
  remain unevaluated. New request IDs can express repeated intent; semantic deduplication
  and rate limiting are not supplied.
- No real connector, continuous/adaptive campaign, independent red team, field
  false-positive estimate, availability guarantee or production readiness is claimed.

The frozen v2/v3 benchmarks and the separate combined-contract runner record both
forbidden requests and legitimate controls, plus restart/replay episodes.
Their raw requests, fixtures, hashes and measured outcomes
are the evidence; percentages alone are not a defensive posture assessment.
