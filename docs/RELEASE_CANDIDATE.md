# Evaluation release candidate: combined authority contract

## Release decision

**0.1.0rc1 is for local, simulation-only evaluation.** It is not a production
deployment, public package-registry release, accreditation, or independent security
assessment. Merge, tagging, distribution, and any operational pilot remain separate
review decisions. The installable entry point cannot select an external target.

This candidate integrates the policy work from PR #7 (`16164b3e541e`) and the
request-bound assurance work from PR #10 (`f08129726812`) on top of the already
merged evidence/contract repairs. Their two incompatible Token 1.2.0 profiles are
replaced by one explicit 1.3.0 contract; do not deploy them as interchangeable.

## What is combined

| Boundary | Candidate behavior | Limit |
|---|---|---|
| Policy | Validate the complete PolicyBundle, hold canonical rules, bind their SHA-256 digest to decisions/tokens/receipts | Trusted provisioning; no remote policy signing/distribution |
| Evidence | Verify Ed25519 issuer authority, full-request binding, observed age, future skew, independent domains | Configured origin is not proof of observation truth |
| Approval | Verify request-bound signatures, expiry, allowlists, independent principals | No live identity service or online revocation |
| Decision | Token 1.3.0 carries both policy and assurance digests plus exact request bindings | Prototype HMAC signer and trusted clock |
| Replay | Shared SQLite atomically claims authorization/execution identities across process restart | One trusted host; not rollback-resistant or distributed |
| Enforcement | Exact requested action/target/scope only; simulated receipt with no side effects | No production connector or real-world recovery |

Integration safeguards retain the final action check after an approval gate and
never widen requested scope to the policy ceiling. Invalid assurance cannot consume
the authorization idempotency claim before a legitimate request reaches that gate.
Policy copies exposed to callers cannot mutate the rules while retaining an old
digest; direct bundle construction cannot bypass validation or claim a false digest.

## Migration

1. Review the combined source and provision trusted policy and issuer configuration.
2. Change signer and verifier together to Token 1.3.0. Reject all older versions;
   do not relabel, infer, or upgrade an existing token.
3. Obtain fresh request-bound evidence and approval proofs, then fresh authorization.
   Evidence v2 and approval v1 proof profiles remain unchanged.
4. Keep durable state and namespace stable. Never delete or replace an authority
   database to make a refused request succeed. Reconcile consumed work manually.

ActionEnvelope v1.0.0 carries the **policy version**, not the policy digest.
Upstream attestations consequently bind a version; tokens bind the exact evaluated
policy bytes. An operator must bump the policy version when changing rules. This
candidate does not claim approval of an exact policy hash by upstream issuers.

## Verification and evidence preservation

The unit/regression suite covers partial tokens, legacy versions, authentic but
malformed token payloads, forged policy digests, policy mutation, and packaged
resource parity in addition to the existing assurance and authority tests.
CI exercises Python 3.10 and 3.12, builds an sdist and a wheel from it, then checks
the installed console command in a fresh environment outside the checkout.
Checksums identify generated artifacts but are not publisher signatures.

All v1/v2/v3 benchmark definitions and checked-in raw results remain historical
evidence. The original reviewer packet and explicit non-claims are retained, as is
the grant proposal. [The new runner](../benchmarks/release_candidate/README.md)
measures the combined interface against v3's exact prepared corpus. Adding
`schema_version: 1.0.0` to the policy file changes its hash; the behavioral rules
remain unchanged. This is disclosed rather than treated as the identical earlier
instrument. Run counts describe selected fixtures, not an attack probability.

## Deferred before operational use

Independent, held-out and adaptive testing; authentic issuer onboarding and key
management; clock/storage trust; revocation; quotas and rate limits; dependency and
artifact provenance; telemetry privacy; and real-connector crash reconciliation
are not supplied by this evaluation release. No endpoint protection, detected or
stopped real attack, broad adversarial resistance, or production readiness is claimed.

See the [quick start](EVALUATION_KIT.md) and [assurance boundary](ASSURANCE_BOUNDARY.md).
