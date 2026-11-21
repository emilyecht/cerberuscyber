# Component capability inventory

Source identities are in README.md. Evidence must be attributed to the specific
branch and commit, because default main does not contain the unmerged fixes.

| Component | Implementation and verification | Boundary |
| --- | --- | --- |
| Advisory proposal | `cerberus/hunt.py`, fabricated incident fixtures | Scripted correlator, no live-model efficacy or operational telemetry |
| Guardian policy | `cerberus/guardian.py`, policy bundle/rule tests | Deterministic under identical trust, time, policy and state; truth of evidence is assumed |
| Typed envelope | `cerberus/models.py`, schema, exact digest tests | Full Python canonical serialization; not cross-language canonicalization conformance |
| Evidence and approvals | `cerberus/assurance.py`, Ed25519 fixture proofs, substitution/scope/expiry regressions | Trusted configured producers, domains and principal mapping; public test keys are not deployment credentials |
| Token issuer | `cerberus/token.py`, HMAC and binding tests | Prototype symmetric key in trusted memory; no hardware custody or production rotation |
| Execution gateway | `cerberus/enforcement.py`, PR 17 context and registry tests | Simulated receipt; no operational read/write connector |
| Current authority | `cerberus/authority.py`, unknown/revoked/purpose/unavailable/order tests | Shared process-local registry, trusted registration and revocation delivery; not durable or distributed |
| Replay storage | `cerberus/state.py`, PR 19 canonical schema, full integrity and atomic two-key tests | Single trusted host/path/namespace, DELETE journal mode only after PR 20; no historical-completeness authentication |
| Elapsed-time check | PR 20 real-clock post-consumption check, fresh lock-wait probe | Trusted clock; caller-supplied `now` is simulation-only trusted input |
| Local marker broker | PR 22 expiry, revocation and unavailable-state tests | Holds registry lock through marker/audit, samples time immediately before syscall; no atomic wall-clock/effect completion guarantee |
| Worker confinement | `cerberus/_lab_worker.py`, supported-host 14-case Landlock lab | Linux ABI >=3, same-UID scripted worker, filesystem constraints only; trusted controller excluded |
| Audit | `cerberus/audit.py`, snapshot and chain tests | In-memory hash chain; no external durability, authenticated anchoring or crash reconciliation |
| Distribution | Built source/wheel from PR 22, clean installed demo | Local portable demo passes; local full installed verifier stops at unavailable Landlock |
| Protocol Boolean FCOI | Separate `src/cerberus_fcoi`, ten original hand fixtures, 60 seeded DAGs, PR 7 three-layer example | Static monotone Boolean DAG, explicit 128-node/32-cause schema bounds and enumeration budgets; no probability, causal discovery or runtime authority |
| Protocol larger architecture | Papers, casebook, Anchor specification, Vigil illustrative experiment | Research artifacts and synthetic illustration; not a complete implemented security system |

Current Guardian verdicts are approve, escalate and deny. Scope widening requires
a fresh authorization; approvals do not override globally forbidden actions.
Missing or unavailable trusted authority must withhold permission. Successful
fixture tests do not establish completeness of the policy or adversary model.

Proposed capabilities remain operational containment/recovery connectors,
authenticated rollback-resistant history, durable independent audit, distributed
authority, production key management, validated causal models, formal security
proofs and independent operational evaluation. Protocol analysis may guide future
test design through a separately reviewed model; no runtime dependency is added.
