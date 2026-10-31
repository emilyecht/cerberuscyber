# CERBERUS Cyber — Canonical Capability Inventory

**Updated 2026-10-31. TRL 2–3 defensive research prototype.** This reconciles
canonical grant brief §5 with executable artifacts. It is not certification,
formal verification, independent validation, operational superiority or
real containment/recovery. Protocol is separate aerospace work, not Cyber evidence.

## Implemented, with boundaries

| Capability | Evidence | Boundary |
|---|---|---|
| Advisory Sentinel | `cerberus/hunt.py`, synthetic scenarios | Fabricated-event correlator, not live-model or operational telemetry |
| Deterministic Guardian | `cerberus/guardian.py`, tests | Same inputs/policy/trust/time/state; not a safety guarantee |
| JSON policy | PolicyBundle 1.0.0; rules 0.5.0; `cerberus/policy.py` | Digest identifies content, not publisher; no OPA/Rego |
| Typed proposal | ActionEnvelope 1.0.0; schema/canonical-input checks; SHA-256 | Python serialization, not cross-language RFC 8785 conformance |
| Authenticity | Request-bound Ed25519 evidence/approval verifier | Configured keys/domains/principals; truth and real independence remain assumptions |
| Freshness | Observation, approval, request and token deadlines | No operational telemetry/issuer service |
| DecisionToken 1.3.0 | `cerberus/token.py`; policy and assurance digests | Prototype HMAC; exact envelope/identity/action/target/scope/expiry/idempotency, not hardware signing/rotation |
| Replay/idempotency | `cerberus/state.py`; optional shared SQLite | One trusted host/database/namespace; not distributed, rollback-resistant or exactly-once real effects |
| Default gateway | `cerberus/enforcement.py` | Exact validation and simulated receipts only; no operational containment/recovery |
| Opt-in local lab | [Lab specification](LOCAL_ENFORCEMENT_DEMO.md), PR #14 | Same-UID scripted worker, Landlock ABI 3+, five required syscall refusals, one temporary marker, replay; not general sandboxing |
| Audit | `cerberus/audit.py` | Snapshot-at-append in-memory hash chain, not external durable/immutable infrastructure |
| Distribution | 0.1.0rc1 source/wheel and fresh-install CI | Evaluation kit, not production or registry release |

Current verdicts are **approve, escalate, deny**. Over-scoped requests are refused;
narrower proposals require fresh authorization. Approvals do not override the
globally forbidden actions.

## Evidence chronology

- [Historical combined record](../results/release_candidate/main-after-pr11.md):
  code `59c6a29`, 0/11 unsafe authorizations, 8/8 eligible simulated responses,
  three lifecycle episodes and 222 recorded tests. Not a new run or operational
  attack-rate estimate.
- [PR #14](https://github.com/emilyecht/cerberuscyber/pull/14),
  [reviewed-head CI](https://github.com/emilyecht/cerberuscyber/actions/runs/41208794085):
  249 tests on each Python matrix entry; 14 native lab cases, zero observed
  unauthorized resource changes, one authorized marker write, five kernel
  refusals and clean installed-wheel verification. Project/agent self-review is
  **not independent human security validation**.

Do not combine different instruments into one security-improvement score.
Preserve each result's source, oracle, trust, clock and state assumptions.

## Proposed or not established

Operational read/write connectors; live-model efficacy; real containment,
rollback or recovery; hardware-backed decision signing/rotation; publisher-signed
policy; OPA/Rego; cross-language canonicalization; distributed/rollback-resistant
state; crash reconciliation; durable independent audit; formal verification;
independent review; field scale/latency/false-positive evidence; mission/classified
accreditation.

Program eligibility, budgets, range size, timeline, model access, application
fields and ownership terms must follow the active official solicitation,
verified immediately before filing; repository plans do not establish them.
