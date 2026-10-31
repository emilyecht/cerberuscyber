# CERBERUS Cyber — Documented Threat Model

**TRL 2–3 research prototype; not a formal model or operational protection claim.**
The project investigates whether separating interpretation from authorization
limits authority gained through compromised analysis.

## Assets and adversary-controlled inputs

Identities, endpoints, workloads, credentials, sensitive data, backups, telemetry
and AI tools are intended future protection targets, not systems currently
defended by this code. Evaluations use synthetic proposals/receipts; the opt-in
lab uses fresh temporary canary and marker files.

An adversary may manipulate confidence, evidence, labels, approvals, timestamps,
action/target/scope and tokens, or attempt direct/alternate execution paths.
Stolen credentials, telemetry poisoning, prompt injection, malicious insiders and
compromised agents motivate the research. Real detection, prevention, attribution
and nation-state effectiveness are not demonstrated.

## Current boundaries and residual assumptions

| Boundary | Implemented control | Residual assumption/gap |
|---|---|---|
| Input → proposal | Strict ActionEnvelope 1.0.0; canonical validation | Python serialization, not cross-language canonicalization |
| Sentinel → Guardian | Explicit approve/escalate/deny policy | Current Sentinel correlates fabricated telemetry; not a live model |
| Evidence/approvals → authority | Request-bound Ed25519 signatures and configured domains/principals | Trusted provisioning; signed observations can be false; real independence unproven |
| Policy → evaluation | PolicyBundle 1.0.0/rules 0.5.0 and exact digest | Digest is not publisher authentication; signed distribution and OPA/Rego proposed |
| Guardian → gateway | HMAC DecisionToken 1.3.0; exact action/target/scope, expiry/replay | Trusted signer; no hardware custody/rotation or operational connector |
| Replay state | Optional shared single-host SQLite claims | Trusted database/filesystem; no rollback resistance, distributed consensus or exactly-once real effects |
| Audit | In-memory hash chain, snapshot-at-append | No durable independent anchoring or operational immutability |
| Worker → lab files | Landlock-restricted worker, fixed broker, before/after hashes | Only documented Linux file/subprocess cases; OS/interpreter/controller/broker trusted |

Layer separation and configured domains do not establish failure-cause
independence. Guardian, policy, verifier, key and state remain trusted parts;
their compromise is a residual risk, not prevented by determinism.

## Required failure behavior

- Deny globally forbidden actions regardless of confidence or approval labels.
- Refuse excessive scope; a narrower proposal is a new authorization request.
- Invalid assurance, expiry, changed action/target/scope and consumed authority
  fail closed. State unavailability cannot create permission.
- Missing required evidence prevents approval; configured conflict escalates.
  A signature does not establish sensor truth.
- The gateway remains side-effect-free. The separate marker broker accepts no
  arbitrary path, program or credential. Without supported confinement its lab
  cannot pass or execute an unrestricted fallback.

## Proposed deployment requirements

Real connectors need separate least-privilege credentials, complete mediation,
authenticated identity, tested revocation/rollback, publisher-signed policy,
update governance, external audit and crash reconciliation. Human evidence-review
interfaces and emergency workflows are not a complete implemented service.
No generic override may bypass the forbidden list.

## Non-claims and exclusions

No production readiness, operational superiority, formal verification, independent
assessment, complete Zero Trust, classified accreditation, real containment or
tested recovery. Root/kernel and trusted-broker compromise are outside the lab
claim. Read/network/IPC isolation, resource-exhaustion protection, arbitrary-code
sandboxing and exhaustive bypass resistance are not demonstrated.

Offensive exploitation, retaliation, harvesting credentials, destructive
remediation and unauthorized third-party scanning remain excluded.

[Safety evidence](SAFETY_INVARIANTS.md) · [Lab assumptions](LOCAL_ENFORCEMENT_DEMO.md) ·
[Capability inventory](CAPABILITY_INVENTORY.md)
