# CERBERUS Cyber Gap-Closure Plan

**TRL 2–3 research prototype.** This refreshes the obsolete inventory claiming
packaging and measured benchmarks did not exist; it does not rewrite old evidence
or promote operational maturity.

## Current artifacts and genuine gaps

| Area | Implemented | Remaining gap |
|---|---|---|
| Evaluation kit | Installable 0.1.0rc1 source/wheel, portable demo, fresh-install CI | Signed distributions, wider platforms, production release; no PyPI claim |
| Benchmarks | Frozen corpora, pinned project-authored measurements/reviewer packet | Representative live-model/benign data and independent matched evaluation |
| Policy | JSON PolicyBundle 1.0.0/rules 0.5.0, validation/digest, deterministic evaluator | OPA/Rego, publisher signatures, update governance, policy-effort study |
| Assurance | Request-bound Ed25519 evidence/approvals, freshness, HMAC tokens 1.3.0 | Operational issuers, evidence truth, production identities/hardware keys/rotation |
| State/audit | Optional single-host SQLite; in-memory chain with snapshots | Distributed/rollback-resistant state, crash reconciliation, independent durable audit |
| Execution | Simulated gateway and Linux temporary-file lab with kernel refusals | Real host/session/network connectors, rollback or field containment |
| Intelligence/telemetry | Synthetic scenarios and fabricated-event correlation | Normalized replay adapters, real read-only feeds and live-model comparison |

See [canonical inventory](CAPABILITY_INVENTORY.md). Each historical measurement
retains its own source, oracle, denominators and non-claims.

## Prioritized work

1. Maintain the local lab's no-fallback isolation checks, permission-denial plus
   unchanged-resource evidence, and real positive control. Add paths only with a
   documented threat-model change; no production targets or credentials.
2. Strengthen policy/trust lifecycle. JSON validation/digest binding already
   exists; OPA/Rego and publisher authentication are separate future milestones.
   Evaluate conflicts, exceptions, expiry and revocation rather than inferring
   truth from signatures.
3. Build representative read-only studies: a normalized contract and synthetic
   replay before operational connectors. Entra, cloud and endpoint/SIEM exports
   are integration candidates, not existing capabilities.
4. Develop one reversible real lab connector only after separate review:
   exact capabilities, authenticated identity, outcome verification, rollback,
   revocation, external audit and crash reconciliation. The marker experiment
   is not that connector.
5. Run matched comparisons and independent assessment with thresholds fixed
   before testing and publication of negative results, benign disruption,
   latency and policy effort. Budgets, schedules, range size, model access and
   sponsor eligibility are provisional until the active solicitation is verified.

## Workstream and readiness reconciliation

The older A–F labels were planning categories, not evidence that README
workstreams completed. Current README foundation/A/B artifacts and JSON policy
binding exist. OPA/Rego, operational connectors, independent review and sponsor
transition remain proposed. Dashboards do not replace boundary validation.

No offensive exploitation, retaliation, credential theft, destructive payloads
or autonomous irreversible remediation. No production readiness, formal
verification, independent validation, operational superiority, field
containment/recovery or classified accreditation is claimed.
