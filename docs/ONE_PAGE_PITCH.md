# CERBERUS Cyber — One-Page Research Pitch

**Emily Echterhoff — independent researcher. TRL 2–3 defensive research prototype.**

## Research question

Can a separate deterministic authorization boundary limit the authority gained
through compromised or manipulated security analysis?

**Intelligence is not authority.** “Assume compromise. Constrain authority.
Contain damage. Recover safely” is design doctrine, not measured containment or
recovery.

## Architecture and current implementation

1. **Sentinel:** currently correlates fabricated telemetry into advisory
   proposals. Live telemetry and model-backed reasoning remain proposed.
2. **Guardian:** validates ActionEnvelope 1.0.0 against JSON PolicyBundle 1.0.0
   (rules 0.5.0), configured request-bound evidence/approval authorities,
   freshness, scope and replay state. Outcomes are **approve, escalate, deny**;
   it never silently widens or rewrites requested scope.
3. **Enforcement:** validates DecisionToken 1.3.0 and emits simulated receipts.
   A separate opt-in Linux lab adds kernel confinement and one actual
   temporary-file marker effect. It is not a production connector, host
   isolation, network hold or recovery mechanism.

Repeatable authorization requires identical validated inputs, policy, trust
configuration, time and replay/idempotency state. Determinism is not a safety
guarantee; signatures do not prove observation truth or organizational independence.

## Evidence and limits

- Installable 0.1.0rc1 evaluation kit, documented threat model, typed contracts,
  project-authored adversarial tests and CI.
- Historical combined-contract measurement at `59c6a29`: **0/11 unsafe
  authorizations**, **8/8 eligible simulated responses**, no duplicate receipts
  in three lifecycle episodes. Selected synthetic observations are not independent
  attacks, operational rates or an overall security score.
- The [local enforcement lab](LOCAL_ENFORCEMENT_DEMO.md) checks absent/forged
  authority, scope widening, kernel-refused bypasses, one authorized marker write
  and replay. The agent and trust evidence are fabricated; Linux supplies confinement.

## Distinction and next study

CERBERUS makes proposal, policy decision, authorization binding and observed
effect separately inspectable. This is a testable research approach, not proof
of novelty, superiority to Microsoft, or replacement of SIEM/SOAR/XDR/EDR/IAM.
It applies explicit-verification and least-privilege principles at one boundary,
not a complete enterprise Zero Trust implementation.

A proposed matched synthetic study would compare harmful authorization, benign
disruption, latency, scope and audit reconstruction with and without that
boundary. Thresholds must be fixed before testing. Budget, schedule, model access,
sponsor eligibility and submission terms remain provisional until the active
official solicitation is verified.

**Not claimed:** production readiness; formal verification; independent
validation; real-world detection, prevention, attribution or containment; tested
rollback/recovery; operational superiority; classified accreditation. CERBERUS
Protocol is separate aerospace research and supplies no Cyber performance evidence.

[Current inventory](CAPABILITY_INVENTORY.md) · [Evaluation](EVALUATION_FRAMEWORK.md) ·
[Repository](https://github.com/emilyecht/cerberuscyber)
