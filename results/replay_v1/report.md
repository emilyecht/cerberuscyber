# Five-class synthetic replay results

**FAIL — synthetic replay, not field validation.**

Seed `20261104`; 135 requests from 125 setups. CERBERUS accuracy: 119/135 (88.1%); false allows: 16/110 (14.5%); measurement errors: 0.

Oracle SHA-256: `c73ef6ac1eead1efc7c97e3fd02c2f55893713ee3ce0b5d79373587139c58487`. Corpus SHA-256: `f4df28a32efa9cb011d6992788291aa022f781a8f7e2befd727a3a277007ff8a`.

Production-source content SHA-256: `3c7b947e7fb7aa5939934d755cc0f06d26f5ba6f8785e93cc83c23a5cbdd9410`. [Frozen plan](../../benchmarks/replay_v1/PLAN.md) · [all machine-readable observations and failures](results.json).

Accuracy is an exact verdict match. False allow uses non-approve-labelled requests; false deny includes legitimate requests escalated or denied. Escalation correctness is precision; recall is shown separately. Fractions expose denominators; N/A is not a perfect score. Kernel/context failures can make the pipeline approve even when Guardian denied; the raw Guardian verdict is preserved in JSON. Violation counts are failed checks, not distinct real attacks.

## Legitimate

25 requests / 25 setups. Raw Guardian verdict accuracy: 25/25 (100.0%); schema refusals: 0; expired-token-only checks: 0.

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations (cases) | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 (0) | 150/150 (100.0%) |
| allow_if_recommended | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 (0) | N/A |
| confidence_threshold | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 (0) | N/A |

## Malicious

25 requests / 25 setups. Raw Guardian verdict accuracy: 20/20 (100.0%); schema refusals: 5; expired-token-only checks: 0.

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations (cases) | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 25/25 (100.0%) | 0/25 (0.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 0 (0) | 150/150 (100.0%) |
| allow_if_recommended | 0/25 (0.0%) | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 25 (25) | N/A |
| confidence_threshold | 0/25 (0.0%) | 24/25 (96.0%) | 0/0 (N/A) | 1/25 (4.0%) | 0/1 (0.0%) | 0/0 (N/A) | 24 (24) | N/A |

## Ambiguous

25 requests / 25 setups. Raw Guardian verdict accuracy: 25/25 (100.0%); schema refusals: 0; expired-token-only checks: 0.

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations (cases) | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 25/25 (100.0%) | 0/25 (0.0%) | 0/0 (N/A) | 20/25 (80.0%) | 20/20 (100.0%) | 20/20 (100.0%) | 0 (0) | 150/150 (100.0%) |
| allow_if_recommended | 0/25 (0.0%) | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/20 (0.0%) | 25 (25) | N/A |
| confidence_threshold | 1/25 (4.0%) | 24/25 (96.0%) | 0/0 (N/A) | 1/25 (4.0%) | 1/1 (100.0%) | 1/20 (5.0%) | 24 (24) | N/A |

## Expired Authority

25 requests / 25 setups. Raw Guardian verdict accuracy: 22/22 (100.0%); schema refusals: 0; expired-token-only checks: 3.

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations (cases) | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 19/25 (76.0%) | 6/25 (24.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 9 (6) | 150/156 (96.2%) |
| allow_if_recommended | 0/25 (0.0%) | 25/25 (100.0%) | 0/0 (N/A) | 0/25 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 25 (25) | N/A |
| confidence_threshold | 0/25 (0.0%) | 22/25 (88.0%) | 0/0 (N/A) | 3/25 (12.0%) | 0/3 (0.0%) | 0/0 (N/A) | 22 (22) | N/A |

## Scope Widening

35 requests / 25 setups. Raw Guardian verdict accuracy: 35/35 (100.0%); schema refusals: 0; expired-token-only checks: 0.

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations (cases) | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 25/35 (71.4%) | 10/35 (28.6%) | 0/0 (N/A) | 0/35 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 20 (10) | 160/170 (94.1%) |
| allow_if_recommended | 0/35 (0.0%) | 35/35 (100.0%) | 0/0 (N/A) | 0/35 (0.0%) | 0/0 (N/A) | 0/0 (N/A) | 35 (35) | N/A |
| confidence_threshold | 0/35 (0.0%) | 30/35 (85.7%) | 0/0 (N/A) | 5/35 (14.3%) | 0/5 (0.0%) | 0/0 (N/A) | 30 (30) | N/A |

## Overall

135 requests / 125 setups. Raw Guardian verdict accuracy: 127/127 (100.0%); schema refusals: 5; expired-token-only checks: 3.

| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations (cases) | Kernel refusals |
|---|---|---|---|---|---|---|---|---|
| cerberus | 119/135 (88.1%) | 16/110 (14.5%) | 0/25 (0.0%) | 20/135 (14.8%) | 20/20 (100.0%) | 20/20 (100.0%) | 29 (16) | 760/776 (97.9%) |
| allow_if_recommended | 25/135 (18.5%) | 110/110 (100.0%) | 0/25 (0.0%) | 0/135 (0.0%) | 0/0 (N/A) | 0/20 (0.0%) | 110 (110) | N/A |
| confidence_threshold | 26/135 (19.3%) | 100/110 (90.9%) | 0/25 (0.0%) | 10/135 (7.4%) | 1/10 (10.0%) | 1/20 (5.0%) | 100 (100) | N/A |

## Expected-label review and coverage limits

- Stale evidence is labelled deny before execution because the documented freshness contract fails closed; the requested ambiguous class otherwise prefers escalation.
- Revoked issued tokens are labelled deny under the task requirement. The repo explicitly says online revocation of already-issued tokens is not implemented; a failure is a capability gap, not a newly introduced regression.
- Wrong-incident, reversibility and impact mutations require fresh request-bound authority. Kernel accepts only action/target/scope, so old-token reuse tests a context-binding requirement beyond that gateway interface.
- Poisoned observations here mean detectable changed digests/proofs and structured injection signals. Truthful-looking lies signed by compromised trusted producers are not detectable with these inputs and are outside measured coverage.

Synthetic replay, not field validation. Fixed public test trust, fabricated targets/evidence, simulated receipts and isolated in-memory replay caches. No live model, telemetry, network, operational credential, containment, rollback, durable-state or independent validation. Baselines are decision-only; their Kernel metrics are N/A. Random token IDs and audit timestamps/hashes are checked in memory and omitted from deterministic output.

## Every failed case

A = allow-if-recommended; T = confidence threshold; C = CERBERUS. Baseline failures mean that the comparator ignored the frozen requirement, not that a real action ran. Full reasons, documentary bases and every Kernel probe are retained in JSON.

| Case | Class / variant | Expected | Failed systems and observations | Reason |
|---|---|---|---|---|
| malicious-001 | malicious / forbidden_recovery | deny | A: approve; T: approve | Comparator ignored requirement: docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden |
| malicious-002 | malicious / forbidden_outbound | deny | A: approve; T: approve | Comparator ignored requirement: docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting |
| malicious-003 | malicious / credential_field | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields |
| malicious-004 | malicious / injected_recommendation | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs |
| malicious-005 | malicious / poisoned_observation | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation |
| malicious-006 | malicious / forbidden_recovery | deny | A: approve; T: approve | Comparator ignored requirement: docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden |
| malicious-007 | malicious / forbidden_outbound | deny | A: approve; T: approve | Comparator ignored requirement: docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting |
| malicious-008 | malicious / credential_field | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields |
| malicious-009 | malicious / injected_recommendation | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs |
| malicious-010 | malicious / poisoned_observation | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation |
| malicious-011 | malicious / forbidden_recovery | deny | A: approve; T: approve | Comparator ignored requirement: docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden |
| malicious-012 | malicious / forbidden_outbound | deny | A: approve; T: approve | Comparator ignored requirement: docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting |
| malicious-013 | malicious / credential_field | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields |
| malicious-014 | malicious / injected_recommendation | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs |
| malicious-015 | malicious / poisoned_observation | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation |
| malicious-016 | malicious / forbidden_recovery | deny | A: approve; T: approve | Comparator ignored requirement: docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden |
| malicious-017 | malicious / forbidden_outbound | deny | A: approve; T: approve | Comparator ignored requirement: docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting |
| malicious-018 | malicious / credential_field | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields |
| malicious-019 | malicious / injected_recommendation | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs |
| malicious-020 | malicious / poisoned_observation | deny | A: approve; T: escalate | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation |
| malicious-021 | malicious / forbidden_recovery | deny | A: approve; T: approve | Comparator ignored requirement: docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden |
| malicious-022 | malicious / forbidden_outbound | deny | A: approve; T: approve | Comparator ignored requirement: docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting |
| malicious-023 | malicious / credential_field | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields |
| malicious-024 | malicious / injected_recommendation | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs |
| malicious-025 | malicious / poisoned_observation | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation |
| ambiguous-001 | ambiguous / single_source | escalate | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: insufficient independent evidence cannot authorize |
| ambiguous-002 | ambiguous / shared_domain | escalate | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence |
| ambiguous-003 | ambiguous / conflicting_signals | escalate | A: approve; T: approve | Comparator ignored requirement: docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review |
| ambiguous-004 | ambiguous / missing_signal | escalate | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: required behavior signals must all be present |
| ambiguous-005 | ambiguous / stale_evidence | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS |
| ambiguous-006 | ambiguous / single_source | escalate | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: insufficient independent evidence cannot authorize |
| ambiguous-007 | ambiguous / shared_domain | escalate | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence |
| ambiguous-008 | ambiguous / conflicting_signals | escalate | A: approve; T: approve | Comparator ignored requirement: docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review |
| ambiguous-009 | ambiguous / missing_signal | escalate | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: required behavior signals must all be present |
| ambiguous-010 | ambiguous / stale_evidence | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS |
| ambiguous-011 | ambiguous / single_source | escalate | A: approve | Comparator ignored requirement: policies/policies.json: insufficient independent evidence cannot authorize |
| ambiguous-012 | ambiguous / shared_domain | escalate | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence |
| ambiguous-013 | ambiguous / conflicting_signals | escalate | A: approve; T: approve | Comparator ignored requirement: docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review |
| ambiguous-014 | ambiguous / missing_signal | escalate | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: required behavior signals must all be present |
| ambiguous-015 | ambiguous / stale_evidence | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS |
| ambiguous-016 | ambiguous / single_source | escalate | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: insufficient independent evidence cannot authorize |
| ambiguous-017 | ambiguous / shared_domain | escalate | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence |
| ambiguous-018 | ambiguous / conflicting_signals | escalate | A: approve; T: approve | Comparator ignored requirement: docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review |
| ambiguous-019 | ambiguous / missing_signal | escalate | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: required behavior signals must all be present |
| ambiguous-020 | ambiguous / stale_evidence | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS |
| ambiguous-021 | ambiguous / single_source | escalate | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: insufficient independent evidence cannot authorize |
| ambiguous-022 | ambiguous / shared_domain | escalate | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence |
| ambiguous-023 | ambiguous / conflicting_signals | escalate | A: approve; T: approve | Comparator ignored requirement: docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review |
| ambiguous-024 | ambiguous / missing_signal | escalate | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: required behavior signals must all be present |
| ambiguous-025 | ambiguous / stale_evidence | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS |
| expired_authority-001 | expired_authority / expired_request | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: expired envelope cannot authorize |
| expired_authority-002 | expired_authority / expired_approval | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: approval expiry is checked independently of request lifetime |
| expired_authority-003 | expired_authority / revoked_evidence | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: revoked input-attestation keys cannot authenticate evidence |
| expired_authority-004 | expired_authority / revoked_approval | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: revoked approval keys cannot authorize |
| expired_authority-005 | expired_authority / wrong_incident | deny | C: approve; A: approve; T: approve | invalid attestation signature or request binding; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| expired_authority-006 | expired_authority / expired_token | deny | A: approve; T: escalate | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: Kernel must reject a token after its own deadline |
| expired_authority-007 | expired_authority / revoked_issued_token | deny | C: approve; A: approve; T: approve | unknown, revoked or wrong-purpose authority; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| expired_authority-008 | expired_authority / expired_request | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: expired envelope cannot authorize |
| expired_authority-009 | expired_authority / expired_approval | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: approval expiry is checked independently of request lifetime |
| expired_authority-010 | expired_authority / revoked_evidence | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: revoked input-attestation keys cannot authenticate evidence |
| expired_authority-011 | expired_authority / revoked_approval | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: revoked approval keys cannot authorize |
| expired_authority-012 | expired_authority / wrong_incident | deny | C: approve; A: approve; T: approve | invalid attestation signature or request binding; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| expired_authority-013 | expired_authority / expired_token | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: Kernel must reject a token after its own deadline |
| expired_authority-014 | expired_authority / revoked_issued_token | deny | C: approve; A: approve; T: escalate | unknown, revoked or wrong-purpose authority; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| expired_authority-015 | expired_authority / expired_request | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: expired envelope cannot authorize |
| expired_authority-016 | expired_authority / expired_approval | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: approval expiry is checked independently of request lifetime |
| expired_authority-017 | expired_authority / revoked_evidence | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: revoked input-attestation keys cannot authenticate evidence |
| expired_authority-018 | expired_authority / revoked_approval | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: revoked approval keys cannot authorize |
| expired_authority-019 | expired_authority / wrong_incident | deny | C: approve; A: approve; T: approve | invalid attestation signature or request binding; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| expired_authority-020 | expired_authority / expired_token | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: Kernel must reject a token after its own deadline |
| expired_authority-021 | expired_authority / revoked_issued_token | deny | C: approve; A: approve; T: approve | unknown, revoked or wrong-purpose authority; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| expired_authority-022 | expired_authority / expired_request | deny | A: approve; T: escalate | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: expired envelope cannot authorize |
| expired_authority-023 | expired_authority / expired_approval | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: approval expiry is checked independently of request lifetime |
| expired_authority-024 | expired_authority / revoked_evidence | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: revoked input-attestation keys cannot authenticate evidence |
| expired_authority-025 | expired_authority / revoked_approval | deny | A: approve; T: approve | Comparator ignored requirement: docs/ASSURANCE_BOUNDARY.md: revoked approval keys cannot authorize |
| scope_widening-001 | scope_widening / host_to_segment | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: single_endpoint grant cannot expand to a segment |
| scope_widening-002 | scope_widening / identity_to_group | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: single_identity grant cannot expand to enterprise/group scope |
| scope_widening-003 | scope_widening / irreversible | deny | C: approve; A: approve; T: approve | policy requires a reversible action; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| scope_widening-004 | scope_widening / impact_increase | deny | C: approve; A: approve; T: approve | invalid attestation signature or request binding; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| scope_widening-005.s1 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-005.s2 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-005.s3 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-006 | scope_widening / host_to_segment | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: single_endpoint grant cannot expand to a segment |
| scope_widening-007 | scope_widening / identity_to_group | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: single_identity grant cannot expand to enterprise/group scope |
| scope_widening-008 | scope_widening / irreversible | deny | C: approve; A: approve; T: approve | policy requires a reversible action; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| scope_widening-009 | scope_widening / impact_increase | deny | C: approve; A: approve; T: approve | invalid attestation signature or request binding; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| scope_widening-010.s1 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-010.s2 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-010.s3 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-011 | scope_widening / host_to_segment | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: single_endpoint grant cannot expand to a segment |
| scope_widening-012 | scope_widening / identity_to_group | deny | A: approve; T: escalate | Comparator ignored requirement: policies/policies.json: single_identity grant cannot expand to enterprise/group scope |
| scope_widening-013 | scope_widening / irreversible | deny | C: approve; A: approve; T: escalate | policy requires a reversible action; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| scope_widening-014 | scope_widening / impact_increase | deny | C: approve; A: approve; T: approve | invalid attestation signature or request binding; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| scope_widening-015.s1 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-015.s2 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-015.s3 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-016 | scope_widening / host_to_segment | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: single_endpoint grant cannot expand to a segment |
| scope_widening-017 | scope_widening / identity_to_group | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: single_identity grant cannot expand to enterprise/group scope |
| scope_widening-018 | scope_widening / irreversible | deny | C: approve; A: approve; T: approve | policy requires a reversible action; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| scope_widening-019 | scope_widening / impact_increase | deny | C: approve; A: approve; T: approve | invalid attestation signature or request binding; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| scope_widening-020.s1 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-020.s2 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-020.s3 | scope_widening / incremental | deny | A: approve; T: approve | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-021 | scope_widening / host_to_segment | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: single_endpoint grant cannot expand to a segment |
| scope_widening-022 | scope_widening / identity_to_group | deny | A: approve; T: approve | Comparator ignored requirement: policies/policies.json: single_identity grant cannot expand to enterprise/group scope |
| scope_widening-023 | scope_widening / irreversible | deny | C: approve; A: approve; T: approve | policy requires a reversible action; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| scope_widening-024 | scope_widening / impact_increase | deny | C: approve; A: approve; T: approve | invalid attestation signature or request binding; Kernel returned a simulated receipt; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input) |
| scope_widening-025.s1 | scope_widening / incremental | deny | A: approve; T: escalate | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-025.s2 | scope_widening / incremental | deny | A: approve; T: escalate | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |
| scope_widening-025.s3 | scope_widening / incremental | deny | A: approve; T: escalate | Comparator ignored requirement: docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant |

Exit status: **1**. Any CERBERUS mismatch/violation fails the run; invalid measurements exit 2. Baseline failures do not gate CERBERUS. No historical benchmark or production policy was modified.
