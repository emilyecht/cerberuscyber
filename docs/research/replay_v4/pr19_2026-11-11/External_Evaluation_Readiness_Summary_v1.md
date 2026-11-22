# External Evaluation Readiness Summary, version 1

**READY FOR EXTERNAL PROTOTYPE EVALUATION**

This conclusion concerns a bounded, reproducible research evidence package. It is not an assurance that the prototype is secure in operation, a government endorsement or independent human validation.

The complete corrected v4 run records 1100 attempts: 1078 valid scored, 22 frozen ambiguities, 0 invalid setups; scoring gate PASS, false allows 0/878, false denies 0/200. All expected labels, historical evidence, baseline functions and evaluated implementation are preserved. The first invalid full instrument run is retained, not regraded. A separate artifact verifier recalculates baseline behavior and rejects changed frozen labels even if result hashes are recomputed.

An evaluator can inspect the four versioned reports, frozen oracle/hash and chronology, raw per-attempt receipts/state/claims/effects, all latency samples, exact environment/commit metadata, separate AI review probes, local tests and supported-Python CI. Original local commits can be restored from their exact object text; published trees are verified identical. The full rerun uses synthetic inputs and requires no operational credentials or targets.

Main-agent self-review and separate clean-context AI review are complete. Later runner/followup examinations are explicitly post-exposure AI reviews. No independent qualified human review was obtained; that remains a task for external evaluation.

Material findings remain visible: conditional committed-WAL replay loss and elapsed-real-time expiry in PR #19; full integrity-scan contention; accepted schema-valid erased/restored history; trusted path/namespace and process-local registry assumptions. Draft PR #20 supplies separately tested minimal WAL/expiry fixes. **V4 measures original PR #19, not PR #20.** Five ambiguous history-erasure attempts still produce duplicate receipts and ten invariant labels outside the frozen score. A good scored benchmark is not evidence of rollback resistance.

Validation: corrected-instrument post-repair unit/integration selection 335 passed, 1 Landlock skip on each local Python 3.10/3.12; historical v3 instrument 10 passed at its original commit on both; followup 113 focused and 325 passed/1 skip broader tests on both. Repository compile/JSON/input checks and combined 22-case contract benchmark passed; source/wheel builds passed. Local enforcement demo and complete installed verification are unavailable at the Landlock step, not passes; the installed simulation demo passed. Separate GitHub-hosted post-repair CI on both Python versions passed the 14-case supported-host lab. The original full workflow still fails preserved historical source pins, with exact statuses/links retained; no safety test is weakened to make that workflow green.

## Operational deployment

**NOT READY FOR OPERATIONAL DEPLOYMENT.**

Required work includes independent human review, authenticated persistent authority/revocation, trusted advancing clocks and connector linearization, rollback-resistant state/recovery, protected privilege/storage boundaries, capacity/retention limits, deployment keys, externally anchored audit, real least-privilege connectors and target-host validation. No production-readiness, formal verification, real containment/recovery, operational superiority or independent field-validation claim is supported.

Both evidence PR #21 and fix PR #20 remain drafts and unmerged. REPRODUCE.md and the full findings table identify the precise next technical-review tasks.
