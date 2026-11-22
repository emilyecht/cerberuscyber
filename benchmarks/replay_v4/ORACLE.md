# replay_v4 documentary oracle — Stage A only

No observed behavior, repair, evaluator or test execution is included. Machine-readable source: [oracle.json](oracle.json). Exact file SHA-256: [oracle.sha256](oracle.sha256).

Seed **604279153**; logical clock **2027-02-16T04:30:00Z**; baseline `f0ebd38c58e9d40af35d35c5cc32b5614eb60439`.

## Coverage

| Family | Cases | Primary attempts | allow | deny | escalate | doc-ambiguous |
|---|---:|---:|---:|---:|---:|---:|
| S | 55 | 55 | 10 | 43 | 0 | 2 |
| T | 50 | 115 | 20 | 85 | 0 | 10 |
| U | 130 | 160 | 30 | 120 | 5 | 5 |
| V | 45 | 45 | 40 | 0 | 0 | 5 |
| W | 725 | 725 | 100 | 625 | 0 | 0 |
| Total | **1005** | **1100** | **200** | **873** | **5** | **22** |

**1078 scored attempts.** Case-level final labels are distinct from all primary-attempt labels. T/replay/duplicate sequence prefixes are counted. W's 725 cases comprise 25 correlated parent clusters; 100 canonical-identity controls allow and 625 changed requests deny. No generalization estimate may pool these mutations.

## W rule fixed before labeling

Compare the actual original approved and candidate canonical UTF-8 bytes before selecting a label. Equal means **allow/control, never deny** in the otherwise valid clean context; unequal means **deny under original authority**. Every W record stores its canonical candidate, original-canonical reference, exact byte counts and computed equality. A future materializer must recompute the guard and verify these frozen bytes; mismatch is an invalid measurement, not permission to relabel.

All W canonical strings are ASCII, so the frozen character equality is exactly UTF-8 byte equality. Object-key order and insignificant wire whitespace disappear on documented canonicalization; array order and identifier values are not normalized. No parent or mutation is derived from v3 cases.

## Source rules

### R-STORE

[docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **State setup and recovery**: Explicitly provision once with create=True; ordinary startup uses create=False. Missing, corrupt, locked or unprovisioned durable state cannot silently acquire authority or fall back to process-local state.

### R-CLAIM

[docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **State setup and recovery**: Atomically persist token and execution-idempotency claims before any simulated receipt; consumed claims survive audit failure/restart and must not be erased to retry.

### R-VALID

[policies/policies.json](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/policies/policies.json), **CYBER-ID-001 / CYBER-RW-001 / CYBER-EX-001 / CYBER-EA-001**: The selected policy permits the exact action and scope when its confidence, signals, independent sources, reversibility and independent approvals all hold, with authenticated fresh proofs and confirmed durable state.

### R-TRUST

[docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **Trust and authority; Migration and test fixtures**: Configure trusted producer/principal allowlists independently of requests; bind genuine synthetic evidence and approvals to the complete canonical request; no re-signing an attack under the original grant.

### R-BIND

[docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **Strict gateway execution context and live token status**: The actual complete enforced envelope digest and action/target/scope must match the original signed grant. A different complete request has no authority under that grant.

### R-STATUS

[docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **Strict gateway execution context and live token status**: Unknown, revoked, wrong-purpose, mismatched or unavailable live authority refuses; revocation is ordered before or after receipt commit and cannot undo a completed receipt.

### R-TIME

[docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **Time boundary**: Evidence age must be <60 seconds; future skew <=5 seconds is accepted; execution at or beyond the earliest evidence/envelope/approval/token expiry refuses.

### R-SCHEMA

[docs/ACTION_ENVELOPE_V1.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ACTION_ENVELOPE_V1.md), **Strict input boundary; Fail-closed behavior**: Validate original decoded inputs without coercion/defaults; reject missing required or unknown fields, malformed values and unsupported contract versions.

### R-CANON

[docs/ACTION_ENVELOPE_V1.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ACTION_ENVELOPE_V1.md), **Canonical serialization and signing**: Canonical UTF-8 JSON sorts object keys and removes insignificant whitespace; identical decoded canonical bytes do not become a binding mismatch.

### R-CONFLICT

[docs/adr/0004-evidence-conflict-escalation.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/adr/0004-evidence-conflict-escalation.md), **Decision 4-7**: With valid earlier input/trust/freshness gates, cross_signal_inconsistency triggers GLOBAL-EVIDENCE-CONFLICT before policy-specific authorization, escalates, and mints no token.

### R-OPTIONAL

[schemas/action-envelope.schema.json](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/schemas/action-envelope.schema.json), **required; additionalProperties; properties.human_approvals**: All 17 current envelope fields are required and unknown metadata is forbidden. Missing a required field denies; absence of a nonexistent metadata field is an unchanged valid input, not an omission probe.

### R-LIMIT

[docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **Residual risks and evidence limits**: Trusted single-host SQLite is not established protection against malicious rollback/replacement/namespace changes or administrator deletion. Do not infer a rollback-detection/recovery guarantee.

## Owner questions and excluded ambiguities

These **22 attempts in 22 cases** are doc-ambiguous. The labels remain unresolved; they do not count as legitimate controls, correct denials, safety successes or scoring failures. A future owner clarification requires a separate pre-evaluation freeze, retaining this version.

### Q-SYMLINK

May a trusted store path be a symlink to a correctly provisioned trusted file (absolute or relative), or must ordinary startup reject symlinks? No symlink policy is documented.

Document: [docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **State setup and recovery; Residual risks and evidence limits**.

Attempts (2): `S-031.s1`, `S-032.s1`.

### Q-RESTORE

After availability loss before first execution, what review, integrity/identity proof or explicit provisioning is required to resume from an exact restored provisioned snapshot? The recovery procedure is unspecified.

Document: [docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **State setup and recovery**.

Attempts (5): `T-041.s2`, `T-042.s2`, `T-043.s2`, `T-044.s2`, `T-045.s2`.

### Q-HISTORY

How must a schema-valid store with erased claim history be distinguished from a legitimate empty provisioned store? Must an integrity epoch/history-loss marker detect it, or is this excluded trusted-storage rollback? No such mechanism/guarantee is documented.

Document: [docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **State setup and recovery; Residual risks and evidence limits**.

Attempts (5): `T-046.s2`, `T-047.s2`, `T-048.s2`, `T-049.s2`, `T-050.s2`.

### Q-ROLLBACK

What decision should follow a supplied clock moving backward, and is any rollback tolerance/detection required? The docs require a trustworthy clock and explicitly do not independently detect rollback.

Document: [docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **Time boundary**.

Attempts (5): `U-K-026.s1`, `U-K-027.s1`, `U-K-028.s1`, `U-K-029.s1`, `U-K-030.s1`.

### Q-SIDECAR

For a policy requiring no human approval, is an omitted sidecar approvals array equivalent to [], or malformed and denied? The sidecar's omission/default contract is not expressly specified.

Document: [docs/ASSURANCE_BOUNDARY.md](https://github.com/emilyecht/cerberuscyber/blob/f0ebd38c58e9d40af35d35c5cc32b5614eb60439/docs/ASSURANCE_BOUNDARY.md), **Trust and authority**.

Attempts (5): `V-041.s1`, `V-042.s1`, `V-043.s1`, `V-044.s1`, `V-045.s1`.

The envelope schema has no optional envelope fields: required-field omission denies, and absence of undeclared metadata leaves an otherwise valid request unchanged. The unresolved optional-array question concerns the **separate assurance sidecar**, not required human_approvals in the envelope.

## Complete case/attempt label index

Every attempt's full document and section citation is also embedded in oracle.json. Rule IDs below resolve to the cited rules above; R-VALID is additionally scoped to the exact selected policy ID. Ordered labels follow the primary attempts in order. This is a frozen label index, not measured results.

### Family S

| Case | Variant | Ordered expected decisions | Documentary rule(s) |
|---|---|---|---|
| `S-001` | missing_file | deny | R-STORE |
| `S-002` | missing_file | deny | R-STORE |
| `S-003` | missing_file | deny | R-STORE |
| `S-004` | missing_file | deny | R-STORE |
| `S-005` | missing_file | deny | R-STORE |
| `S-006` | zero_byte_file | deny | R-STORE |
| `S-007` | zero_byte_file | deny | R-STORE |
| `S-008` | zero_byte_file | deny | R-STORE |
| `S-009` | zero_byte_file | deny | R-STORE |
| `S-010` | zero_byte_file | deny | R-STORE |
| `S-011` | truncated_file | deny | R-STORE |
| `S-012` | truncated_file | deny | R-STORE |
| `S-013` | truncated_file | deny | R-STORE |
| `S-014` | truncated_file | deny | R-STORE |
| `S-015` | truncated_file | deny | R-STORE |
| `S-016` | wrong_schema | deny | R-STORE |
| `S-017` | wrong_schema | deny | R-STORE |
| `S-018` | wrong_schema | deny | R-STORE |
| `S-019` | wrong_schema | deny | R-STORE |
| `S-020` | wrong_schema | deny | R-STORE |
| `S-021` | wrong_permissions | deny | R-STORE |
| `S-022` | wrong_permissions | deny | R-STORE |
| `S-023` | wrong_permissions | deny | R-STORE |
| `S-024` | wrong_permissions | deny | R-STORE |
| `S-025` | wrong_permissions | deny | R-STORE |
| `S-026` | directory_in_place | deny | R-STORE |
| `S-027` | directory_in_place | deny | R-STORE |
| `S-028` | directory_in_place | deny | R-STORE |
| `S-029` | directory_in_place | deny | R-STORE |
| `S-030` | directory_in_place | deny | R-STORE |
| `S-031` | symlink | doc-ambiguous | R-STORE; R-LIMIT |
| `S-032` | symlink | doc-ambiguous | R-STORE; R-LIMIT |
| `S-033` | symlink | deny | R-STORE |
| `S-034` | symlink | deny | R-STORE |
| `S-035` | symlink | deny | R-STORE |
| `S-036` | read_only_file | deny | R-STORE |
| `S-037` | read_only_file | deny | R-STORE |
| `S-038` | read_only_file | deny | R-STORE |
| `S-039` | read_only_file | deny | R-STORE |
| `S-040` | read_only_file | deny | R-STORE |
| `S-041` | locked_file | deny | R-STORE |
| `S-042` | locked_file | deny | R-STORE |
| `S-043` | locked_file | deny | R-STORE |
| `S-044` | locked_file | deny | R-STORE |
| `S-045` | locked_file | deny | R-STORE |
| `S-046` | correctly_provisioned_file | allow | R-STORE; R-VALID (CYBER-EA-001); R-TRUST |
| `S-047` | correctly_provisioned_file | allow | R-STORE; R-VALID (CYBER-EA-001); R-TRUST |
| `S-048` | correctly_provisioned_file | allow | R-STORE; R-VALID (CYBER-EA-001); R-TRUST |
| `S-049` | correctly_provisioned_file | allow | R-STORE; R-VALID (CYBER-RW-001); R-TRUST |
| `S-050` | correctly_provisioned_file | allow | R-STORE; R-VALID (CYBER-RW-001); R-TRUST |
| `S-051` | explicit_provision_then_use | allow | R-STORE; R-VALID (CYBER-RW-001); R-TRUST |
| `S-052` | explicit_provision_then_use | allow | R-STORE; R-VALID (CYBER-EA-001); R-TRUST |
| `S-053` | explicit_provision_then_use | allow | R-STORE; R-VALID (CYBER-ID-001); R-TRUST |
| `S-054` | explicit_provision_then_use | allow | R-STORE; R-VALID (CYBER-RW-001); R-TRUST |
| `S-055` | explicit_provision_then_use | allow | R-STORE; R-VALID (CYBER-EX-001); R-TRUST |

### Family T

| Case | Variant | Ordered expected decisions | Documentary rule(s) |
|---|---|---|---|
| `T-001` | missing_after_issue | deny → deny | R-STORE |
| `T-002` | missing_after_issue | deny → deny | R-STORE |
| `T-003` | missing_after_issue | deny → deny | R-STORE |
| `T-004` | missing_after_issue | deny → deny | R-STORE |
| `T-005` | missing_after_issue | deny → deny | R-STORE |
| `T-006` | zero_after_issue | deny → deny | R-STORE |
| `T-007` | zero_after_issue | deny → deny | R-STORE |
| `T-008` | zero_after_issue | deny → deny | R-STORE |
| `T-009` | zero_after_issue | deny → deny | R-STORE |
| `T-010` | zero_after_issue | deny → deny | R-STORE |
| `T-011` | corrupt_after_issue | deny → deny | R-STORE |
| `T-012` | corrupt_after_issue | deny → deny | R-STORE |
| `T-013` | corrupt_after_issue | deny → deny | R-STORE |
| `T-014` | corrupt_after_issue | deny → deny | R-STORE |
| `T-015` | corrupt_after_issue | deny → deny | R-STORE |
| `T-016` | missing_after_receipt | allow → deny → deny | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-CLAIM |
| `T-017` | missing_after_receipt | allow → deny → deny | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-CLAIM |
| `T-018` | missing_after_receipt | allow → deny → deny | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-CLAIM |
| `T-019` | missing_after_receipt | allow → deny → deny | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-CLAIM |
| `T-020` | missing_after_receipt | allow → deny → deny | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-CLAIM |
| `T-021` | zero_after_receipt | allow → deny → deny | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-CLAIM |
| `T-022` | zero_after_receipt | allow → deny → deny | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-CLAIM |
| `T-023` | zero_after_receipt | allow → deny → deny | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-CLAIM |
| `T-024` | zero_after_receipt | allow → deny → deny | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-CLAIM |
| `T-025` | zero_after_receipt | allow → deny → deny | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-CLAIM |
| `T-026` | corrupt_after_receipt | allow → deny → deny | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-CLAIM |
| `T-027` | corrupt_after_receipt | allow → deny → deny | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-CLAIM |
| `T-028` | corrupt_after_receipt | allow → deny → deny | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-CLAIM |
| `T-029` | corrupt_after_receipt | allow → deny → deny | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-CLAIM |
| `T-030` | corrupt_after_receipt | allow → deny → deny | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-CLAIM |
| `T-031` | permission_loss | deny → deny | R-STORE |
| `T-032` | permission_loss | deny → deny | R-STORE |
| `T-033` | permission_loss | deny → deny | R-STORE |
| `T-034` | permission_loss | deny → deny | R-STORE |
| `T-035` | permission_loss | deny → deny | R-STORE |
| `T-036` | locked_then_zero_replacement | deny → deny | R-STORE |
| `T-037` | locked_then_zero_replacement | deny → deny | R-STORE |
| `T-038` | locked_then_zero_replacement | deny → deny | R-STORE |
| `T-039` | locked_then_zero_replacement | deny → deny | R-STORE |
| `T-040` | locked_then_zero_replacement | deny → deny | R-STORE |
| `T-041` | restore_exact_snapshot | deny → doc-ambiguous | R-STORE; R-LIMIT |
| `T-042` | restore_exact_snapshot | deny → doc-ambiguous | R-STORE; R-LIMIT |
| `T-043` | restore_exact_snapshot | deny → doc-ambiguous | R-STORE; R-LIMIT |
| `T-044` | restore_exact_snapshot | deny → doc-ambiguous | R-STORE; R-LIMIT |
| `T-045` | restore_exact_snapshot | deny → doc-ambiguous | R-STORE; R-LIMIT |
| `T-046` | erase_claim_history | allow → doc-ambiguous | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-CLAIM; R-LIMIT |
| `T-047` | erase_claim_history | allow → doc-ambiguous | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-CLAIM; R-LIMIT |
| `T-048` | erase_claim_history | allow → doc-ambiguous | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-CLAIM; R-LIMIT |
| `T-049` | erase_claim_history | allow → doc-ambiguous | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-CLAIM; R-LIMIT |
| `T-050` | erase_claim_history | allow → doc-ambiguous | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-CLAIM; R-LIMIT |

### Family U

| Case | Variant | Ordered expected decisions | Documentary rule(s) |
|---|---|---|---|
| `U-C-001` | expired_and_widened | deny | R-TIME; R-BIND |
| `U-C-002` | expired_and_widened | deny | R-TIME; R-BIND |
| `U-C-003` | expired_and_widened | deny | R-TIME; R-BIND |
| `U-C-004` | expired_and_widened | deny | R-TIME; R-BIND |
| `U-C-005` | expired_and_widened | deny | R-TIME; R-BIND |
| `U-C-006` | revoked_wrong_incident | deny | R-STATUS; R-BIND |
| `U-C-007` | revoked_wrong_incident | deny | R-STATUS; R-BIND |
| `U-C-008` | revoked_wrong_incident | deny | R-STATUS; R-BIND |
| `U-C-009` | revoked_wrong_incident | deny | R-STATUS; R-BIND |
| `U-C-010` | revoked_wrong_incident | deny | R-STATUS; R-BIND |
| `U-C-011` | stale_injected_proposal | deny | R-TIME; R-TRUST; R-BIND |
| `U-C-012` | stale_injected_proposal | deny | R-TIME; R-TRUST; R-BIND |
| `U-C-013` | stale_injected_proposal | deny | R-TIME; R-TRUST; R-BIND |
| `U-C-014` | stale_injected_proposal | deny | R-TIME; R-TRUST; R-BIND |
| `U-C-015` | stale_injected_proposal | deny | R-TIME; R-TRUST; R-BIND |
| `U-C-016` | revoked_dependency_target_widening | deny | R-STATUS; R-BIND |
| `U-C-017` | revoked_dependency_target_widening | deny | R-STATUS; R-BIND |
| `U-C-018` | revoked_dependency_target_widening | deny | R-STATUS; R-BIND |
| `U-C-019` | revoked_dependency_target_widening | deny | R-STATUS; R-BIND |
| `U-C-020` | revoked_dependency_target_widening | deny | R-STATUS; R-BIND |
| `U-C-021` | conflict_missing_corroboration | escalate | R-CONFLICT |
| `U-C-022` | conflict_missing_corroboration | escalate | R-CONFLICT |
| `U-C-023` | conflict_missing_corroboration | escalate | R-CONFLICT |
| `U-C-024` | conflict_missing_corroboration | escalate | R-CONFLICT |
| `U-C-025` | conflict_missing_corroboration | escalate | R-CONFLICT |
| `U-R-001` | exact_replay | allow → deny | R-VALID (CYBER-ID-001); R-STORE; R-CLAIM |
| `U-R-002` | exact_replay | allow → deny | R-VALID (CYBER-RW-001); R-STORE; R-CLAIM |
| `U-R-003` | exact_replay | allow → deny | R-VALID (CYBER-ID-001); R-STORE; R-CLAIM |
| `U-R-004` | exact_replay | allow → deny | R-VALID (CYBER-EA-001); R-STORE; R-CLAIM |
| `U-R-005` | exact_replay | allow → deny | R-VALID (CYBER-RW-001); R-STORE; R-CLAIM |
| `U-R-006` | cross_envelope_reuse | allow → deny | R-VALID (CYBER-ID-001); R-STORE; R-CLAIM; R-BIND |
| `U-R-007` | cross_envelope_reuse | allow → deny | R-VALID (CYBER-ID-001); R-STORE; R-CLAIM; R-BIND |
| `U-R-008` | cross_envelope_reuse | allow → deny | R-VALID (CYBER-EA-001); R-STORE; R-CLAIM; R-BIND |
| `U-R-009` | cross_envelope_reuse | allow → deny | R-VALID (CYBER-ID-001); R-STORE; R-CLAIM; R-BIND |
| `U-R-010` | cross_envelope_reuse | allow → deny | R-VALID (CYBER-RW-001); R-STORE; R-CLAIM; R-BIND |
| `U-R-011` | partial_claim_audit_failure | deny → deny | R-CLAIM |
| `U-R-012` | partial_claim_audit_failure | deny → deny | R-CLAIM |
| `U-R-013` | partial_claim_audit_failure | deny → deny | R-CLAIM |
| `U-R-014` | partial_claim_audit_failure | deny → deny | R-CLAIM |
| `U-R-015` | partial_claim_audit_failure | deny → deny | R-CLAIM |
| `U-R-016` | revocation_mid_sequence | deny → deny | R-BIND; R-STATUS |
| `U-R-017` | revocation_mid_sequence | deny → deny | R-BIND; R-STATUS |
| `U-R-018` | revocation_mid_sequence | deny → deny | R-BIND; R-STATUS |
| `U-R-019` | revocation_mid_sequence | deny → deny | R-BIND; R-STATUS |
| `U-R-020` | revocation_mid_sequence | deny → deny | R-BIND; R-STATUS |
| `U-R-021` | dependency_revocation_mid_sequence | deny → deny | R-BIND; R-STATUS |
| `U-R-022` | dependency_revocation_mid_sequence | deny → deny | R-BIND; R-STATUS |
| `U-R-023` | dependency_revocation_mid_sequence | deny → deny | R-BIND; R-STATUS |
| `U-R-024` | dependency_revocation_mid_sequence | deny → deny | R-BIND; R-STATUS |
| `U-R-025` | dependency_revocation_mid_sequence | deny → deny | R-BIND; R-STATUS |
| `U-O-001` | revocation_before_enforcement | deny | R-STATUS |
| `U-O-002` | revocation_before_enforcement | deny | R-STATUS |
| `U-O-003` | revocation_before_enforcement | deny | R-STATUS |
| `U-O-004` | revocation_before_enforcement | deny | R-STATUS |
| `U-O-005` | revocation_before_enforcement | deny | R-STATUS |
| `U-O-006` | dependency_revocation_before_enforcement | deny | R-STATUS |
| `U-O-007` | dependency_revocation_before_enforcement | deny | R-STATUS |
| `U-O-008` | dependency_revocation_before_enforcement | deny | R-STATUS |
| `U-O-009` | dependency_revocation_before_enforcement | deny | R-STATUS |
| `U-O-010` | dependency_revocation_before_enforcement | deny | R-STATUS |
| `U-O-011` | receipt_before_revocation | allow | R-STATUS; R-VALID (CYBER-ID-001) |
| `U-O-012` | receipt_before_revocation | allow | R-STATUS; R-VALID (CYBER-EX-001) |
| `U-O-013` | receipt_before_revocation | allow | R-STATUS; R-VALID (CYBER-RW-001) |
| `U-O-014` | receipt_before_revocation | allow | R-STATUS; R-VALID (CYBER-ID-001) |
| `U-O-015` | receipt_before_revocation | allow | R-STATUS; R-VALID (CYBER-EA-001) |
| `U-O-016` | duplicate_ordered_after_receipt | allow → deny | R-STORE; R-VALID (CYBER-EA-001); R-TRUST; R-CLAIM |
| `U-O-017` | duplicate_ordered_after_receipt | allow → deny | R-STORE; R-VALID (CYBER-ID-001); R-TRUST; R-CLAIM |
| `U-O-018` | duplicate_ordered_after_receipt | allow → deny | R-STORE; R-VALID (CYBER-EA-001); R-TRUST; R-CLAIM |
| `U-O-019` | duplicate_ordered_after_receipt | allow → deny | R-STORE; R-VALID (CYBER-ID-001); R-TRUST; R-CLAIM |
| `U-O-020` | duplicate_ordered_after_receipt | allow → deny | R-STORE; R-VALID (CYBER-EX-001); R-TRUST; R-CLAIM |
| `U-O-021` | unavailable_status_before_receipt | deny | R-STATUS |
| `U-O-022` | unavailable_status_before_receipt | deny | R-STATUS |
| `U-O-023` | unavailable_status_before_receipt | deny | R-STATUS |
| `U-O-024` | unavailable_status_before_receipt | deny | R-STATUS |
| `U-O-025` | unavailable_status_before_receipt | deny | R-STATUS |
| `U-K-001` | expiry_before | allow | R-TIME; R-VALID (CYBER-ID-001) |
| `U-K-002` | expiry_before | allow | R-TIME; R-VALID (CYBER-RW-001) |
| `U-K-003` | expiry_before | allow | R-TIME; R-VALID (CYBER-EA-001) |
| `U-K-004` | expiry_before | allow | R-TIME; R-VALID (CYBER-EA-001) |
| `U-K-005` | expiry_before | allow | R-TIME; R-VALID (CYBER-RW-001) |
| `U-K-006` | expiry_at | deny | R-TIME |
| `U-K-007` | expiry_at | deny | R-TIME |
| `U-K-008` | expiry_at | deny | R-TIME |
| `U-K-009` | expiry_at | deny | R-TIME |
| `U-K-010` | expiry_at | deny | R-TIME |
| `U-K-011` | expiry_after | deny | R-TIME |
| `U-K-012` | expiry_after | deny | R-TIME |
| `U-K-013` | expiry_after | deny | R-TIME |
| `U-K-014` | expiry_after | deny | R-TIME |
| `U-K-015` | expiry_after | deny | R-TIME |
| `U-K-016` | evidence_age_edges | allow | R-TIME |
| `U-K-017` | evidence_age_edges | deny | R-TIME |
| `U-K-018` | evidence_age_edges | deny | R-TIME |
| `U-K-019` | evidence_age_edges | allow | R-TIME |
| `U-K-020` | evidence_age_edges | deny | R-TIME |
| `U-K-021` | future_skew_edges | allow | R-TIME |
| `U-K-022` | future_skew_edges | allow | R-TIME |
| `U-K-023` | future_skew_edges | deny | R-TIME |
| `U-K-024` | future_skew_edges | allow | R-TIME |
| `U-K-025` | future_skew_edges | deny | R-TIME |
| `U-K-026` | clock_rollback | doc-ambiguous | R-TIME |
| `U-K-027` | clock_rollback | doc-ambiguous | R-TIME |
| `U-K-028` | clock_rollback | doc-ambiguous | R-TIME |
| `U-K-029` | clock_rollback | doc-ambiguous | R-TIME |
| `U-K-030` | clock_rollback | doc-ambiguous | R-TIME |
| `U-P-001` | single_field:schema_version | deny | R-BIND; R-SCHEMA |
| `U-P-002` | single_field:envelope_id | deny | R-BIND; R-SCHEMA |
| `U-P-003` | single_field:incident_id | deny | R-BIND; R-SCHEMA |
| `U-P-004` | single_field:actor | deny | R-BIND; R-SCHEMA |
| `U-P-005` | single_field:threat | deny | R-BIND; R-SCHEMA |
| `U-P-006` | single_field:action | deny | R-BIND; R-SCHEMA |
| `U-P-007` | single_field:target | deny | R-BIND; R-SCHEMA |
| `U-P-008` | single_field:scope | deny | R-BIND; R-SCHEMA |
| `U-P-009` | single_field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `U-P-010` | single_field:confidence | deny | R-BIND; R-SCHEMA |
| `U-P-011` | single_field:freshness | deny | R-BIND; R-SCHEMA |
| `U-P-012` | single_field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `U-P-013` | single_field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `U-P-014` | single_field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `U-P-015` | single_field:policy_version | deny | R-BIND; R-SCHEMA |
| `U-P-016` | single_field:mission_impact | deny | R-BIND; R-SCHEMA |
| `U-P-017` | single_field:human_approvals | deny | R-BIND; R-SCHEMA |
| `U-P-018` | single_field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `U-P-019` | single_field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `U-P-020` | single_field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `U-P-021` | single_field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `U-P-022` | single_field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `U-P-023` | single_field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `U-P-024` | unknown_metadata_added | deny | R-SCHEMA; R-OPTIONAL |
| `U-P-025` | required_human_approvals_omitted | deny | R-SCHEMA; R-OPTIONAL |

### Family V

| Case | Variant | Ordered expected decisions | Documentary rule(s) |
|---|---|---|---|
| `V-001` | critical_with_authority | allow | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-TIME |
| `V-002` | critical_with_authority | allow | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-TIME |
| `V-003` | critical_with_authority | allow | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-TIME |
| `V-004` | critical_with_authority | allow | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-TIME |
| `V-005` | critical_with_authority | allow | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-TIME |
| `V-006` | scope_ceiling | allow | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-TIME |
| `V-007` | scope_ceiling | allow | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-TIME |
| `V-008` | scope_ceiling | allow | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-TIME |
| `V-009` | scope_ceiling | allow | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-TIME |
| `V-010` | scope_ceiling | allow | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-TIME |
| `V-011` | independence_threshold | allow | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-TIME |
| `V-012` | independence_threshold | allow | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-TIME |
| `V-013` | independence_threshold | allow | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-TIME |
| `V-014` | independence_threshold | allow | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-TIME |
| `V-015` | independence_threshold | allow | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-TIME |
| `V-016` | confidence_threshold | allow | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-TIME |
| `V-017` | confidence_threshold | allow | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-TIME |
| `V-018` | confidence_threshold | allow | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-TIME |
| `V-019` | confidence_threshold | allow | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-TIME |
| `V-020` | confidence_threshold | allow | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-TIME |
| `V-021` | last_live_microsecond | allow | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-TIME |
| `V-022` | last_live_microsecond | allow | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-TIME |
| `V-023` | last_live_microsecond | allow | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-TIME |
| `V-024` | last_live_microsecond | allow | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-TIME |
| `V-025` | last_live_microsecond | allow | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-TIME |
| `V-026` | maximum_future_skew | allow | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-TIME |
| `V-027` | maximum_future_skew | allow | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-TIME |
| `V-028` | maximum_future_skew | allow | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-TIME |
| `V-029` | maximum_future_skew | allow | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-TIME |
| `V-030` | maximum_future_skew | allow | R-VALID (CYBER-EA-001); R-TRUST; R-STORE; R-TIME |
| `V-031` | empty_then_explicit_provision | allow | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-TIME |
| `V-032` | empty_then_explicit_provision | allow | R-VALID (CYBER-RW-001); R-TRUST; R-STORE; R-TIME |
| `V-033` | empty_then_explicit_provision | allow | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-TIME |
| `V-034` | empty_then_explicit_provision | allow | R-VALID (CYBER-ID-001); R-TRUST; R-STORE; R-TIME |
| `V-035` | empty_then_explicit_provision | allow | R-VALID (CYBER-EX-001); R-TRUST; R-STORE; R-TIME |
| `V-036` | canonical_absent_undeclared_metadata | allow | R-VALID (CYBER-EA-001); R-OPTIONAL; R-CANON |
| `V-037` | canonical_absent_undeclared_metadata | allow | R-VALID (CYBER-RW-001); R-OPTIONAL; R-CANON |
| `V-038` | canonical_absent_undeclared_metadata | allow | R-VALID (CYBER-ID-001); R-OPTIONAL; R-CANON |
| `V-039` | canonical_absent_undeclared_metadata | allow | R-VALID (CYBER-RW-001); R-OPTIONAL; R-CANON |
| `V-040` | canonical_absent_undeclared_metadata | allow | R-VALID (CYBER-ID-001); R-OPTIONAL; R-CANON |
| `V-041` | omitted_empty_sidecar_approvals | doc-ambiguous | R-TRUST |
| `V-042` | omitted_empty_sidecar_approvals | doc-ambiguous | R-TRUST |
| `V-043` | omitted_empty_sidecar_approvals | doc-ambiguous | R-TRUST |
| `V-044` | omitted_empty_sidecar_approvals | doc-ambiguous | R-TRUST |
| `V-045` | omitted_empty_sidecar_approvals | doc-ambiguous | R-TRUST |

### Family W

| Case | Variant | Ordered expected decisions | Documentary rule(s) |
|---|---|---|---|
| `W-0001` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0002` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0003` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0004` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0005` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0006` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0007` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0008` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0009` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0010` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0011` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0012` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0013` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0014` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0015` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0016` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0017` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0018` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0019` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0020` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0021` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0022` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0023` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0024` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0025` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0026` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0027` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0028` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0029` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0030` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0031` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0032` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0033` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0034` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0035` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0036` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0037` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0038` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0039` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0040` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0041` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0042` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0043` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0044` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0045` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0046` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0047` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0048` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0049` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0050` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0051` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0052` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0053` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0054` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0055` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0056` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0057` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0058` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0059` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0060` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0061` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0062` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0063` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0064` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0065` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0066` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0067` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0068` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0069` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0070` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0071` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0072` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0073` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0074` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0075` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0076` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0077` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0078` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0079` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0080` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0081` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0082` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0083` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0084` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0085` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0086` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0087` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0088` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0089` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0090` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0091` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0092` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0093` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0094` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0095` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0096` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0097` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0098` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0099` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0100` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0101` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0102` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0103` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0104` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0105` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0106` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0107` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0108` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0109` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0110` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0111` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0112` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0113` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0114` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0115` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0116` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0117` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0118` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0119` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0120` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0121` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0122` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0123` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0124` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0125` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0126` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0127` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0128` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0129` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0130` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0131` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0132` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0133` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0134` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0135` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0136` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0137` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0138` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0139` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0140` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0141` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0142` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0143` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0144` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0145` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0146` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0147` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0148` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0149` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0150` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0151` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0152` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0153` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0154` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0155` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0156` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0157` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0158` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0159` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0160` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0161` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0162` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0163` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0164` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0165` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0166` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0167` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0168` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0169` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0170` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0171` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0172` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0173` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0174` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0175` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0176` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0177` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0178` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0179` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0180` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0181` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0182` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0183` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0184` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0185` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0186` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0187` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0188` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0189` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0190` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0191` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0192` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0193` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0194` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0195` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0196` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0197` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0198` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0199` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0200` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0201` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0202` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0203` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0204` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0205` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0206` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0207` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0208` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0209` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0210` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0211` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0212` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0213` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0214` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0215` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0216` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0217` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0218` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0219` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0220` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0221` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0222` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0223` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0224` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0225` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0226` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0227` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0228` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0229` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0230` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0231` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0232` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0233` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0234` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0235` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0236` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0237` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0238` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0239` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0240` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0241` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0242` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0243` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0244` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0245` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0246` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0247` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0248` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0249` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0250` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0251` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0252` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0253` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0254` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0255` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0256` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0257` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0258` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0259` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0260` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0261` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0262` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0263` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0264` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0265` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0266` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0267` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0268` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0269` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0270` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0271` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0272` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0273` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0274` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0275` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0276` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0277` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0278` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0279` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0280` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0281` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0282` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0283` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0284` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0285` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0286` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0287` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0288` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0289` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0290` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0291` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0292` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0293` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0294` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0295` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0296` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0297` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0298` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0299` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0300` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0301` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0302` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0303` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0304` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0305` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0306` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0307` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0308` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0309` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0310` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0311` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0312` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0313` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0314` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0315` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0316` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0317` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0318` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0319` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0320` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0321` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0322` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0323` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0324` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0325` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0326` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0327` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0328` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0329` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0330` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0331` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0332` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0333` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0334` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0335` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0336` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0337` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0338` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0339` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0340` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0341` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0342` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0343` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0344` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0345` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0346` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0347` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0348` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0349` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0350` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0351` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0352` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0353` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0354` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0355` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0356` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0357` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0358` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0359` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0360` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0361` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0362` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0363` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0364` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0365` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0366` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0367` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0368` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0369` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0370` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0371` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0372` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0373` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0374` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0375` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0376` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0377` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0378` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0379` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0380` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0381` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0382` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0383` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0384` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0385` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0386` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0387` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0388` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0389` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0390` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0391` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0392` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0393` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0394` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0395` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0396` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0397` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0398` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0399` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0400` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0401` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0402` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0403` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0404` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0405` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0406` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0407` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0408` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0409` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0410` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0411` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0412` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0413` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0414` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0415` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0416` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0417` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0418` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0419` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0420` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0421` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0422` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0423` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0424` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0425` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0426` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0427` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0428` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0429` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0430` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0431` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0432` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0433` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0434` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0435` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0436` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0437` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0438` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0439` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0440` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0441` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0442` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0443` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0444` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0445` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0446` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0447` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0448` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0449` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0450` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0451` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0452` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0453` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0454` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0455` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0456` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0457` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0458` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0459` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0460` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0461` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0462` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0463` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0464` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0465` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0466` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0467` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0468` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0469` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0470` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0471` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0472` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0473` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0474` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0475` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0476` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0477` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0478` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0479` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0480` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0481` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0482` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0483` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0484` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0485` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0486` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0487` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0488` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0489` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0490` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0491` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0492` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0493` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0494` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0495` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0496` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0497` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0498` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0499` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0500` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0501` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0502` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0503` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0504` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0505` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0506` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0507` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0508` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0509` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0510` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0511` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0512` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0513` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0514` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0515` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0516` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0517` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0518` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0519` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0520` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0521` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0522` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0523` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0524` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0525` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0526` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0527` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0528` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0529` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0530` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0531` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0532` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0533` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0534` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0535` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0536` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0537` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0538` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0539` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0540` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0541` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0542` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0543` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0544` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0545` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0546` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0547` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0548` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0549` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0550` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0551` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0552` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0553` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0554` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0555` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0556` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0557` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0558` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0559` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0560` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0561` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0562` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0563` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0564` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0565` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0566` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0567` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0568` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0569` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0570` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0571` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0572` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0573` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0574` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0575` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0576` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0577` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0578` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0579` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0580` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0581` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0582` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0583` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0584` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0585` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0586` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0587` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0588` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0589` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0590` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0591` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0592` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0593` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0594` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0595` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0596` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0597` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0598` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0599` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0600` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0601` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0602` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0603` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0604` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0605` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0606` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0607` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0608` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0609` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0610` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0611` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0612` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0613` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0614` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0615` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0616` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0617` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0618` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0619` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0620` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0621` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0622` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0623` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0624` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0625` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0626` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0627` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0628` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0629` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0630` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0631` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0632` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0633` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0634` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0635` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0636` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0637` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0638` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0639` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0640` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0641` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0642` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0643` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0644` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0645` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0646` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0647` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0648` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0649` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0650` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0651` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0652` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0653` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0654` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0655` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0656` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0657` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0658` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0659` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0660` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0661` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0662` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0663` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0664` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0665` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0666` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0667` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0668` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0669` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0670` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0671` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0672` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0673` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0674` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0675` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0676` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0677` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0678` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0679` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0680` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0681` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0682` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0683` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0684` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0685` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0686` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0687` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0688` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0689` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0690` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0691` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0692` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0693` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0694` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0695` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0696` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EA-001); R-STORE; R-TRUST |
| `W-0697` | field:schema_version | deny | R-BIND; R-SCHEMA |
| `W-0698` | field:envelope_id | deny | R-BIND; R-SCHEMA |
| `W-0699` | field:incident_id | deny | R-BIND; R-SCHEMA |
| `W-0700` | field:actor | deny | R-BIND; R-SCHEMA |
| `W-0701` | field:threat | deny | R-BIND; R-SCHEMA |
| `W-0702` | field:action | deny | R-BIND; R-SCHEMA |
| `W-0703` | field:target | deny | R-BIND; R-SCHEMA |
| `W-0704` | field:scope | deny | R-BIND; R-SCHEMA |
| `W-0705` | field:evidence_refs | deny | R-BIND; R-SCHEMA |
| `W-0706` | field:confidence | deny | R-BIND; R-SCHEMA |
| `W-0707` | field:freshness | deny | R-BIND; R-SCHEMA |
| `W-0708` | field:idempotency_key | deny | R-BIND; R-SCHEMA |
| `W-0709` | field:reversibility_flag | deny | R-BIND; R-SCHEMA |
| `W-0710` | field:required_approval_mode | deny | R-BIND; R-SCHEMA |
| `W-0711` | field:policy_version | deny | R-BIND; R-SCHEMA |
| `W-0712` | field:mission_impact | deny | R-BIND; R-SCHEMA |
| `W-0713` | field:human_approvals | deny | R-BIND; R-SCHEMA |
| `W-0714` | field:evidence_refs.0.source_id | deny | R-BIND; R-SCHEMA |
| `W-0715` | field:evidence_refs.0.digest | deny | R-BIND; R-SCHEMA |
| `W-0716` | field:evidence_refs.0.signal | deny | R-BIND; R-SCHEMA |
| `W-0717` | field:evidence_refs.0.observed_at | deny | R-BIND; R-SCHEMA |
| `W-0718` | field:freshness.timestamp | deny | R-BIND; R-SCHEMA |
| `W-0719` | field:freshness.expires_at | deny | R-BIND; R-SCHEMA |
| `W-0720` | field:freshness.nonce | deny | R-BIND; R-SCHEMA |
| `W-0721` | field:human_approvals.0 | deny | R-BIND; R-SCHEMA |
| `W-0722` | identity_noop_assignment | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0723` | identity_object_order_and_whitespace | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0724` | identity_escaped_ASCII_identifier | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |
| `W-0725` | identity_change_then_restore | allow | R-CANON; R-VALID (CYBER-EX-001); R-STORE; R-TRUST |

No system is run in Stage A. All runtime materialization, signatures, positive controls, repairs and measurements are deferred. Do not start Stage B.
