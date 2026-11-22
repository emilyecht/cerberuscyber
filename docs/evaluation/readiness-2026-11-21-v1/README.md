# CERBERUS external evaluation package version 1

Package `readiness-2026.11.21-v1`, prepared 21 November 2026. CERBERUS remains
**TRL 2-3 research**. This package supports an initial technical introduction and
a bounded independent prototype evaluation. It does not support operational
deployment, production containment, rollback-resistant replay protection or
operational recovery.

Fresh replay v4 reproduced its frozen scored gate: **0/878 false allows and
0/200 false denies**, 1,100 attempts, 1,078 scored, 22 documentary ambiguities,
zero invalid primary setups and zero repeated-outcome mismatches. Five
erased-history duplicate receipts remain outside that score and are concrete
remaining failures. Historical v3 functional reproduction remains **FAIL,
9/3,484 false allows and 0/133 false denies**. No historical labels changed.

## Architecture and project separation

Cyber's advisory component produces a structured proposal. Guardian validates the
exact envelope, policy, authenticated evidence and approvals, freshness and replay
state. An approved decision can carry a short-lived HMAC token. The gateway
requires that exact envelope, a live trusted registry record, matching purpose and
scope, and an atomic token/execution claim before returning a **simulated** receipt.
The optional Linux lab places a scripted adversarial worker under Landlock and
lets a trusted broker write one temporary marker. That marker is not a network
containment action. The broker, Guardian and controller remain trusted.

Protocol is a separate architecture/research repository. Its implemented Boolean
structural-FCOI slice enumerates minimal sufficient failure sets in a bounded
static model and reports model-relative exact overlap. It neither grants authority
nor proves real-world independence. Its broader Vigil/Anchor concepts are not
integrated Cyber security capabilities.

## Exact source identities

| Artifact or source | Commit | Role |
| --- | --- | --- |
| Cyber default main | c6894a5cee974ff7904d2f27c13c547a973debda | Initial default, before unmerged replay stack |
| Cyber PR 18 | f0ebd38c58e9d40af35d35c5cc32b5614eb60439 | Original v3 failure and functional reproduction |
| Cyber PR 19 | 6fe417400ff4844d7647dddd9435288c3485ffc0 | Exact implementation measured by v4 |
| Cyber PR 20 | c5fad3b3dc3fe5e214b143f9d43142d5466ac358 | Later WAL and advancing-clock fixes |
| Cyber PR 21 | 94c5b746100bf82ad1d405cef0ef348c56667e4f | v4 runner and preserved original artifacts |
| Cyber PR 22 repair | d03ed58791b4a39cef6ac67a9b3b6be51bcdc6de | New local-marker authority-boundary repair |
| Cyber PR 22 final validation | 7f0174e14c710cd1d3834fc57af3e05ea110f37f | Same production code plus supported installed-wheel CI |
| Protocol initial main | 48e62fd8a645c10c9161dadf62c07d0eb1c2ee5a | Existing Boolean engine and schema |
| Protocol PR 7 | 47cc290a9f1b5c7ba17f569071895c0be5390b3b | Expanded FCOI fixtures and Unicode refusal |

Cyber evaluation-kit version remains `0.1.0rc1`; DecisionToken is `1.3.0`,
ActionEnvelope and PolicyBundle schemas are `1.0.0`, policy rules `0.5.0`.
Protocol distribution/report version remains `0.1.0`, Boolean schema `1.0.0`.
The evidence publication commit is the commit containing this directory; it is
not substituted for any measured implementation commit above.

## Package contents

- [Capability inventory](capability-inventory.md)
- [Threat model and assurance boundaries](assurance-boundaries.md)
- [Measurements and chronology](measurements.md)
- [Installation and reproduction](reproduce.md)
- [Proposed independent evaluation](independent-evaluation.md)
- [Engineering assessment and integration decisions](engineering-assessment.md)
- Raw observations and logs: `results/readiness_2026-11-21/`, including a SHA-256 manifest.

## Evidence classifications

| Classification | Evidence here | What it establishes |
| --- | --- | --- |
| Synthetic simulation | Frozen v1-v4, combined contract, local tests | Behavior on the specified fixtures and trust assumptions |
| Local enforcement demonstration | PR 22 supported GitHub-hosted Linux jobs | Five actual kernel refusals and one temporary marker effect in that host configuration |
| Independent validation | None completed | Proposed procedure only; CI is project-controlled automation |
| Operational capability | None established | No operational connector, recovery, accreditation or deployment evidence |

The review and fresh reproduction were AI-led. No independent qualified human
review, CIA evaluation, endorsement or agency interest is asserted. Government
introductory documents are prepared separately for owner review and have not
been submitted to an agency.
