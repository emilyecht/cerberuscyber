# CERBERUS engineering assessment

Prepared 21 November 2026. **CERBERUS is ready for a bounded initial technology
introduction and a reproducible research evaluation, with the limits in this
package. It is not ready for operational deployment.** Retain TRL 2-3. No agency
submission or agreement has been made. CIA-specific introduction documents are
prepared separately for owner review.

## Changes actually implemented

Cyber [PR 22](https://github.com/emilyecht/cerberuscyber/pull/22) repairs the
temporary-marker broker. Previously it froze the clock across durable consumption
and released the live-authority lock before its actual marker write. New tests
demonstrated expired effects and revocation completion before the effect. The
broker now holds the registry lock through authorization, marker write and audit,
checks advancing time through the gateway and again immediately before the
marker syscall, and turns unavailable/corrupt state into controlled refusals.
Consumed claims remain burned after late refusal.

Seven broker cases and three SQLite OS-process/atomicity cases were added. The
post-repair workflow triggers on these changes and now builds and verifies the
installed wheel on supported Linux. The production repair commit is
`d03ed58791b4a39cef6ac67a9b3b6be51bcdc6de`; its workflow completion commit is
`7f0174e14c710cd1d3834fc57af3e05ea110f37f`. No Guardian policy, schema, frozen
instrument/oracle or historical result changed.

Protocol [PR 7](https://github.com/emilyecht/cerberus-runtime-assurance/pull/7),
`47cc290a9f1b5c7ba17f569071895c0be5390b3b`, extends the already implemented
Boolean vertical slice. A new three-layer hand example is cross-checked against
all 16 root-cause assignments and four hash seeds. It exposes shared causes even
where exact cut-set overlap is zero. Malformed Unicode now gives a controlled
no-result refusal. The frozen Boolean schema, enumeration algorithm and valid
model outputs are unchanged. No runtime coupling to Cyber was added.

This versioned package adds source identities, capability inventory, threat model,
reproduction commands, complete fresh v4 observations/timing, functional v3
reproduction, raw test/probe logs, preserved failures and a proposed external
procedure. The new evidence is additive; predecessor artifacts remain intact.

## Pull requests and integration decisions

| PR | Base and dependency | Observed checks/review | Decision |
| --- | --- | --- | --- |
| Cyber 16 | main | Original safety gate red, 16/110 false allows; draft | Keep open; historical failure must remain visible |
| Cyber 17 | 16 | Green Python 3.10/3.12; draft, no independent human approval | Keep open pending stack review |
| Cyber 18 | 17 | Green checks; safety result remains v3 FAIL | Reviewed and fresh functional result reproduced; keep open behind dependencies |
| Cyber 19 | 18 | No check runs on inspected head; COMMENT AI review, not approval | Repair tests reproduced through descendant trees; keep open for exact-head required checks/review |
| Cyber 20 | 19 | Green post-repair, red original workflow; draft | WAL and expiry fixes reproduced; keep open for review/integration |
| Cyber 21 | 19, sibling of 20 | Green post-repair, red original workflow; draft | Both old artifacts and fresh v4 verified; keep open as distinct #19 evidence |
| Cyber 22 | 20 | Green supported post-repair at repair commit, red original workflow; draft | New repair and CI evidence published; keep open pending adequate review and dependency integration |
| Protocol 7 | main | Green Boolean-slice Python 3.10/3.12; no independent human approval | Reviewable new change; keep open for owner/reviewer review |

No PR was merged. Appropriate sequence is #16 -> #17 -> #18 -> #19; #20 and #21
then remain sibling changes to review and combine deliberately; #22 follows #20.
The evidence branch does not make #20/#22 the target of v4. The exact combined
tree must be tested before any default-branch integration claim.

Classic main-branch protection reads returned 403 from the connected app on both
repositories. Visible rulesets were empty, which does not prove classic protection
is absent. Required-check configuration could not be established. No protection
bypass, forced merge or invented human approval was attempted. New issue
[27](https://github.com/emilyecht/cerberuscyber/issues/27) captures the historical
versus current CI split needed for safe integration.

## Tests executed and results

The [measurement ledger](measurements.md) gives every denominator and material
validation limitation. Highlights: default Cyber 257 passed/1 skipped; #20
current-source 325/1; #21 current-source 335/1; #22 clean current-source 335/1
locally and 336 passes per supported CI Python job; historical v3 instrument 10
passes on its original source. Seven new broker cases have six failures on
unmodified #20 and seven passes after repair. Three process tests pass. The
combined 22-case contract has 0/11 unsafe authorizations and 8/8 eligible successes.

Full fresh frozen v4 reproduces 0/878 false allows and 0/200 false denies across
1,078 scored attempts, with no setup errors or repetition mismatches. All 22
ambiguities, including five duplicate receipts and ten invariant labels, remain
outside the score. Original instrument v1 remains INVALID_MEASUREMENT with two
permission setup errors. Fresh historical v3 functional execution remains FAIL,
9/3,484 false allows and 0/133 false denies; seven oracle defects remain in that
score. V1/v2 original evidence was not relabeled.

The original full suite on #22 has 338 passes, one failure, six errors and one
local Landlock skip because immutable v3 rejects changed protected source. An
earlier dirty-tree run also failed a benchmark's clean-source precondition; the
subsequent clean-commit run passed. Both are retained, not hidden.

Local source/wheel builds and four isolated installed simulation cases pass.
The local complete installed verifier stops at unavailable Landlock. Supported
CI at d03ed58 ran the native 14-case lab with five actual kernel refusals, one
authorized temporary marker and zero unauthorized resource changes on both
Python versions. The later workflow commit adds the installed-wheel gate;
it also passed on both supported Python versions, including both builds and
installed-wheel verification with four portable plus 14 native lab cases. Exact
check URLs and log extracts are retained in CI evidence.

Protocol main has 13 passing unittest methods; PR 7 has 16 locally and green
3.10/3.12 CI. These method counts encompass many subcases and are not independent
field trials. No independent human or agency evaluation occurred.

## Security issues resolved and remaining

The new code resolves the demonstrated marker clock-freezing and revocation
ordering gaps, plus controlled state-failure handling. Existing proposed #19/#20
repairs resolve the tested unprovisioned/corrupt main-file, conditional WAL and
post-consumption expiry paths; they remain unmerged and cannot be attributed to
default main. New process tests strengthen evidence for atomic trusted-history
claims and process restart behavior.

Remaining issues have impact, reproduction and acceptance criteria:

- [23](https://github.com/emilyecht/cerberuscyber/issues/23): authenticated
  replay-history continuity and recovery after rollback/erasure.
- [24](https://github.com/emilyecht/cerberuscyber/issues/24): retained-history
  integrity-scan contention. Fresh 500k-row burst had two unavailable refusals
  among eight distinct healthy callers; do not remove integrity checks to speed it up.
- [25](https://github.com/emilyecht/cerberuscyber/issues/25): trusted path identity
  and lstat/open replacement races.
- [26](https://github.com/emilyecht/cerberuscyber/issues/26): durable revocation,
  execution linearization and claim/effect/audit crash reconciliation.
- [27](https://github.com/emilyecht/cerberuscyber/issues/27): authoritative CI
  separation and reviewed stack integration.

There is no authenticated anti-rollback anchor, durable registry service,
externally anchored audit, exactly-once external connector, operational recovery,
field-scale capacity result or production containment capability. Time is sampled
before a Python file syscall, not atomically with kernel completion. Trusted
controller/key/clock/storage assumptions remain essential.

## Evidence supporting evaluation readiness

The project now has a reproducible failure-to-repair chain, an untouched frozen
oracle, separately verified invalid and corrected measurements, full raw
observations and timing, new falsifiable regressions, actual supported-host kernel
refusals and precise open issues. This is enough to invite a narrow independent
prototype assessment. It is insufficient for certification, mission integration
or a claim of reliable operational autonomy.

## Three highest leverage engineering tasks

1. Specify and prototype authenticated history continuity with an external
   monotonic/epoch anchor and explicit recovery reconciliation. Test erasure,
   valid-snapshot restore, namespace replacement and interrupted recovery under
   a new versioned evaluator-controlled challenge.
2. Define the authority and execution lifecycle across restart, unavailable
   revocation delivery, blocking effects and crashes. Then measure a bounded
   single-host storage/concurrency contract while retaining index-corruption
   detection and fail-closed behavior.
3. Obtain qualified independent review of exact heads, resolve current/historical
   CI semantics without weakening evidence, and integrate the stack in dependency
   order with supported-host installed-package and combined-tree validation.

## Initial CIA introduction assessment

**Yes for a concise research introduction and request for pathway guidance.**
Lead with independently developed TRL 2-3 work and a proposed bounded evaluation.
Explain the scored v4 result together with erased-history failures. Describe
Cyber and Protocol separately. Offer public pinned evidence and request guidance,
without assuming eligibility, funding, procurement or research partnership.

CIA's official Digital Gateway page describes vendor engagement and prototype
pathways; CIA Labs describes collaborative research and outreach. Given this
maturity, a research-pathway inquiry is a reasonable inference, not an agency
invitation or finding of fit. Verify the live recipient/form and disclosure terms
when the owner chooses to proceed. No contact details, agreements or agency
submission are completed by this package.

Official sources checked 21 November 2026:
https://www.cia.gov/tech/tech-collaboration/digital-gateway/ ;
https://www.cia.gov/cia-labs/ ; https://www.cia.gov/tech/tech-collaboration/ .
