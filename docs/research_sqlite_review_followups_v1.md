# SQLite review followups, version 1

This branch is based on PR #19 commit
`6fe417400ff4844d7647dddd9435288c3485ffc0`. It addresses two separately reproduced
conditional security gaps without changing Guardian, policies, schemas, frozen
oracles, case corpora, historical results, or the implementation evaluated by v4.
No claim that v4 measured this branch is made.

| Finding | Smallest change | Regression evidence |
| --- | --- | --- |
| A checksum-damaged committed WAL may recover to valid-looking schema with lost replay claims; integrity_check can return ok | Refuse any journal mode except DELETE during verification before every claim; never convert WAL state silently | Normal reopen, existing-object claim and explicit-provision WAL refusals; one-bit corruption of independently observed committed WAL after abrupt child exit; healthy DELETE positive control |
| A real-clock token may expire while durable consume waits for a lock or full integrity scan | Refresh real time after consume, refuse an expired receipt and retain the consumed claim; timestamp a successful receipt with refreshed time | Deterministic shared token/gateway clock crosses the deadline inside a real durable consume; boundary negative and live positive controls; both preserve duplicate refusal |

The WAL finding and placement of the expiry check predate PR #19. Full integrity
checking increases contention and widens the expiry window. Both remain important
limits on broad claims about corrupt-state refusal or expiry at receipt commit.

New focused selection: `python -m pytest -q tests/test_sqlite_review_followups.py
tests/test_state_initialization.py tests/test_assurance_hardening.py
tests/test_kernel_binding.py` — **113 passed** on Python 3.12.14 / SQLite 3.53.1
and Python 3.10.22 / SQLite 3.53.1. Record actual versions from the evidence
package if a reproduction uses another SQLite build.

The first six newly authored regression cases initially failed because the tests
matched an inner exception's message against its generic outer wrapper and patched
only one of the two clocks. Corrected tests inspect the exact chained cause and
patch token verification and gateway to the same advancing clock. Existing tests
were not weakened. The initial development log is retained with the final logs.

Review provenance: main-agent self-review plus a separate AI examination and
reproduction; no independent human review or field validation. The separate
reviewer had already inspected v4 runner inputs by the time it reviewed these
followups. These fixes are therefore post-exposure work, not a held-out result.

Remaining limits: trusted single-host storage and parent directories; no authenticated
rollback/replacement history; no protection if a trusted administrator changes a
recovered WAL database back to DELETE and calls it trustworthy; no cryptographic
provisioning attestation; process-local live revocation registry; no exactly-once
external effects. The unchanged full-history integrity_check still holds a writer
reservation and can cause healthy requests to time out as history/load grows. Do
not remove it without an alternative that preserves table/index corruption refusal.
Real deployment needs an advancing trusted clock, a defined execution linearization
point, persistent revocation, least-privilege real connectors, external audit anchors,
capacity limits and independent review. Caller-supplied `now` is trusted fixed logical
time for simulations. This followup does not turn it into an advancing clock.

The original full pytest/CI path intentionally rejects repaired `state.py` through
v3's protected-source pin. Keep those pins. Validate current nonhistorical tests
separately and run the historical v3 instrument on its original commit, as the v4
evidence branch documents. Neither PR #19 nor this followup is merged by this work.
