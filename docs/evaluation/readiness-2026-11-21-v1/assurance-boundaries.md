# Threat model and assurance boundaries

The evaluated property is bounded authorization of one exact request, followed by
a simulated receipt or the optional fixed temporary-marker effect. Protect tokens,
approval/evidence bindings, replay claims, live authority state and audit records.
The untrusted worker/requester may alter proposals, substitute approvals or tokens,
widen scope, replay grants, submit malformed input, and attempt the lab's direct
filesystem bypasses. Fault injection includes missing, zero-byte, corrupt or locked
state, process death, concurrent processes, expiry and registry unavailability.

## Trusted dependencies

Guardian, broker/controller, policy provisioning, evidence/approval trust roots,
HMAC signer, interpreter and imported modules, OS/kernel, advancing clock, SQLite
implementation, protected storage parents, namespace configuration, registration
and revocation delivery are trusted. Evidence signatures authenticate configured
producers; they do not establish observational truth or organizational independence.
The process-local registry must be shared by all participating trusted gateways.
Losing it refuses old grants as unknown; safe authenticated reconstruction is open.

The Linux lab confines its separate worker, not arbitrary code inside the trusted
controller. It requires a supported Landlock ABI and explicit kernel errno
evidence. Local ENOSYS is unavailable and must never become a successful test.

## Findings and residual risks

| Finding | Observed result | Security consequence and tracking |
| --- | --- | --- |
| Zero-byte or malformed initialization | PR 19 refuses ordinary unprovisioned opens and tested corruption | Repair tested; explicit `create=True` remains a trusted provisioning operation |
| WAL recovery loss | Old committed WAL corruption can erase claims with integrity_check still ok | PR 20 refuses non-DELETE mode; authenticated rollback is separate |
| Expiry after blocking consume | Original #19 can acknowledge late; PR 20 fresh probe refuses and retains claim | Tested bounded repair, not a real-connector deadline guarantee |
| Marker expiry and revocation gap | New #22 tests fail six ways on #20 and pass after repair | Lock now encloses effect/audit; final time sample precedes syscall |
| Schema-valid history erasure or restore | Five v4 duplicate receipts; fresh valid-snapshot reconsumption on #22 | OPEN issue [23](https://github.com/emilyecht/cerberuscyber/issues/23); trusted storage continuity required |
| Integrity scan contention | 500k rows, eight distinct callers: six accepted, two unavailable | OPEN issue [24](https://github.com/emilyecht/cerberuscyber/issues/24); availability not guaranteed |
| Mutable path identity | Injected lstat/open swap follows a symlink at initialization; next static claim refuses | OPEN issue [25](https://github.com/emilyecht/cerberuscyber/issues/25); no TOCTOU-proof path boundary |
| Registry and effect lifecycle | Process-local revocation; claim/effect/audit not atomic | OPEN issue [26](https://github.com/emilyecht/cerberuscyber/issues/26); no exactly-once recovery |
| Integration and review | Red legacy checks coexist with green post-repair checks; adequate external review absent | OPEN issue [27](https://github.com/emilyecht/cerberuscyber/issues/27); default-branch integration blocked |

A burned claim may prevent an otherwise legitimate action after a crash. An effect
may occur before its audit is appended. An advancing-clock check cannot make time
atomic with kernel completion; a stalled effect can delay revocation. No durable
audit anchor, state rollback prevention, real system restoration, general sandbox
guarantee, field security rate, certification or agency accreditation is demonstrated.

Prototype evaluation readiness requires transparent source pins and these residual
risks, not pretending they have been eliminated. Retain TRL 2-3.
