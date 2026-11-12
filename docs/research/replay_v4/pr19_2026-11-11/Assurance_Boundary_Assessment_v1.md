# Assurance Boundary Assessment, version 1

CERBERUS Cyber remains a TRL 2–3 defensive research prototype. The evaluated v4
implementation is exactly PR #19, `6fe417400ff4844d7647dddd9435288c3485ffc0`.
The separate followup PR #20 is not silently substituted for this target. No
production-readiness, formal-verification or operational-superiority claim follows.

## Demonstrated boundary

The recorded synthetic cases exercise authenticated fixture evidence and approval
signatures, deterministic Guardian policy, full-envelope signed request binding,
trusted process-local live revocation, shared single-host SQLite replay claims and
an exact simulated receipt/audit boundary. Ordinary missing/unprovisioned or tested
main-file corruption cannot be substituted for explicit provisioning. A successful
receipt causes a recorded symbolic state change even if the request was unsafe;
the observer does not suppress effects using expected labels.

Reproduction pins the target, Guardian blob, documentary sources, policies, wire
schemas, seed, logical clock and original oracle. Historical results are preserved.
Counts/intervals describe these fixtures; W is a correlated 25-parent mutation
sweep. The runner and repair had access to public precommitted cases; prior failures
motivated the test design. This is post-repair challenge/regression evidence, not
blinded generalization or independent field validation.

## Assumptions and unestablished properties

| Boundary | Assumed or missing | Needed before an operational claim |
| --- | --- | --- |
| Provisioning and trusted state | Canonical schema is not authenticated provenance; namespace, path and all producers/controllers are trusted | Authenticated lifecycle/identity, protected storage paths and fail-closed deployment configuration |
| Historical replay continuity | Valid erased/restored state is accepted; WAL recovery loss is a separate conditional gap in PR #19 | External monotonic/history anchors, explicit recovery reconciliation, fault/power-loss tests; review proposed DELETE-mode restriction |
| Time at actual execution | Fixed logical clocks do not test elapsed wall time; PR #19 can cross expiry while consuming state | Trusted advancing clocks, explicit execution linearization, post-wait checks and real connector deadline tests; review PR #20 separately |
| Concurrency and availability | Single-host serialized writes; integrity scan cost grows with retained history; no capacity/queue/retention contract | Measured retained-history limits, bounded queues/deadlines and safe storage lifecycle; preserve corruption detection |
| Authority and revocation | Shared process-local registry; upstream revocation delivery and dependency completeness trusted | Persistent authenticated authority service, identity/channel security, revocation failure/recovery tests and defined distributed semantics |
| Signer and privilege separation | Prototype HMAC signer and trusted process memory; fixture private keys are public test material | Hardware-backed deployment keys, rotation, authenticated issuer service and isolation from untrusted workers |
| Effects and audit | Gateway receipts and synthetic state are not real containment; local hash chain is not externally anchored; claim is not atomically joined to external action | Least-privilege real connectors, fault-tolerant effect protocols, externally anchored audit and recovery accounting |
| Real-effect lab | Landlock demonstration is a bounded Linux facility, separate from the simulation gateway | Deployment-host refusal evidence, supported kernel configuration, operational threat model and connector integration |
| Reviewer independence | Main-agent self-review and separate AI examinations only | Independent qualified human security review and an evaluator-controlled assessment with independently chosen inputs |

Local enforcement demo and installed verification report unavailable on this host
because Landlock ABI >=3 returns ENOSYS. That is not evidence of successful local
confinement here. PR #20's separate GitHub-hosted Python 3.10/3.12 workflow did run
the 14-case lab successfully on its supported host. These are host- and branch-specific
observations, not universal kernel/isolation guarantees or v4 real-effect validation.

## Deployment assessment

**NOT READY FOR OPERATIONAL DEPLOYMENT.** Scope is a reproducible research
evaluation of selected authorization boundaries. Real-world deployment requires
the missing controls above, resolution/acceptance of the documented findings,
supported-host verification, independent review and substantially different
evidence from synthetic benchmark accuracy alone.
