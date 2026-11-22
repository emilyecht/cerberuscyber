# Proposed independent prototype evaluation

An external security/research team can evaluate whether exact, verifiable
authorization is enforced under explicitly bounded faults. The proposed exercise
uses synthetic requests and temporary files. It makes no claim of agency
participation or independent validation already completed.

## Scope and environment

Allocate a disposable Linux VM with Landlock ABI >=3, no production credentials
or telemetry, a non-root evaluator identity without effective capabilities,
Python 3.10 and/or 3.12, a complete Git history and checked dependency versions.
Allow dependency acquisition before evaluation, then disable evaluation networking.
Use evaluator-controlled artifact storage and clocks for advancing-time probes.
The duration depends on the full replay and storage-growth sweeps; do not promise
an operational deployment schedule or a fixed agency engagement.

Evaluate three separate artifacts: historical v4 measured implementation #19;
current repaired broker #22; and separate Protocol FCOI #7. Record exact commits,
source hashes, build hashes, OS/kernel, UID/capabilities, SQLite configuration,
dependency inventory and all command exit codes before scoring.

## Procedure and decision rules

| Stage | Required evidence | Success condition | Failure or invalidity condition |
| --- | --- | --- | --- |
| Provenance | Source/manifest hashes, original local-commit restoration | Exact pinned bytes verified, predecessor artifacts retained | Missing or conflicting source/hash mapping; no inferred pass |
| Historical integrity | Original invalid v4 and corrected v4, v3 original source | Invalid run stays invalid; v3 gate stays FAIL; corrected v4 artifact verifies | Relabeling, discarded cases, weakened pins, denied-all grading or altered denominator |
| Fresh frozen replay | 1,100 per-attempt observations plus repetitions | Reproduce scored 0/878 and 0/200, with no setup errors or mismatches | Any scored discrepancy; unsupported permission fixture is INVALID_MEASUREMENT |
| Broader replay assurance | Erased-history and restored-state cases | Report five duplicates as known failures and expose trust continuity limits | Treating those cases as defensive passes or asserting rollback resistance |
| Authority negatives | Independently authored token, envelope, approval, scope, purpose, revocation and time mutations | No receipt or marker effect without valid current bounded authority; positive controls succeed | Unauthorized acceptance/effect, silent fallback, or failed positive control hidden as defense |
| Durable state | Corruption, missing/zero state, locking, eight processes, restart and interrupted transaction | Replay refused under intact trusted history; ambiguity and availability failures explicit | Duplicate consumption under supported intact history, automatic reprovisioning or crash credited as defense |
| Kernel lab | Same-UID worker, snapshots, errno evidence, installed package | 14 expected cases, 5 kernel refusals, 1 authorized temporary marker change, zero unauthorized changes | Unavailable isolation, missing refusal evidence, effect without valid authority, or receipt-only positive control |
| Protocol | Frozen schema, hand fixtures, exhaustive truth tables, hash seeds, invalid/incomplete/budget cases | Exact expected cut sets; no partial exact scores; zero overlap not equated to independence | Wrong family, nondeterminism, partial result advertised as exact, or conceptual capability claimed implemented |

The scored frozen gate is a reproduction criterion only. A broader assurance
conclusion must explicitly retain the erased-history failures and the WAL/clock
findings against #19. The repaired #22 has its own regression/CI evidence; do not
attribute #19's v4 count to it without a separately specified measurement.

## Evaluator chosen challenges

Before execution, the external team should record new inputs and expected outcomes
without sharing them with repair authors. Include approval substitution across
incidents, targets and principals; token reuse after scope/policy/request mutation;
registry restart and revocation-service loss; lock waits across expiry; exceptions
after durable consume; backup restore and history erasure; concurrent fresh grants
for one execution; path replacement; and increasing retained history. Record
genuine positive controls for each negative family. Preserve any discovered
failure and use a new evaluation version for a later repair.

## Open research questions and deliverables

Can authenticated monotonic history detect rollback and support explicit safe
recovery? Can integrity checking retain index-corruption detection while bounding
queue and revocation delay? How should authority survive restart and lost delivery?
Where is the linearization point for a real connector, and how are effects
reconciled after crashes? Which shared failure causes are supported by reviewed
evidence rather than modeling assumptions?

The evaluator should deliver immutable raw observations, per-family denominators,
invalidity reasons, kernel refusal evidence, independent effect observations,
all known failures, source/build/environment hashes and an explicit assessment of
which claims are and are not supported. No passing fixture gate authorizes
deployment, certifies containment or changes TRL automatically.
