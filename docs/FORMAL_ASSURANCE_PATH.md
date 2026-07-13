# Guardian Formal Assurance Path

The current Guardian is tested but not formally verified. This document defines a realistic progression from executable policy tests to stronger assurance.

## Stage 1 — Restricted Policy Semantics

Before formal methods are useful, the policy language must be deliberately constrained.

Recommended first-class fields:

- action type
- asset class
- evidence count and provenance
- confidence band
- action scope
- reversibility
- mission criticality
- data classification
- enclave
- approval status
- protected recovery status

Avoid arbitrary embedded code in policy rules.

## Stage 2 — Exhaustive Finite-Domain Testing

Enumerate finite combinations of policy inputs and verify expected outcomes.

Target properties:

- forbidden actions are never approved;
- missing approval cannot produce execution;
- protected recovery assets always deny or escalate destructive actions;
- unsigned policy bundles cannot load;
- malformed input fails closed;
- conflicting rules cannot silently select the less restrictive result.

**Feasibility:** high for the prototype.

## Stage 3 — Property-Based Testing

Use a property-testing framework to generate large numbers of proposed actions and contexts.

Candidate properties:

- increasing scope cannot convert a denial into approval without an explicit policy path;
- lower-quality evidence cannot produce a more permissive decision;
- any action affecting recovery infrastructure requires the strongest configured authorization path;
- every approved action produces a deterministic reason code;
- every execution request must reference a valid, current authorization decision.

**Feasibility:** high.

## Stage 4 — SMT-Based Policy Analysis

Translate policy constraints into formulas and use an SMT solver to check:

- contradictory rules;
- unreachable rules;
- invariant violations;
- bypass paths;
- existence of any context that authorizes a forbidden action;
- approval paths that omit required human gates.

Example question:

> Does there exist any valid context in which `delete_backup` is approved without dual authorization?

**Feasibility:** moderate if policy semantics remain restricted.

## Stage 5 — Architecture Model Checking

Model the authorization workflow with a tool such as TLA+, Alloy, or an equivalent formalism.

Candidate temporal properties:

- no execution occurs before authorization;
- denied actions never reach Enforcement;
- every execution eventually generates an external audit record;
- policy changes cannot become active without required signatures;
- stale authorization decisions expire;
- recovery assets remain available after any permitted containment sequence represented in the model.

**Feasibility:** moderate for an abstract model.

## Stage 6 — Higher-Assurance Implementation

Only after policy semantics stabilize should the project consider a higher-assurance Guardian implementation using a memory-safe or verification-oriented language.

Possible options include Rust, SPARK/Ada, Dafny, F*, or another environment selected with a qualified formal-methods reviewer.

**Feasibility now:** low.

## Assurance Claims by Stage

| Stage | Permitted claim |
|---|---|
| Current | Tested deterministic simulator |
| Exhaustive/property testing | Broadly tested within a defined finite input model |
| SMT analysis | Rule set checked for specified logical conflicts and invariant violations |
| Model checking | Abstract workflow satisfies specified temporal properties |
| Verified implementation | Only claim properties actually proved against the implemented artifact |

Formal verification must never be claimed merely because the Guardian is deterministic.