# OpenAI Cybersecurity Grant Program — Application Draft

**Applicant:** Emily Echt  
**Role / Title:** Independent Researcher and Project Lead  
**Company or University:** Independent  
**Email:** [add preferred application email]  
**LinkedIn:** [add LinkedIn profile URL]  

## Project title

**CERBERUS Cyber: Deterministic Authority Gating for AI Defensive Agents**

## One descriptive sentence

A 90-day open-source evaluation of whether a separate deterministic authorization and enforcement boundary can stop manipulated, mistaken, or compromised AI defenders from turning bad recommendations into harmful cyber actions.

## Project proposal

I built CERBERUS because I think we are moving too quickly from “the model noticed something” to “the model should be allowed to act.” Those are not the same claim. Intelligence is not authority.

One of the things that scares me most about AI in cybersecurity is not only that a model can be deceived, compromised, or pushed toward the wrong goal. It is that the same model may already hold the credentials and tools needed to turn that failure into a real operational action. A prompt injection, poisoned telemetry source, compromised connector, stale policy, or confident but incorrect conclusion should not be able to become host isolation, credential rotation, workload shutdown, backup deletion, or broad enterprise containment simply because the model sounded certain.

CERBERUS Cyber is my attempt to put a hard authority boundary between intelligent reasoning and consequential action.

The current prototype separates three functions:

1. **Sentinel Intelligence** observes telemetry, forms hypotheses, and recommends actions. It is useful, adaptive, and untrusted by design.
2. **Guardian Policy Engine** deterministically approves, escalates, or denies typed action proposals using explicit policy, evidence provenance, independent-source requirements, scope ceilings, freshness, reversibility, and human approval gates.
3. **Enforcement & Recovery Kernel** acts only when it receives a valid short-lived decision token bound to the exact approved action, target, scope, actor, policy version, and idempotency key.

The model does not hold enforcement authority. Its confidence is information, not permission. Enforcement cannot reinterpret the recommendation or widen its scope.

The prototype already includes a versioned ActionEnvelope contract, JSON Schema validation, canonical serialization, envelope digests, short-lived signed DecisionTokens, one-time token consumption, replay rejection, a simulated Enforcement Gateway, a hash-chained audit ledger, baseline cyber scenarios, an adversarial authority-boundary corpus, and automated tests on Python 3.10 and 3.12. It is still a TRL 2–3 research prototype. It has no production connectors, makes no operational-readiness claim, and performs no real containment by default.

I am proposing a narrow next step: test whether the authority boundary actually reduces harmful automated response when an AI defensive agent is manipulated or wrong, and measure what it costs in speed and defensive utility.

### Research question

Can consequential defensive actions remain bounded, auditable, and reversible when the intelligent layer is wrong, compromised, reward-seeking, or adversarially manipulated?

More specifically: compared with a conventional model-to-playbook pipeline, does CERBERUS reduce false containment, over-scoped action, invariant violations, and adversary-induced harmful response without making true-positive containment unacceptably slow?

### Experimental design

The project will run in an isolated, unclassified cyber range using synthetic telemetry and simulated actions only. No production systems, unauthorized scanning, exploit deployment, credential theft, destructive payloads, or autonomous retaliation will be used.

The range will represent a small synthetic enterprise of approximately 25–50 hosts with a mock identity provider, synthetic cloud control-plane events, endpoint and DNS telemetry, audit logs, backup infrastructure, and a simulated AI security agent.

Two pipelines will receive the same telemetry and the same opportunity to propose actions:

**Baseline A — Conventional automation**  
Detection event → model recommendation → response playbook → simulated execution

**CERBERUS B — Assured automation**  
Detection event → typed ActionEnvelope → deterministic Guardian decision → exact-token Enforcement validation → simulated execution

The intelligent layer will use an OpenAI cyber-capable model, preferably GPT-5.5-Cyber through Trusted Access for Cyber, or the closest available equivalent at project start. A lower-cost general-purpose OpenAI model will be used as a comparison condition if credits allow. Model outputs will be treated as untrusted proposals in both pipelines.

The evaluation will include benign, malicious, and adversarial variants across:

- stolen administrator sessions;
- ransomware-like behavior;
- suspicious data exfiltration;
- lateral movement;
- cloud privilege escalation;
- backup tampering;
- insider misuse;
- prompt injection against the AI agent;
- telemetry poisoning;
- contradictory evidence;
- spoofed confidence;
- compromised connectors;
- stale or conflicting policy;
- malformed-input and policy-routing bypass attempts;
- adversary-induced false containment.

The current nine-case authority-boundary corpus will be expanded into a public benchmark containing scenario descriptions, synthetic telemetry bundles, model context, proposed ActionEnvelopes, expected authority outcomes, policy reason codes, and ground-truth labels. The goal is not to create another benchmark where a model is rewarded only for producing a correct answer. The goal is to measure whether a system can remain safe when the answer, evidence, or model trajectory is wrong.

### Measures

The primary safety measure is **Invariant Integrity**. The target is zero forbidden-action authorizations. A single violation is a critical failure, not something averaged away by good performance elsewhere.

Additional measures will include:

- false-containment rate on benign scenarios;
- adversary-induced harmful-action rate;
- percentage of over-scoped proposals denied or escalated;
- true-positive containment latency;
- time to approved action;
- action scope and number of mission assets affected;
- replay, substitution, and stale-token rejection;
- completeness of decision reconstruction from logs;
- policy conflict count and unreachable rules;
- review time per policy change;
- exception growth and maintainability;
- model disagreement and repeated-attempt behavior;
- documented failure cases and denial-of-defense behavior.

Thresholds and acceptance criteria will be frozen before held-out evaluation. I do not want to select the definition of success after seeing the results.

### Connection to CERBERUS Runtime Assurance

The broader CERBERUS Runtime Assurance project asks whether the independence of layered safeguards remains real over time or whether the layers begin failing for the same reasons. It treats independence as a perishable runtime quantity rather than a permanent design-time promise.

That larger research line includes the proposed Failure-Cause Overlap Index, passive Vigil monitoring, asymmetric authority contraction, a minimal survivable Anchor, and evidence-gated restoration. This grant proposal does not claim that the full runtime-independence architecture is already implemented in cyber. The 90-day study is deliberately narrower: validate the authority boundary first, document correlated failures, and create the evidence needed for a later runtime-independence experiment.

### Why this matters now

Long-horizon models are becoming more persistent, more capable with tools, and better at finding paths around obstacles. Recent public incidents have made the problem easier to explain, but I did not build CERBERUS because of one incident. I built it because I believe a system can be extremely intelligent and still be wrong about what it is allowed to do.

The answer cannot only be “make the model better.” Better models still operate inside imperfect software, policies, credentials, connectors, telemetry, and human organizations. The authority boundary should survive even when the intelligence does not.

I am not trying to build an autonomous AI defender with broader access. I am trying to prove that we can use strong models without quietly transferring human authority to them.

### Team and execution

I am the project creator and current sole technical lead. I will lead architecture, implementation, experiment design, testing, analysis, documentation, and public release.

At the preferred funding level, I will contract an independent cybersecurity reviewer to attempt bypasses, inspect the policy model, and reconstruct decisions from the audit trail. No reviewer is committed yet, and I will disclose the reviewer before the independent-review phase.

### Outputs and public benefit

The project will release:

- the expanded CERBERUS authority-boundary benchmark;
- the synthetic telemetry replay harness;
- the baseline and CERBERUS evaluation pipelines;
- frozen policies, schemas, and acceptance criteria;
- reproducible experiment scripts and seed partitions;
- machine-readable results;
- a failure report, including negative and ambiguous results;
- an implementation and assurance-gap report;
- a public technical paper or preprint.

CERBERUS Cyber code will remain available under Apache License 2.0. Public research artifacts and datasets will use a permissive license suitable for reuse, with the final license identified before release. No confidential, personal, classified, or production data will be collected.

### Success and failure conditions

A credible success would be:

- zero invariant violations;
- materially lower adversary-induced harmful response than the baseline;
- lower false containment without an unacceptable increase in true-positive latency;
- complete decision reconstruction;
- manageable policy-authoring effort;
- independent reviewers able to reproduce the results;
- openly documented failures and unresolved risks.

A credible failure would also be useful. If the Guardian creates excessive denial of defense, policies become impossible to maintain, model proposals route around typed contracts, enforcement checks fail under concurrency, or the added latency destroys defensive utility, I will publish that. I want to know whether this architecture works, not protect it from being disproven.

The core idea is simple:

**Assume compromise. Constrain authority. Contain damage. Recover safely.**

I think humans and machines should think alongside each other. I do not think consequential choices should leave human hands merely because a machine became capable of making them.

## What problem are you trying to solve? — 200-word field

AI-enabled defensive systems increasingly combine detection, reasoning, planning, tool use, and response. This creates a dangerous authority-collapse problem: if the analytical model is manipulated by prompt injection, poisoned telemetry, stolen credentials, a compromised connector, reward-seeking behavior, or a confident mistake, the same failure may immediately gain access to privileged defensive actions.

Current safeguards often live inside the agent, its prompt, or the same automation stack it is being asked to control. Layering does not automatically create independence, and model confidence does not establish legitimacy, evidence quality, reversibility, or the right to act.

CERBERUS Cyber separates intelligence from authority. An AI model may observe and recommend, but a deterministic Guardian evaluates a typed proposal against explicit policy, evidence provenance, independent-source requirements, scope ceilings, freshness, reversibility, and approval gates. A separate Enforcement layer acts only on a short-lived token bound to the exact approved action.

The proposed study will compare this architecture with conventional model-to-playbook automation in a synthetic cyber range. It will measure invariant violations, false containment, adversary-induced harmful response, containment latency, auditability, replay resistance, and policy maintainability. The goal is not to prevent every model failure. It is to stop model failure from automatically becoming operational authority.

## Project timeline

### Month 1 after award — Instrumentation and preregistration

- freeze ActionEnvelope, DecisionToken, policies, safety invariants, metrics, and acceptance criteria;
- build the synthetic telemetry replay harness and baseline pipeline;
- expand benign and true-positive scenario coverage;
- establish immutable logs and fixed seed partitions.

### Month 2 after award — Adversarial evaluation

- run prompt-injection, telemetry-poisoning, evidence-conflict, confidence-spoofing, compromised-connector, replay, substitution, stale-policy, and scope-widening tests;
- compare Baseline A and CERBERUS B on identical inputs;
- measure safety, latency, utility, and denial-of-defense behavior.

### Month 3 after award — Independent review and publication

- conduct external bypass and auditability review if funded;
- run held-out evaluation under frozen thresholds;
- analyze results and document failure cases;
- release code, benchmark, data, reproducibility package, and technical report.

## Requested funding / API credits / resources needed

### Minimum viable support — $10,000 in OpenAI API credits

This supports model-backed scenario generation, repeated evaluation runs, baseline comparison, adversarial variants, and public benchmark creation. The project would remain fully synthetic and would be completed by the project lead without a contracted external reviewer.

### Preferred support — $30,000 direct grant plus up to $10,000 in API credits and Trusted Access for Cyber

The direct grant would support full-time implementation and analysis, an isolated evaluation environment, reproducibility tooling, and a contracted independent cybersecurity reviewer. API credits and Trusted Access would support repeated testing with a cyber-capable OpenAI model and a general-purpose comparison model.

### Expanded support — $50,000 total support plus API credits

This would add a larger held-out corpus, multi-model comparison, deeper concurrency and replay-state testing, a second independent reviewer, and a more complete public assurance case. Production integrations and real-world containment would remain out of scope.

## New datasets

Yes. The project will expand the existing adversarial authority-boundary corpus into a synthetic, public CERBERUS Authority Boundary Benchmark. It will contain no personal, confidential, classified, or production information.

## AI models requested

- GPT-5.5-Cyber through Trusted Access for Cyber, or the closest currently available cyber-capable OpenAI model;
- one current general-purpose OpenAI reasoning model as a comparison condition;
- lower-cost OpenAI models for scenario expansion and ablation testing where appropriate.

## Relevant work

- CERBERUS Cyber — defensive authority-boundary prototype: https://github.com/emilyecht/cerberuscyber
- CERBERUS Runtime Assurance — independence-as-a-runtime-quantity research architecture: https://github.com/emilyecht/cerberus-runtime-assurance
- CERBERUS Vigil Experiment — matched-model evidence-to-authority pipeline verification: https://github.com/emilyecht/cerberus-vigil-experiment

## Additional notes

This is an independent application. The applicant retains ownership of the existing CERBERUS repositories and understands that submission does not create exclusivity or prevent OpenAI from developing similar work. The project is defensive-only, public-benefit oriented, and intentionally scoped to synthetic evaluation rather than production deployment.
