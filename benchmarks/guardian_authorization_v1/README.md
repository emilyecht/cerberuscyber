# Guardian Authorization Benchmark v1

This diagnostic measures whether explicit unsafe requests receive usable signed authority, whether eligible responses still work, and whether token and idempotency boundaries survive reuse. It evaluates the **raw ActionEnvelope boundary and simulated enforcement**, not live threat detection or containment.

The 59 cases and their expected outcomes are fixed in `cases.json`. The oracle does not call Guardian or derive expected answers from its loaded policies. It is project-authored, uses knowledge of known weaknesses, and has not received independent review. There is no held-out-test claim.

For the complete inputs behind the comparison, open the [reviewer evidence packet](../../results/guardian_authorization_v1/reviewer_packet/README.md). It expands all 33 unsafe requests and 8 eligible controls, preserves external test facts, and provides one-command replay with an exact comparison to the recorded observations.

## Scope and denominators

| Population | Cases | Measurement |
|---|---:|---|
| Unsafe native requests | 33 | Valid signed tokens issued when the oracle requires authority to be withheld |
| Eligible requests | 8 | Exact action/target/scope token plus a matching side-effect-free receipt |
| Review controls | 4 | Expected escalation without signed authority |
| Benign request controls | 4 | Authorization/disruption proxy and review burden |
| Gateway binding and replay probes | 8 | Acceptance of an unauthorized or duplicate simulated action after a valid setup |
| Guardian idempotency probes | 2 | Duplicate simulated action after envelope re-evaluation |

Requests and expected outcomes are authored before execution. Every case has an ID, threat family, requirement basis, purpose, and explicit outcome. Sources and approval labels in positive controls have a **trusted-upstream precondition**; the prototype does not authenticate them. Negative authenticity cases remove that precondition. They expose the limits of accepting raw attacker-controlled envelopes; they do not demonstrate a bypass of an independently authenticated deployed integration.

`existing_contract` cases check documented action, scope, input, policy, signing, and instance-local replay requirements. `extended_assurance` cases assess additional security requirements: authenticated independent evidence/approvals, evidence age of at most 60 seconds with at most 5 seconds of forward skew, and state that survives new instances/processes. Those age limits are proposed benchmark settings, not existing policy settings.

## Reproduce the pinned comparison

Use Python 3.10 or 3.12. The policy is version 0.5.0 in both targets. Keep the benchmark source on its own checkout and use two clean target worktrees:

```bash
git worktree add --detach ../cerberus-baseline ac22a922fae1475cbfa9921534222df96cbdf2b5
git worktree add --detach ../cerberus-repaired 651bd4a465661c7c54d58d3c60c279338b727c4f
python -m venv ../cerberus-benchmark-venv
../cerberus-benchmark-venv/bin/python -m pip install -r ../cerberus-repaired/requirements-dev.txt
../cerberus-benchmark-venv/bin/python benchmarks/guardian_authorization_v1/run.py --target ../cerberus-baseline --output results/guardian_authorization_v1/baseline.json
../cerberus-benchmark-venv/bin/python benchmarks/guardian_authorization_v1/run.py --target ../cerberus-repaired --output results/guardian_authorization_v1/repaired.json
```

Run one target per interpreter; module contamination is rejected. The clock, fixtures, and idempotency identifiers are deterministic. Outputs bind the corpus, runner, target production sources, commit, and policy with hashes. Raw per-case outcomes and denominators are retained; token strings are not written into the result files. Random token IDs and audit timestamps are not used as metrics.

Add `--case V01` to investigate one case (the output is marked incomplete). Unknown case IDs fail. The default exit code is 0 for completed measurement, including observed security violations; it is 2 for measurement errors. Add `--fail-on-violation` to return 1 when any expected security outcome fails. An import, runtime, worker, or precondition error cannot count as a successful defense, and affected rates are null.

To render the checked-in graphs and case-level CSV:

```bash
python -m pip install -r benchmarks/guardian_authorization_v1/requirements-plots.txt
python benchmarks/guardian_authorization_v1/render_results.py --results results/guardian_authorization_v1
```

The renderer rejects incomplete results, measurement errors, different policies, or mismatched corpus/runner/input hashes. No confidence intervals are plotted: these hand-selected, dependent diagnostic cases do not support IID population estimates. Test counts and corpus rates are not an overall security score.

## Known limits

- This version bypasses Sentinel's detection pipeline. Benign results are request-level proxies, not operational false-positive rates.
- Every eligible response is simulated; actual enforcement escape, containment latency, rollback success, and real-world damage are unmeasured.
- G08 launches a separate Python process. G07 uses a second gateway instance; it is not a distributed load or concurrency test. L02 tests a new Guardian with default in-memory state.
- No live malware, network scanning, external targets, production credentials, or operational connectors are used.
- No independent evaluator, adaptive red team, representative traffic distribution, formal proof, or production integration is included.
- Once published, these cases are regression material. A future held-out evaluation needs separately authored cases and a frozen configuration.

The next increment should address the measured gaps, then add independent evaluation and isolated-lab post-action verification. Do not revise expected outcomes merely to make existing behavior pass.

## Validation of the instrument

`tests/test_guardian_benchmark.py` checks that denying every request fails eligible controls, allowing every request exposes unsafe authorizations, exceptions and invalid preconditions do not count as defenses, exact receipts are required, inputs are stable, and both checked-in results match the same oracle and policy. CI runs these tests together with the existing suite on Python 3.10 and 3.12.
