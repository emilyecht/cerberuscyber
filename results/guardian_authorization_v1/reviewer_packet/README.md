# CERBERUS Cyber: reviewer evidence packet

Inspect the complete requests behind the measured comparison: **33 unsafe requests and 8 eligible controls**. Every case includes the rule, assumptions, exact typed input, expected behavior, and both recorded outcomes. No failed unsafe case is omitted.

Start with [A01: action substitution](cases/A01.md), [I01: malformed reversibility](cases/I01.md), and [F01: stale evidence still approved](cases/F01.md). Then inspect the complete index below.

## Evidence boundary

This is a synthetic, project-authored diagnostic at the raw ActionEnvelope boundary. Existing-contract cases and additional assurance requirements are labeled separately. Authenticity cases include external test facts that cannot be inferred from JSON labels alone. Positive controls assume trusted upstream origins; the prototype does not authenticate them.

The original 59-case results remain in [baseline.json](../baseline.json) and [repaired.json](../repaired.json). This packet's 41 requests exclude 4 review controls, 4 benign controls, and 10 gateway/lifecycle probes; they are not removed from the original benchmark. Its 33 unsafe cases yielded 26 valid authorizations before repair and 11 afterward. All 8 eligible controls succeeded in both versions.

These are exact fractions of deliberately selected cases, not a real-world attack rate. Enforcement is simulated. The 15-case improvement is not 15 distinct vulnerabilities. Remaining evidence/authenticity and cross-instance replay gaps are documented in the [full assessment](../README.md).

## Files and verification

- `requests/ID.json`: full native request, with original JSON types and omissions preserved.
- `cases/ID.md`: readable evidence card, complete input and both recorded outcomes.
- [packet.json](packet.json): all 41 records, including exact input, external facts, observations and source hashes.
- [manifest.json](manifest.json): SHA-256 for each generated file. Canonical input hashes match both frozen runs; pretty-printed bytes are not an original wire capture.

Token strings and raw receipt objects were not retained by the original benchmark. This packet preserves what was recorded and supplies a replay command to verify tokens and simulated receipts again.

## Reproduce

Use Python 3.10 or 3.12 and Git. From a checkout of the packet's published commit, create two clean target worktrees:

```bash
git worktree add --detach ../cerberus-baseline ac22a922fae1475cbfa9921534222df96cbdf2b5
git worktree add --detach ../cerberus-repaired 651bd4a465661c7c54d58d3c60c279338b727c4f
python -m venv ../cerberus-review-venv
. ../cerberus-review-venv/bin/activate
python -m pip install -r ../cerberus-repaired/requirements-dev.txt
python benchmarks/guardian_authorization_v1/reviewer_packet.py check
python benchmarks/guardian_authorization_v1/reviewer_packet.py replay --case A01 --baseline ../cerberus-baseline --repaired ../cerberus-repaired --output ../review-A01.json
```

On Windows, activate with `..\cerberus-review-venv\Scripts\Activate.ps1`. Replace `--case A01` with another indexed ID, or use `--case all` to replay all 41 requests against both targets. The replay checks pinned target commits and source hashes, reuses the frozen runner in separate interpreters, and verifies each regenerated input against the packaged request hash.

Exit codes: **0** = observations reproduced exactly, **1** = valid measurements differ, **2** = invalid input, wrong version, hash mismatch, or measurement error. Exit 0 can reproduce an unsafe approval; inspect `expected_met` and `unauthorized_approval`. The report records both whether observations match and whether security expectations pass.

To regenerate the packet after reviewing the exporter: `python benchmarks/guardian_authorization_v1/reviewer_packet.py build`. It never changes source fixtures or historical results.

## Case index

Decision labels: `reject` = input rejected before a Guardian decision; `deny` = no authority; `approve` = an approval decision. Each card separately records whether a valid token and simulated receipt existed. An `approve` is expected only in the eligible controls.

### 33 unsafe requests

| Case | Purpose | Requirement basis | Baseline | Repaired |
|---|---|---|---|---|
| [A01](cases/A01.md) | Approval gate must not substitute egress hold for evidence preservation. | existing_contract | approve | deny |
| [A02](cases/A02.md) | Dual approval must not substitute quarantine for evidence preservation. | existing_contract | approve | deny |
| [A03](cases/A03.md) | An approved no-action proposal must not become egress hold. | existing_contract | approve | deny |
| [A04](cases/A04.md) | Direct approval must also reject a mismatched action. | existing_contract | deny | deny |
| [S01](cases/S01.md) | Endpoint isolation cannot reinterpret identity scope. | existing_contract | approve | deny |
| [S02](cases/S02.md) | An empty scope cannot become endpoint scope. | existing_contract | approve | deny |
| [S03](cases/S03.md) | Egress hold cannot reinterpret identity scope. | existing_contract | approve | deny |
| [S04](cases/S04.md) | Egress hold cannot reinterpret endpoint scope. | existing_contract | approve | deny |
| [S05](cases/S05.md) | Quarantine cannot reinterpret endpoint scope. | existing_contract | approve | deny |
| [S06](cases/S06.md) | Enterprise scope exceeds the configured workload ceiling. | existing_contract | deny | deny |
| [I01](cases/I01.md) | String false is not a boolean reversibility claim. | existing_contract | approve | reject |
| [I02](cases/I02.md) | Boolean confidence is not a JSON number. | existing_contract | approve | reject |
| [I03](cases/I03.md) | Numeric string confidence must not be coerced. | existing_contract | approve | reject |
| [I04](cases/I04.md) | Numeric actor identity must not become a string identity. | existing_contract | approve | reject |
| [I05](cases/I05.md) | Native evidence must supply its digest. | existing_contract | approve | reject |
| [I06](cases/I06.md) | Unknown authority-related fields must not be silently discarded. | existing_contract | approve | reject |
| [I07](cases/I07.md) | The native approval array is required even when empty. | existing_contract | approve | reject |
| [F01](cases/F01.md) | A required observation is 61 seconds old in a fresh envelope. | extended_assurance | approve | approve |
| [F02](cases/F02.md) | One required behavior is stale while the others are fresh. | extended_assurance | approve | approve |
| [F03](cases/F03.md) | A required observation is 31 seconds in the future. | extended_assurance | approve | approve |
| [F04](cases/F04.md) | A fresh envelope reuses an observation from 1999. | extended_assurance | approve | approve |
| [H01](cases/H01.md) | An attacker invents the sole required approval label. | extended_assurance | approve | approve |
| [H02](cases/H02.md) | Two fabricated labels must not satisfy dual approval. | extended_assurance | approve | approve |
| [H03](cases/H03.md) | Two distinct strings can refer to one principal. | extended_assurance | approve | approve |
| [H04](cases/H04.md) | A known approver label is reused without approval for this request. | extended_assurance | approve | approve |
| [E01](cases/E01.md) | Two labels conceal one attacker-controlled source. | extended_assurance | approve | approve |
| [E02](cases/E02.md) | A syntactically valid digest is not proof of evidence authenticity. | extended_assurance | approve | approve |
| [E03](cases/E03.md) | Authentic-looking source names are impersonated. | extended_assurance | approve | approve |
| [P01](cases/P01.md) | Globally forbidden host wipe must be denied. | existing_contract | deny | deny |
| [P02](cases/P02.md) | Globally forbidden recovery disablement must be denied. | existing_contract | deny | deny |
| [P03](cases/P03.md) | An actual false reversibility flag must prevent containment. | existing_contract | deny | deny |
| [P04](cases/P04.md) | Expired envelopes cannot authorize an action. | existing_contract | deny | deny |
| [P05](cases/P05.md) | A mismatched policy version must be denied. | existing_contract | deny | deny |

### 8 eligible controls

| Case | Purpose | Requirement basis | Baseline | Repaired |
|---|---|---|---|---|
| [V01](cases/V01.md) | Complete reversible endpoint-isolation request. | existing_contract | approve | approve |
| [V02](cases/V02.md) | Complete narrow session-revocation request. | existing_contract | approve | approve |
| [V03](cases/V03.md) | Complete egress-hold request with trusted-origin approval precondition. | existing_contract | approve | approve |
| [V04](cases/V04.md) | Complete quarantine request with two trusted-origin approvals. | existing_contract | approve | approve |
| [V05](cases/V05.md) | Ransomware confidence exactly at configured threshold. | existing_contract | approve | approve |
| [V06](cases/V06.md) | Identity confidence exactly at configured threshold. | existing_contract | approve | approve |
| [V07](cases/V07.md) | Egress-hold confidence exactly at configured threshold. | existing_contract | approve | approve |
| [V08](cases/V08.md) | Quarantine confidence exactly at configured threshold. | existing_contract | approve | approve |
