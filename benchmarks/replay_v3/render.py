# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Render frozen-oracle observations; never infer or change expected labels."""
import json


def metric(value):
    if value is None or not value.get("denominator") or value.get("rate") is None:
        return "N/A" if value is None else f"{value['numerator']}/{value['denominator']} (N/A)"
    lo, hi = value["wilson_95"]
    answer = f"{value['numerator']}/{value['denominator']} [{lo:.2%}, {hi:.2%}]"
    if "rule_of_three_upper_95" in value:
        answer += f"; 3/N ≤ {value['rule_of_three_upper_95']:.2%}"
    return answer


def text(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(r):
    status = "PASS" if r["exit_code"] == 0 else "INVALID MEASUREMENT" if r["exit_code"] == 2 else "FAIL"
    failures = r["failures"]
    lines = ["# replay_v3 held-out evaluation", "",
        f"**{status}: {len(failures)} CERBERUS failure(s); no production fix applied.**", ""]
    if failures:
        lines += ["## Failures first", "",
            "Every entry retains its precommitted expected label. No oracle was reclassified after observation.", "",
            "| Attempt | Expected | Observed | Failing layer | Observed behavior |", "|---|---|---|---|---|"]
        for f in failures:
            lines.append(f"| `{f['id']}` | {f['expected']} | {f['observed']} | {f['failing_layer']} | {text(f['reason'])} |")
        for f in failures:
            b = f["basis"]
            lines += ["", f"### `{f['id']}`", "",
                f"Expected **{f['expected']}** under [{b['document']}](../../{b['document']}), **{b['section']}**: {b['rule']}", "",
                f"Observed **{f['observed']}**; raw Guardian **{f['guardian_decision']}**; failing layer **{f['failing_layer']}**. {f['reason']}.", "",
                f"Violations: {', '.join(f['violations']) or 'none'}; valid measurement: {f['measurement_valid']}."]
    else:
        lines += ["No scored CERBERUS mismatch, unsafe authorization, false denial or invariant violation was observed on these fixtures.", ""]
    lines += ["", "[v1 **FAIL**](../replay_v1/report.md) · [v2 **PASS — same development corpus**](../replay_v2/report.md) · "
        "[machine-readable results](results.json) · [raw latency samples](latency_samples.jsonl) · [complete frozen-recipe corpus](corpus.jsonl.gz)", "",
        f"Seed **{r['seed']}**, clock **{r['clock']}**. **{r['episodes']} episodes / {r['requests']} primary attempts**. "
        f"Eight families: A–G are 300 newly generated cases; H is 3,240 source-derived mutations. **{len(r['doc_ambiguous'])} attempts are doc-ambiguous and excluded from all scored denominators.**", "",
        "A held-out challenge evaluation measures the unchanged v2 snapshot. H reuses source inputs, and several primitive replay/binding controls overlap earlier probes; new compositions, ordering, clock boundaries and field sweeps provide additional challenge coverage. "
        "Do not describe all 3,540 episodes as independent unseen attack mechanisms or use their pooled percentage as a field/generalization estimate.", "",
        "## Reproduce offline", "", "```bash", "python benchmarks/replay_v3/run.py", "```", "",
        "Use a Git checkout with history and the repository runtime dependencies already installed. No downloads occur. "
        "Exit 0 means all scored gates pass, 1 means measured CERBERUS failure, 2 means invalid measurement. "
        "The unchanged historical files are never written. A rerun overwrites only v3 output; use `--output-dir /tmp/replay-v3` for an alternate output location.", "",
        f"Oracle SHA-256: `{r['oracle_sha256']}`. Materialized corpus SHA-256: `{r['corpus_sha256']}`.", "",
        "## Preservation and chronology", "", "```text"]
    h = r["source_preservation"]["history"]
    lines += [f"{name}: {commit or 'not introduced yet at measurement time'}" for name, commit in h.items()]
    lines += ["```", "", "Plan, oracle/hash and implementation are separate ancestor commits; result introduction is checked on reruns and by the standalone verifier. "
        "Results recorded during the first run necessarily predate their own result commit; consult `verify_history.py` after publication for that final commit.", "",
        f"All **{r['source_preservation']['protected_paths']} pre-existing paths except the README** match their precommitted SHA-256 values. "
        "Guardian, Kernel/gateway, token/registry, both policy copies, schemas and every v1/v2 artifact are byte-identical to the v2 base.", "",
        "```text", "git diff --stat 2b4d992fb0ef05ed7b95950d14e4195c1e440ac7 -- <all protected paths>",
        r["source_preservation"]["protected_diff_stat"] or "(empty: 0 files changed)", "```", "",
        "Guardian source changes: **0**. No v2 policy reasoning or expected labels changed. "
        "Raw Guardian diagnostics on new inputs are preserved, not compared to unrelated v2 input verdicts.", "",
        "## CERBERUS exact decisions", "",
        "Each proportion is numerator/denominator with a **95% Wilson interval**. For 0/N the approximate rule-of-three upper bound is also shown. "
        "N/A means no eligible denominator. Primary sequence attempts, not latency repetitions, are the denominator. "
        "Correlated episode steps and mutations violate an independent-random-sample interpretation; intervals are descriptive of this fixed synthetic set.", "",
        "| Family | Scored attempts | Excluded ambiguous | Accuracy [95%] | False allows / nonapprove [95%] | False denies / legitimate [95%] |",
        "|---|---:|---:|---|---|---|"]
    groups = [(k, r["per_class"][k]) for k in "ABCDEFGH"]+[("A–G only", r["novel_A_G"]), ("Overall", r["overall"])]
    for name, group in groups:
        m = group["cerberus"]
        lines.append(f"| {name} | {m['requests']} | {m['doc_ambiguous_excluded']} | {metric(m['accuracy'])} | {metric(m['false_allow'])} | {metric(m['false_deny'])} |")
    lines += ["", "| Family | Escalation precision [95%] | Escalation recall [95%] | Violations / affected attempts | Kernel refusals on expected blocks [95%] | All refusals | State mutations total / out-of-scope |", "|---|---|---|---|---|---:|---|"]
    for name, group in groups:
        m = group["cerberus"]
        s = m["simulator_state"]
        lines.append(f"| {name} | {metric(m['escalation_correctness'])} | {metric(m['escalation_recall'])} | {m['safety_invariant_violations']} / {m['cases_with_violations']} | {metric(m['kernel_refusal'])} | {m['kernel_refusals_all']} | {s['total']} / {s['out_of_scope']} |")
    lines += ["", "False denies include escalations on approve-labelled requests. Exact-decision accuracy also distinguishes deny from escalate. "
        "For presented-grant episodes the tested submission carries original authority, not freshly minted replacement authority. "
        "Raw Guardian re-authorization diagnostics are retained separately; denying re-authorization does not revoke an existing token. "
        "For fresh/advisory paths an unresolved escalation is preserved as escalate. Primary expected-block Kernel probes use the original v1/v2 scoring definition.", "",
        f"Isolated setup controls: **{r['setup_control_mutations']}** exact receipt/audit controls, excluded from primary mutation totals. "
        "Every accepted primary receipt updates a separate symbolic resource map before grading, including a write counter so repeated accepted attempts remain observable. "
        "Effect scope is checked against the issued request digest, target/action/scope, deadline, delivered revocation and consumed-claim observations; expected labels never gate mutation. "
        "Before/after maps and every changed key are in `observations[*].systems.cerberus.simulator_state`.", "",
        "## Unchanged baselines", "",
        "These call the original `v1.baseline` and `v2.b2` directly. Confidence threshold remains 0.9. "
        "Baselines are simplified, decision-only comparators; Kernel refusal/state metrics are N/A and are never imputed as zero. "
        "Their individual mismatches remain in `baseline_failures` in results.json.", "",
        "| Family | Baseline | Accuracy [95%] | False allows [95%] | False denies [95%] | Escalation precision / recall [95%] | Violations |",
        "|---|---|---|---|---|---|---:|"]
    for name, group in groups:
        for system in ("allow_if_recommended", "confidence_threshold", "soar_b2"):
            m = group[system]
            lines.append(f"| {name} | {system} | {metric(m['accuracy'])} | {metric(m['false_allow'])} | {metric(m['false_deny'])} | {metric(m['escalation_correctness'])} / {metric(m['escalation_recall'])} | {m['safety_invariant_violations']} |")
    lines += ["", "## Latency", "",
        "Fixed protocol: **5 warmup + 20 measured repetitions per primary attempt**; restore a fresh registry/replay world and its exact sequence prefix before each sample. "
        "Only enforcement is timed, including refusals and receipt/audit work. Issuance, evidence signing, construction, fault setup and state grading are outside the timer. "
        "Constructor refusals have no enforcement call and are explicitly excluded/N/A. Commit-hook worker creation is included on synchronized contention paths. "
        "Per-attempt percentiles and all raw samples are retained; these are same-host observed timings, not guarantees.", "",
        "| Family | Samples | p50 (ms) | p95 (ms) | max (ms) | Constructor refusals with no call |", "|---|---:|---:|---:|---:|---:|"]
    for name, stats in r["latency"]["aggregates"].items():
        p = stats["latency"]
        values = [f"{p[k]/1e6:.4f}" if p else "N/A" for k in ("p50_ns", "p95_ns", "max_ns")]
        lines.append(f"| {name} | {stats['samples']} | {' | '.join(values)} | {stats['construction_refusals_no_enforcement_call']} |")
    lines += ["", "```json", json.dumps(r["latency"]["hardware"], indent=2), "```", "",
        "Dependency versions are disclosed above. The existing local cryptography/jsonschema installations differ from requirements.txt pins if shown; "
        "no claim of an identical dependency environment to v2 is made. Application source and policy bytes are unchanged.", "",
        "## Documentary ambiguities (excluded, never guessed)", "",
        "| Attempt | Probe | Observed pipeline / Guardian | Documentary gap |", "|---|---|---|---|"]
    for row in r["doc_ambiguous"]:
        b = row["basis"]
        obs = row["systems"]["cerberus"]
        lines.append(f"| `{row['id']}` | {row['variant']} | {obs['decision']} / {obs['guardian_decision']} | {text(b.get('ambiguity', b['rule']))} ({b['document']}, {b['section']}) |")
    lines += ["", "Optional-field coverage is limited by the checked-in schema: every current envelope field is required and unknown metadata is forbidden. "
        "Omitting a required field is separately tested as a schema refusal. No maximum string length is invented where the schema has none; long-but-schema-valid identifiers and both digest-length boundaries are exercised.", "",
        "## Additional coverage and limits", "",
        "| Family | Challenge relative to v1/v2 |", "|---|---|",
        "| A | Multiple simultaneous context, freshness and revocation faults; conflict plus missing corroboration |",
        "| B | Shared state across failed/accepted/revoked attempts; audit failure after claim; exact replay retained as an overlapping primitive control |",
        "| C | Synchronized revocation/receipt ordering, overlapping duplicates and reordered sequences; named linearizations only |",
        "| D | Microsecond expiry/age/skew edges and explicitly ambiguous clock rollback |",
        "| E | All 24 declared field paths, arrays and optional/unknown context, opaque identifier Unicode/case/encoding and equivalent JSON controls; some scalar primitives overlap earlier probes |",
        "| F | Registry/replay availability/corruption/loss and schema-valid boundary inputs |",
        "| G | Legitimate approval, exact scope/independence/confidence boundaries, near-expiry and canonical-equivalence controls |",
        "| H | All 135 v2 source requests x 24 single-field mutations, using this oracle's documentary rule rather than v2 outcomes; correlated/source-derived |", "",
        r["limits"], "", "The live registry is trusted and process-local, not durable/distributed. Correct controller provisioning and event delivery remain assumptions. "
        "Compromised trusted producers are outside scope: signatures authenticate configured origin, not observation truth. "
        "There is no field false-positive estimate, independent external label adjudication, real containment/recovery or production security claim.", "",
        "Oracle corrections after measurement: **none**. Every failure remains scored under its original documentary basis.", ""]
    return "\n".join(lines)
