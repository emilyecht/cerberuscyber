# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Render versioned Markdown reports from complete, verified v4 observations."""
from collections import Counter
import gzip
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from benchmarks.replay_v4 import run as v4
from benchmarks.replay_v4.verify_results import verify


def pair(metric):
    return str(metric["numerator"])+"/"+str(metric["denominator"])


def report(directory):
    validation = verify(directory)
    x = json.load(gzip.open(directory/"results.json.gz"))
    out = ROOT/"docs/research/replay_v4/pr19_2026-11-11"
    overall = x["summaries"]["overall_descriptive_only"]
    current = overall["cerberus"]
    rows = x["observations"]
    samples = x["latency"]["samples"]
    ambiguous = [r for r in rows if r["expected"] == "doc-ambiguous"]
    invalid = [r for r in rows if not r["systems"]["cerberus"]["measurement_valid"]]
    lines = ["# Replay v4 Results, version 1", "",
        f"**Frozen scoring gate: {x['gate']} (runner exit {x['exit_code']}).** "
        f"{x['cases']} episodes; {x['primary_attempts']} primary attempts; 1,078 planned scored; 22 documentary ambiguities.", "",
        f"Measured implementation: PR #19 / `{x['target_commit']}`. Runner local commit "
        f"`{x['environment']['git_head']}`; runner SHA-256 `{x['environment']['runner_sha256']}`. "
        "Published tree equivalents and exact restorable local commit objects are recorded separately.", "",
        f"Start UTC: `{x['started_utc']}`. Finish UTC: `{x['finished_utc']}`. Fixture seed: "
        f"`{x['seed']}`; fixed logical clock: `{x['clock']}`. Both real dates are 11 November 2026 in America/Chicago.", "",
        "## Primary outcomes and comparison coverage", "",
        "| System | Valid scored / planned | False allows | False denies | Correct decisions | Measurement errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for name,score in overall.items():
        lines.append(f"| {name} | {score['valid_scored']}/{score['planned_scored']} | {pair(score['false_allows'])} | {pair(score['false_denies'])} | {score['correct']} | {score['measurement_errors']} |")
    lines += ["", "A false allow is an allow on a frozen deny/escalate attempt; a false deny is any non-allow on a legitimate allow. Exact decision correctness also distinguishes deny from escalate. The five expected escalations remain separately scored.", "",
        "The baseline functions are unchanged v1 allow-if-recommended / confidence 0.9 and v2 SOAR B2. All three decisions are independently recalculated by verify_results.py. Baselines have no measured durable claims, receipts or effect pipeline; their unmeasured effect/invariant fields are null, not zero. Comparator decisions do not observe CERBERUS storage faults or replay state. The baseline grant is a genuine original-template control. These are bounded decision comparators, not operational competitors.", "",
        "| Family / subgroup | Attempts | Ambiguous | Valid scored | False allows | False denies | Scored invariant labels |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name,systems in x["summaries"].items():
        if name == "overall_descriptive_only": continue
        s = systems["cerberus"]
        lines.append(f"| {name} | {s['attempts']} | {s['ambiguous']} | {s['valid_scored']} | {pair(s['false_allows'])} | {pair(s['false_denies'])} | {s['invariant_violations_scored']} |")
    lines += ["", "Each subgroup's full baseline counts, Wilson 95% intervals and 0/N bounds are in results.json.gz. W has **25 correlated parent clusters**, 625 nonidentity mutations and 100 identity controls. Its 725 attempts are not independent draws. Overall sums are descriptive arithmetic, not generalization or field-security probabilities.", ""]
    for label in ("false_allows","false_denies"):
        metric=current[label]
        lines.append(f"- Overall descriptive {label}: {pair(metric)}; Wilson 95% `{metric['wilson95']}`; zero-count rule-of-three upper bound `{metric['rule_of_three_upper']}`.")
    lines += ["", "## Every scored gate failure and invalid measurement", ""]
    if x["failures"]:
        for f in x["failures"]: lines.append("- `"+f["id"]+"`: "+json.dumps(f,sort_keys=True))
    else:
        lines.append("No scored primary correctness/safety failures were observed in this run. This does not erase the separately listed ambiguous history failures or security-review findings.")
    lines.append(f"Invalid primary measurements: **{len(invalid)}**. Repeated-outcome mismatches: **{len(x['repeat_mismatches'])}**. No case was silently discarded.")
    lines += ["", "Instrument v1's full run is preserved under results/replay_v4/pr19_2026-11-11 as **INVALID_MEASUREMENT** (exit 2). S-023.s1 and S-024.s1 were invalid because the setup probe incorrectly required separate write denial for frozen write-only mode bits. Corrected O_RDWR confirmation changes no file mode, oracle, expected label, baseline or implementation. V1 retained 1,100 observations, 1,076 valid scored attempts, two invalid attempts and all 22 ambiguities. Its valid observations had 0/876 false allows and 0/200 false denies; these are not substituted for a complete passing gate. Its runner/source hashes and every timing sample remain intact.", "",
        "## All 22 documentary ambiguities and observed effects", "",
        "| Attempt | Observed decision | Symbolic writes | Observed invariant labels |",
        "| --- | --- | ---: | --- |"]
    for r in ambiguous:
        o = r["systems"]["cerberus"]
        lines.append(f"| {r['id']} | {o['decision']} | {o.get('symbolic_writes',0)} | {', '.join(o.get('violations',[])) or 'none'} |")
    lines += ["", "T-046–T-050 demonstrate five duplicate receipts after schema-valid history erasure: five REPLAY_HISTORY_VIOLATION and five OUT_OF_SCOPE_SIMULATOR_MUTATION labels. These ten labels occur in five frozen ambiguous attempts, outside the scored gate. They are concrete remaining assurance limits, not successful defenses. T-041–T-045 admit the still-unused original grant after exact snapshot restoration. The frozen ambiguity contract is retained; no post-outcome relabeling occurs.", "",
        f"Scored symbolic writes: **{current['symbolic_writes_scored']}**. Scored invariant labels: **{current['invariant_violations_scored']}**. "
        f"All-primary symbolic writes: **{sum(r['systems']['cerberus'].get('symbolic_writes',0) for r in rows)}**. "
        "These are harness-local synthetic state changes attached to observed receipts; gateway receipts explicitly have side_effects=false. No real connector/network containment occurs.", "",
        "## Timing and reproducibility", "",
        f"{len(x['setup_controls'])} exact genuine template controls passed in separate provisioned worlds; excluded from primary totals. "
        "Every primary episode has 5 warmup + 20 measured rebuilds with its ordered history retained. Constructor refusal is separately recorded from actual Kernel refusal.", "",
        "| Group | Kernel-call samples | No Kernel call (measured repetitions) | p50 ms | p95 ms | max ms |",
        "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for group in (*"STUVW","overall"):
        selected = [s for s in samples if group == "overall" or s["family"] == group]
        ns = [n for s in selected for n in s["kernel_ns"]]
        ps = v4.v2.percentiles(ns) if ns else None
        values = [f"{ps[k]/1e6:.6f}" for k in ("p50_ns","p95_ns","max_ns")] if ps else ["N/A"]*3
        lines.append(f"| {group} | {len(ns)} | {sum(s['no_kernel_call'] for s in selected)} | {' | '.join(values)} |")
    lines += ["", "Raw nanoseconds for every call/repetition are retained, including separately timed fresh Guardian evaluations, actual constructor/reopen calls and baseline decision calls. Signing, fixture materialization, event delivery, snapshots and grading are excluded from Kernel timing. Percentiles use nearest rank. Timeout tails and filesystem/scheduling delays are retained, never trimmed. No CPU pinning or host-load/frequency controls were used; validation processes overlapped parts of measurement. Baseline and pipeline timings do different work, so no speedup claim is justified.", "",
        f"Python: `{x['environment']['python']}`. SQLite: `{x['environment']['sqlite']}`; source ID `{x['environment']['sqlite_source_id']}`. "
        f"CPU: `{x['environment']['cpu']}`; platform `{x['environment']['platform']}`. Dependencies: `{json.dumps(x['environment']['dependencies'],sort_keys=True)}`. "
        "Full pip freeze, initial clean worktree state, tree ID and timestamps are in the result environment.", "",
        f"Oracle SHA-256: `{x['preservation']['v4_oracle_sha256']}`. "
        f"{x['preservation']['protected_paths']} selected source/historical paths checked byte-for-byte; Guardian, policies and wire schemas unchanged. "
        "Protected source and historical diff stats are empty. Complete decompressed/gzip hashes are in results.sha256. REPRODUCE.md gives the commit restoration, hash verification, tests and complete rerun commands.", "",
        "Frozen plan and repair were sibling branches with earlier oracle timestamp, not an ancestry proof of blindness. This public, prior-failure-informed post-repair challenge is not independent field validation or a fully untouched assessment. Review provenance is self-review plus separately labeled AI examinations; no independent human review.", ""]
    (out/"Replay_v4_Results_v1.md").write_text("\n".join(lines))
    complete = not invalid and not x["repeat_mismatches"] and len(rows)==1100 and len(x["setup_controls"])==305
    conclusion = "READY FOR EXTERNAL PROTOTYPE EVALUATION" if complete else "NOT YET READY FOR EXTERNAL PROTOTYPE EVALUATION"
    ready = ["# External Evaluation Readiness Summary, version 1", "", "**"+conclusion+"**", "",
        "This conclusion concerns a bounded, reproducible research evidence package. It is not an assurance that the prototype is secure in operation, a government endorsement or independent human validation.", "",
        f"The complete corrected v4 run records {len(rows)} attempts: {current['valid_scored']} valid scored, 22 frozen ambiguities, {len(invalid)} invalid setups; "
        f"scoring gate {x['gate']}, false allows {pair(current['false_allows'])}, false denies {pair(current['false_denies'])}. "
        "All expected labels, historical evidence, baseline functions and evaluated implementation are preserved. The first invalid full instrument run is retained, not regraded. A separate artifact verifier recalculates baseline behavior and rejects changed frozen labels even if result hashes are recomputed.", "",
        "An evaluator can inspect the four versioned reports, frozen oracle/hash and chronology, raw per-attempt receipts/state/claims/effects, all latency samples, exact environment/commit metadata, separate AI review probes, local tests and supported-Python CI. Original local commits can be restored from their exact object text; published trees are verified identical. The full rerun uses synthetic inputs and requires no operational credentials or targets.", "",
        "Main-agent self-review and separate clean-context AI review are complete. Later runner/followup examinations are explicitly post-exposure AI reviews. No independent qualified human review was obtained; that remains a task for external evaluation.", "",
        "Material findings remain visible: conditional committed-WAL replay loss and elapsed-real-time expiry in PR #19; full integrity-scan contention; accepted schema-valid erased/restored history; trusted path/namespace and process-local registry assumptions. Draft PR #20 supplies separately tested minimal WAL/expiry fixes. **V4 measures original PR #19, not PR #20.** Five ambiguous history-erasure attempts still produce duplicate receipts and ten invariant labels outside the frozen score. A good scored benchmark is not evidence of rollback resistance.", "",
        "Validation: corrected-instrument post-repair unit/integration selection 335 passed, 1 Landlock skip on each local Python 3.10/3.12; historical v3 instrument 10 passed at its original commit on both; followup 113 focused and 325 passed/1 skip broader tests on both. Repository compile/JSON/input checks and combined 22-case contract benchmark passed; source/wheel builds passed. Local enforcement demo and complete installed verification are unavailable at the Landlock step, not passes; the installed simulation demo passed. Separate GitHub-hosted post-repair CI on both Python versions passed the 14-case supported-host lab. The original full workflow still fails preserved historical source pins, with exact statuses/links retained; no safety test is weakened to make that workflow green.", "",
        "## Operational deployment", "", "**NOT READY FOR OPERATIONAL DEPLOYMENT.**", "",
        "Required work includes independent human review, authenticated persistent authority/revocation, trusted advancing clocks and connector linearization, rollback-resistant state/recovery, protected privilege/storage boundaries, capacity/retention limits, deployment keys, externally anchored audit, real least-privilege connectors and target-host validation. No production-readiness, formal verification, real containment/recovery, operational superiority or independent field-validation claim is supported.", "",
        "Both evidence PR #21 and fix PR #20 remain drafts and unmerged. REPRODUCE.md and the full findings table identify the precise next technical-review tasks.", ""]
    (out/"External_Evaluation_Readiness_Summary_v1.md").write_text("\n".join(ready))
    print(json.dumps({"reports_written":2,"conclusion":conclusion,"artifact_validation":validation},indent=2))


if __name__ == "__main__":
    report(ROOT/"results/replay_v4/pr19_2026-11-11_v2")
