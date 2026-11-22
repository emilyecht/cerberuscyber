# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Verify a recorded result, including a faithfully recorded failed/invalid gate."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import timedelta
import gzip
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from benchmarks.replay_v4 import run as v4


def verify(directory):
    oracle, preservation = v4.frozen_inputs()
    compressed = (directory/"results.json.gz").read_bytes()
    raw = gzip.decompress(compressed)
    entries = [line.split() for line in (directory/"results.sha256").read_text().splitlines()]
    assert entries[0][0] == v4.sha(raw), "decompressed digest mismatch"
    assert entries[1][0] == v4.sha(compressed), "gzip digest mismatch"
    result = json.loads(raw)
    assert result["target_commit"] == v4.TARGET
    assert result["freeze_commit"] == v4.FREEZE
    assert result["seed"] == oracle["seed"]
    env = result["environment"]
    runner = v4.git("show",env["git_head"]+":benchmarks/replay_v4/run.py")
    assert v4.sha(runner) == env["runner_sha256"], "runner/source commit mismatch"
    planned = [(c,i,a) for c in oracle["cases"] for i,a in enumerate(c["attempts"])]
    rows = result["observations"]
    assert len(rows) == len(planned) == 1100
    assert len({r["id"] for r in rows}) == 1100
    assert result["cases"] == 1005 and result["primary_attempts"] == 1100
    samples = {s["id"]:s for s in result["latency"]["samples"]}
    assert len(samples) == 1100
    assert result["latency"]["warmup"] == 5
    assert result["latency"]["measured_repetitions"] == 20
    allow, unsafe, fa, fd, invalid, ambiguous, failures = 0,0,0,0,0,0,[]
    baseline_checks = Counter()
    for row,(case,index,attempt) in zip(rows,planned):
        identifier = case["id"]+".s"+str(index+1)
        assert row["id"] == identifier
        assert row["expected"] == attempt["expected"], "frozen label changed: "+identifier
        assert row["citations"] == attempt["citations"]
        assert row["family"] == case["family"] and row["variant"] == case["variant"]
        request = v4.request_for(type("Inputs",(),{"oracle":oracle})(),case,attempt)
        obs = row["systems"]["cerberus"]
        if obs["measurement_valid"]:
            assert row["request_sha256"] == v4.sha(v4.canonical(request))
            receipt = obs.get("receipt")
            if receipt is not None:
                assert obs["decision"] == "allow" and obs["symbolic_writes"] == 1
                assert receipt["status"] == "simulated" and receipt["side_effects"] is False
                assert receipt["envelope_digest"] == row["request_sha256"]
                for name in ("envelope_id","idempotency_key","actor","incident_id","action","target","scope","policy_version"):
                    assert receipt[name] == request[name]
                target = receipt["target"]
                assert obs["state_after"][target]["writes"] == obs["state_before"].get(target,{}).get("writes",0)+1
            else:
                assert obs["decision"] != "allow" and obs["symbolic_writes"] == 0
            for name,expected in (("allow_if_recommended","deny" if request["action"] == "none" else "allow"),
                ("confidence_0.9","deny" if request["action"] == "none" else "allow" if request["confidence"] >= .9 else "escalate")):
                assert row["systems"][name]["decision"] == expected
                baseline_checks[name] += 1
            # Independent scalar/expiry calculation for the fixed SOAR baseline.
            template = oracle["templates"][case["template_ref"]]
            original = template["envelope"]
            clock = v4.parse(oracle["clock"])
            deadlines = [clock+timedelta(seconds=int(json.loads((ROOT/"policies/policies.json").read_text())["decision_ttl_seconds"])),
                v4.parse(original["freshness"]["expires_at"])]
            deadlines += [v4.parse(e["observed_at"])+timedelta(seconds=60) for e in original["evidence_refs"]]
            if original["human_approvals"]:
                deadlines.append(v4.parse(template["assurance_recipe"]["approval_expiry"]))
            now = v4.parse(row["logical_time"])
            # Token not-before is exact, distinct from evidence's skew allowance.
            approved = now < min(deadlines) and now >= clock
            approved &= v4.v2.B2_ACTIONS.get(request["action"]) == request["scope"]
            approved &= all(request[k] == original[k] for k in ("action","target","scope"))
            assert row["systems"]["soar_b2"]["decision"] == ("allow" if approved else "deny"), "SOAR baseline mismatch: "+identifier
            baseline_checks["soar_b2"] += 1
        if not obs["measurement_valid"]: invalid += 1
        if attempt["expected"] == "doc-ambiguous":
            ambiguous += 1
        elif obs["measurement_valid"]:
            if attempt["expected"] == "allow":
                allow += 1; fd += obs["decision"] != "allow"
            else:
                unsafe += 1; fa += obs["decision"] == "allow"
        if attempt["expected"] != "doc-ambiguous" and (not obs["measurement_valid"] or obs["decision"] != attempt["expected"] or obs.get("violations")):
            failures.append(identifier)
        sample = samples[identifier]
        assert len(sample["kernel_ns"])+sample["no_kernel_call"] == 20
        for key in ("kernel_ns","guardian_ns","constructor_ns"):
            assert len(sample[key]) in (0,20)
            assert all(n > 0 for n in sample[key])
        for name in v4.SYSTEMS[1:]:
            assert len(sample["baseline_ns"][name]) == (20 if obs["measurement_valid"] else 0)
        if obs.get("constructor_refusal"):
            assert not sample["kernel_ns"], "constructor refusal has fake kernel latency"
    assert ambiguous == 22
    assert failures == [f["id"] for f in result["failures"]]
    summary = result["summaries"]["overall_descriptive_only"]["cerberus"]
    assert summary["false_allows"]["numerator"] == fa and summary["false_allows"]["denominator"] == unsafe
    assert summary["false_denies"]["numerator"] == fd and summary["false_denies"]["denominator"] == allow
    code = 2 if invalid or result["repeat_mismatches"] else 1 if failures else 0
    assert result["exit_code"] == code
    assert result["gate"] == ("INVALID_MEASUREMENT" if code == 2 else "FAIL" if code else "PASS")
    return {"artifact_verified":True,"recorded_gate":result["gate"],"primary_attempts":len(rows),
        "false_allows":[fa,unsafe],"false_denies":[fd,allow],"ambiguous":ambiguous,
        "invalid_primary_measurements":invalid,"baseline_decisions_independently_checked":dict(baseline_checks),
        "runner_commit":env["git_head"],"runner_sha256":env["runner_sha256"],
        "oracle_sha256":preservation["v4_oracle_sha256"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory",type=Path)
    parser.add_argument("--require-pass",action="store_true")
    args = parser.parse_args()
    outcome = verify(args.directory)
    print(json.dumps(outcome,indent=2))
    if args.require_pass and outcome["recorded_gate"] != "PASS":
        raise SystemExit(1)
