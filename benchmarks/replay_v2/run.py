# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Strict execution-context replay; v1 inputs, labels and scoring stay frozen."""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import importlib.metadata
import importlib.util
import json
import math
from pathlib import Path
import platform
import subprocess
import sys
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import cerberus as api
from cerberus.guardian import EnvelopeIdempotencyRegistry
from cerberus.models import ValidationError
from benchmarks.replay_v1 import run as v1
from benchmarks.replay_v1.run import verifier, valid_receipt
from benchmarks.replay_v1.generate import CLASSES, NOW, sha256, trust_configuration

HERE = Path(__file__).resolve().parent
SYSTEMS = v1.SYSTEMS + ("soar_b2",)
BASE_TREE = "01ecf6493d4aec1f2a5bfb3963523e68d705a099"
ORACLE_HASH = "c73ef6ac1eead1efc7c97e3fd02c2f55893713ee3ce0b5d79373587139c58487"
CORPUS_HASH = "f4df28a32efa9cb011d6992788291aa022f781a8f7e2befd727a3a277007ff8a"
REFERENCE_KERNEL_HASH = "c5307ea2c78a7698a968763b2948b0fee339066ccfae10c903e21d56e04d3e5a"
B2_ACTIONS = {
    "revoke_sessions": "single_identity", "isolate_endpoint": "single_endpoint",
    "temporary_egress_hold": "single_workload", "quarantine_workload": "single_workload",
}


def frozen_inputs(verbose=False):
    frozen_sources = json.loads((HERE / "protected_sources.json").read_text())
    hashes = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in frozen_sources}
    if hashes != frozen_sources:
        raise ValueError("protected v1/Guardian/policy/envelope source changed: " +
                         ", ".join(p for p in hashes if hashes[p] != frozen_sources[p]))
    frozen, cases = v1.load_cases()
    historical = json.loads((ROOT / "results/replay_v1/results.json").read_text())
    checks = {
        "v1_oracle_sha256": historical["oracle_sha256"],
        "v2_oracle_sha256": hashes["benchmarks/replay_v1/oracle.json"],
        "v1_corpus_sha256": historical["corpus_sha256"],
        "v2_corpus_sha256": sha256(cases),
    }
    if verbose:
        for name, value in checks.items():
            print(f"{name}: {value}", flush=True)
    if checks["v1_oracle_sha256"] != ORACLE_HASH or checks["v2_oracle_sha256"] != ORACLE_HASH or checks["v1_corpus_sha256"] != CORPUS_HASH or checks["v2_corpus_sha256"] != CORPUS_HASH:
        raise ValueError("v1/v2 corpus or oracle hashes differ; refusing replay")
    diff = subprocess.check_output(
        ["git", "-C", str(ROOT), "diff", "--stat", BASE_TREE, "--",
         "benchmarks/replay_v1", "results/replay_v1", "tests/test_replay_v1.py"],
        text=True)
    if diff.strip():
        raise ValueError("v1 files changed:\n" + diff)
    return frozen, cases, historical, checks, {"protected_files": hashes, "v1_git_diff_stat": diff}


def dependencies(case):
    return frozenset(p["key_id"] for collection in case["assurance"].values() for p in collection)


@dataclass
class Simulator:
    gateway: api.EnforcementGateway
    state: dict
    events: list = field(default_factory=list)

    @property
    def ledger(self):
        return self.gateway.ledger


def submit(simulator, token, request, now):
    try:
        receipt = simulator.gateway.authorize_and_simulate(
            token, **{k: request[k] for k in ("action", "target", "scope")},
            expected_envelope=request, now=now)
    except api.EnforcementDenied as exc:
        return {"accepted": False, "reason": str(exc), "receipt": None}
    if not isinstance(receipt, dict) or not all(k in receipt for k in ("target", "action", "scope")):
        raise RuntimeError("Kernel returned an unobservable/malformed simulated receipt")
    # Apply before grading. No expected label or case variant controls mutation.
    before = deepcopy(simulator.state)
    simulator.state[receipt["target"]] = {"mode": receipt["action"], "scope": receipt["scope"]}
    changed = sorted(k for k in set(before) | set(simulator.state) if before.get(k) != simulator.state.get(k))
    for key in changed:
        simulator.events.append({
            "resource": key, "before": before.get(key), "after": deepcopy(simulator.state.get(key)),
            "request_sha256": sha256(request), "receipt_envelope_digest": receipt.get("envelope_digest"),
        })
    return {"accepted": True, "reason": "Kernel returned a simulated receipt", "receipt": receipt}


def new_simulator(signer, registry, target):
    return Simulator(api.EnforcementGateway(signer, replay_cache=api.ReplayCache(),
                     authority_registry=registry), {target: {"mode": "available", "scope": "none"}})


def setup_context(case, policies):
    setup = api.ActionEnvelope.from_dict(case["setup_request"])
    signer = api.DecisionTokenSigner(v1.PUBLIC_TEST_KEY, key_id="public-replay-v1")
    proofs = api.AssuranceBundle.from_dict(case["assurance"])
    decision = api.Guardian(policies, signer=signer,
        assurance_verifier=v1.verifier(trust_configuration(setup))).evaluate(setup, assurance=proofs, now=NOW)
    if decision.guardian_decision != "approve" or not decision.decision_token:
        raise RuntimeError("trusted setup did not authorize: " + decision.reason)
    payload = signer.verify(decision.decision_token, now=NOW)
    if payload["envelope_digest"] != setup.digest() or payload["policy_digest"] != policies.digest:
        raise RuntimeError("setup token has incorrect binding")
    authority = api.TokenAuthorityRegistry()
    authority.register(decision.decision_token, signer, authority_key_ids=dependencies(case), now=NOW)
    control = new_simulator(signer, authority, setup.target)
    positive = submit(control, decision.decision_token, case["setup_request"], NOW)
    if not positive["accepted"] or not v1.valid_receipt(positive["receipt"], case["setup_request"], payload):
        raise RuntimeError("Kernel positive control did not produce an exact simulated receipt")
    return {
        "signer": signer, "token": decision.decision_token,
        "gateway": new_simulator(signer, authority, setup.target),
        "registry": EnvelopeIdempotencyRegistry(), "authority_registry": authority,
        "probed": False, "timing_tokens": {}, "setup_control_mutations": len(control.events),
    }


def _observe_protocol(case: dict, policies: api.PolicyBundle, context: dict) -> dict:
    now = datetime.fromisoformat(case["evaluation_at"].replace("Z", "+00:00"))
    request = case["request"]
    violations, probes = [], []
    gateway, signer = context["gateway"], context["signer"]
    if not context["probed"]:
        variants = (
            ("missing_token", "", case["setup_request"]),
            ("forged_token", "e30." + "A" * 43, case["setup_request"]),
            ("unapproved_action", context["token"], dict(case["setup_request"], action="wipe_host")),
            ("unapproved_target", context["token"], dict(case["setup_request"], target="sandbox:replay:unapproved")),
            ("unapproved_scope", context["token"], dict(case["setup_request"], scope="enterprise")),
        )
        for name, token, altered in variants:
            outcome = submit(gateway, token, altered, NOW)
            probes.append({"probe": name, "expected_block": True, "accepted": outcome["accepted"], "reason": outcome["reason"]})
            if outcome["accepted"]:
                violations.append("KERNEL_ACCEPTED_" + name.upper())
        context["probed"] = True

    # Trusted-controller revocation events, independent of labels and case names.
    for key in case["trust_configuration"]["revoked_key_ids"]:
        context["authority_registry"].revoke_authority(key)

    guardian_observation, input_rejected = None, False
    decision = None
    if case["kernel_only"]:
        raw_decision, reason = None, "execution of previously issued authority after its deadline"
    else:
        try:
            envelope = api.ActionEnvelope.from_dict(request)
        except ValidationError as exc:
            raw_decision, reason, input_rejected = None, str(exc), True
        else:
            guardian = api.Guardian(policies, signer=signer, assurance_verifier=verifier(case["trust_configuration"]), idempotency_registry=context["registry"])
            decision = guardian.evaluate(envelope, assurance=api.AssuranceBundle.from_dict(case["assurance"]), now=now)
            raw_decision, reason = decision.guardian_decision, decision.reason
            if raw_decision not in {"approve", "escalate", "deny"}:
                raise RuntimeError("Guardian returned an unknown verdict")
            guardian_observation = {k: v for k, v in decision.to_dict().items() if k not in {"decision_token", "audit_record_hash"}}
            if not guardian.ledger.verify():
                violations.append("INVALID_GUARDIAN_AUDIT_CHAIN")
            if raw_decision != "approve" and decision.decision_token:
                violations.append("TOKEN_ON_NONAPPROVED_DECISION")
            if raw_decision == "approve" and not decision.decision_token:
                violations.append("APPROVE_WITHOUT_AUTHORITY")
            if raw_decision == "approve" and case["expected"] != "approve":
                violations.append("UNSAFE_GUARDIAN_AUTHORIZATION")

    if decision is not None and decision.decision_token:
        context["authority_registry"].register(decision.decision_token, signer, authority_key_ids=dependencies(case), now=now)
    token = context["token"] if case["reuse_grant"] else (decision.decision_token if decision else None) or ""
    context["timing_tokens"][case["id"]] = token
    outcome = submit(gateway, token, request, now)
    expected_block = case["expected"] != "approve"
    probes.append({"probe": "old_grant_for_current_request" if case["reuse_grant"] else "current_request", "expected_block": expected_block, "accepted": outcome["accepted"], "reason": outcome["reason"]})
    receipt_observation = None
    if outcome["accepted"]:
        pipeline_decision = "approve"
        if expected_block:
            violations.append("UNSAFE_KERNEL_PERMISSION")
        try:
            payload = signer.verify(token, now=now)
        except api.TokenValidationError:
            violations.append("KERNEL_ACCEPTED_INVALID_AUTHORITY")
        else:
            if payload["envelope_digest"] != sha256(request):
                violations.append("KERNEL_CONTEXT_NOT_BOUND_TO_CURRENT_REQUEST")
            if not valid_receipt(outcome["receipt"], request, payload):
                violations.append("INVALID_OR_REAL_EFFECT_RECEIPT")
            # Random token IDs/audit hashes are validated above, not serialized.
            receipt_observation = {k: outcome["receipt"].get(k) for k in (
                "status", "side_effects", "envelope_id", "envelope_digest", "idempotency_key", "actor", "incident_id", "policy_version", "policy_digest", "action", "target", "scope", "executed_at"
            )}
        reason = reason + "; " + outcome["reason"]
        if expected_block:
            reason += "; old authority was accepted for a denied/changed context (gateway has no expected-envelope or live-revocation input)"
        replay = submit(gateway, token, request, now)
        probes.append({"probe": "consumed_token_replay", "expected_block": True, "accepted": replay["accepted"], "reason": replay["reason"]})
        if replay["accepted"]:
            violations.append("KERNEL_ACCEPTED_CONSUMED_TOKEN")
    else:
        pipeline_decision = raw_decision if raw_decision in {"deny", "escalate"} else "deny"
        reason = reason + "; Kernel refusal: " + outcome["reason"]
    if not gateway.ledger.verify():
        violations.append("INVALID_KERNEL_AUDIT_CHAIN")
    return {
        "decision": pipeline_decision, "guardian_decision": raw_decision,
        "decision_layer": "input_validation" if input_rejected else "kernel" if case["reuse_grant"] else "guardian_and_kernel",
        "input_rejected": input_rejected, "reason": reason, "guardian": guardian_observation,
        "setup_control_passed": True, "receipt": receipt_observation,
        "kernel_probes": probes, "violations": violations, "measurement_valid": True,
    }



def observe(case, policies, context):
    simulator = context["gateway"]
    before, event_start = deepcopy(simulator.state), len(simulator.events)
    result = _observe_protocol(case, policies, context)
    events = deepcopy(simulator.events[event_start:])
    for event in events:
        event["in_authorized_scope"] = (
            case["expected"] == "approve" and result["guardian_decision"] == "approve"
            and event["resource"] == case["request"]["target"]
            and event["request_sha256"] == event["receipt_envelope_digest"] == sha256(case["request"])
        )
    result["simulator_state"] = {
        "before": before, "after": deepcopy(simulator.state), "mutations": events,
        "total": len(events), "out_of_scope": sum(not e["in_authorized_scope"] for e in events),
    }
    if result["simulator_state"]["out_of_scope"]:
        result["violations"].append("OUT_OF_SCOPE_SIMULATOR_MUTATION")
    return result


def b2(case, context):
    request = case["request"]
    try:
        payload = context["signer"].verify(context["token"],
            now=datetime.fromisoformat(case["evaluation_at"].replace("Z", "+00:00")))
    except api.TokenValidationError as exc:
        decision, reason = "deny", str(exc)
    else:
        allowed = B2_ACTIONS.get(request["action"]) == request["scope"]
        same = all(request[k] == payload[k] for k in ("action", "target", "scope"))
        decision = "approve" if allowed and same else "deny"
        reason = "fixed allowlist/scalar scope and signature/expiry gate; no evidence, full-envelope or revocation check"
    return {"decision": decision, "reason": reason, "measurement_valid": True,
            "violations": ["UNSAFE_BASELINE_PERMISSION"] if decision == "approve" and case["expected"] != "approve" else [],
            "kernel_probes": []}


def measure_functional(verbose=False):
    frozen, cases, historical, hashes, preservation = frozen_inputs(verbose)
    policies = api.PolicyBundle.load(ROOT / "policies/policies.json")
    contexts, rows = {}, []
    for case in cases:
        try:
            context = contexts.get(case["grant_id"])
            if context is None:
                contexts[case["grant_id"]] = context = setup_context(case, policies)
            measured = observe(case, policies, context)
            soar = b2(case, context)
        except Exception as exc:
            measured = {"decision": None, "reason": f"{type(exc).__name__}: {exc}",
                        "measurement_valid": False, "violations": [], "kernel_probes": []}
            soar = {"decision": None, "reason": "setup precondition unavailable", "measurement_valid": False,
                    "violations": [], "kernel_probes": []}
        systems = {"cerberus": measured, "soar_b2": soar}
        for system in v1.SYSTEMS[1:]:
            systems[system] = v1.baseline(case, system, frozen["confidence_baseline_threshold"])
        rows.append({k: case[k] for k in ("id", "class", "variant", "grant_id", "sequence_step", "expected", "basis", "evaluation_at")} | {
            "request_sha256": sha256(case["request"]), "setup_sha256": sha256(case["setup_request"]), "systems": systems})
    per_class = {name: {system: v1.summarize([r for r in rows if r["class"] == name], system) for system in SYSTEMS} for name in CLASSES}
    overall = {system: v1.summarize(rows, system) for system in SYSTEMS}
    failures = [{k: row[k] for k in ("id", "class", "variant", "expected", "basis")} | {
        "system": system, "observed": obs["decision"], "reason": obs["reason"],
        "measurement_valid": obs["measurement_valid"], "violations": obs["violations"]}
        for row in rows for system, obs in row["systems"].items()
        if not obs["measurement_valid"] or obs["decision"] != row["expected"] or obs["violations"]]
    old_rows = {r["id"]: r for r in historical["observations"]}
    changes = [{"id": r["id"], "v1": old_rows[r["id"]]["systems"]["cerberus"].get("guardian"),
                "v2": r["systems"]["cerberus"].get("guardian")} for r in rows
               if old_rows[r["id"]]["systems"]["cerberus"].get("guardian") != r["systems"]["cerberus"].get("guardian")]
    baseline_changes = [r["id"] for r in rows for system in v1.SYSTEMS[1:]
                        if r["systems"][system] != old_rows[r["id"]]["systems"][system]]
    state = {}
    for name in CLASSES + ("overall",):
        selected = rows if name == "overall" else [r for r in rows if r["class"] == name]
        events = [e for r in selected for e in r["systems"]["cerberus"].get("simulator_state", {}).get("mutations", [])]
        state[name] = {"total": len(events), "authorized": sum(e["in_authorized_scope"] for e in events),
                       "out_of_scope": sum(not e["in_authorized_scope"] for e in events)}
    new_denies = [r["id"] for r in rows if r["expected"] == "approve"
                  and old_rows[r["id"]]["systems"]["cerberus"]["decision"] == "approve"
                  and r["systems"]["cerberus"]["decision"] != "approve"]
    comparison = {name: {"v1": historical["overall"]["cerberus"] if name == "overall" else historical["per_class"][name]["cerberus"],
                         "v2": overall["cerberus"] if name == "overall" else per_class[name]["cerberus"]}
                  for name in CLASSES + ("overall",)}
    production = v1.source_hashes()
    result = {
        "instrument": "five-class-replay-v2", "seed": frozen["seed"], "clock": frozen["clock"],
        "upstream_snapshot": "48eefd82cee2c47c5ffc4f79de392ce3b0049ffe",
        "cases_per_class": frozen["cases_per_class"], "requests": len(rows), **hashes,
        "oracle_sha256": hashes["v2_oracle_sha256"], "corpus_sha256": hashes["v2_corpus_sha256"],
        "policy_digest": policies.digest, "production_files": production, "production_source_sha256": sha256(production),
        "instrument_files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.glob("*") if p.is_file()},
        "baseline_threshold": frozen["confidence_baseline_threshold"], "label_review": frozen["label_review"],
        "per_class": per_class, "overall": overall, "observations": rows, "failures": failures,
        "v1_comparison": comparison, "guardian_changes": changes, "baseline_changes": baseline_changes,
        "new_false_denies": new_denies, "simulator_state": state,
        "setup_control_mutations": sum(c["setup_control_mutations"] for c in contexts.values()),
        "source_preservation": preservation,
        "limits": "Synthetic replay in a simulator; labels derive from this repository's own documents, not field validation. Baselines are simplified stand-ins. Public fixture trust, no real telemetry or credentials, no network, simulated receipts and symbolic in-memory state only. Live registry is trusted, process-local and not durable/distributed; upstream revocation delivery and issuer provisioning remain assumptions.",
    }
    result["exit_code"] = 2 if overall["cerberus"]["measurement_errors"] else 1 if (
        any(f["system"] == "cerberus" for f in failures) or changes or baseline_changes or new_denies or state["overall"]["out_of_scope"]) else 0
    return result, cases, contexts


def reference_kernel():
    path = HERE / "reference_enforcement.py"
    if hashlib.sha256(path.read_bytes()).hexdigest() != REFERENCE_KERNEL_HASH:
        raise ValueError("original Kernel latency reference changed")
    spec = importlib.util.spec_from_file_location("cerberus._frozen_replay_v1_kernel", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def percentiles(samples):
    ordered = sorted(samples)
    return {name: ordered[max(0, math.ceil(p * len(ordered)) - 1)] for name, p in (("p50_ns", .5), ("p95_ns", .95), ("max_ns", 1))}


def measure_latency(cases, contexts):
    old = reference_kernel()
    samples, stats = [], []
    for case in cases:
        context = contexts[case["grant_id"]]
        token = context["timing_tokens"][case["id"]]
        request = case["request"]
        now = datetime.fromisoformat(case["evaluation_at"].replace("Z", "+00:00"))
        old_times, new_times = [], []
        outcomes = {}
        for repetition in range(120):
            gateways = {
                "v1": old.EnforcementGateway(context["signer"], replay_cache=old.ReplayCache()),
                "v2": api.EnforcementGateway(context["signer"], replay_cache=api.ReplayCache(), authority_registry=context["authority_registry"]),
            }
            elapsed = {}
            for version in (("v1", "v2") if repetition % 2 == 0 else ("v2", "v1")):
                kwargs = {k: request[k] for k in ("action", "target", "scope")}
                if version == "v2":
                    kwargs["expected_envelope"] = request
                started = perf_counter_ns()
                try:
                    receipt = gateways[version].authorize_and_simulate(token, **kwargs, now=now)
                except PermissionError:
                    accepted = False
                else:
                    accepted = True
                    if receipt.get("side_effects") is not False:
                        raise RuntimeError("latency reference produced a non-simulated receipt")
                elapsed[version] = perf_counter_ns() - started
                outcomes[version] = accepted
            if repetition >= 20:
                old_times.append(elapsed["v1"])
                new_times.append(elapsed["v2"])
        delta = [b - a for a, b in zip(old_times, new_times)]
        samples.append({"id": case["id"], "class": case["class"], "expected": case["expected"],
                        "v1_ns": old_times, "v2_ns": new_times, "paired_delta_ns": delta})
        stats.append({"id": case["id"], "class": case["class"], "v1": percentiles(old_times),
                      "v2": percentiles(new_times), "paired_delta": percentiles(delta), "acceptance": outcomes})
    aggregates = {}
    for name in CLASSES + ("overall", "legitimate_allow"):
        selected = samples if name == "overall" else [r for r in samples if r["class"] == ("legitimate" if name == "legitimate_allow" else name)]
        aggregates[name] = {field: percentiles([v for r in selected for v in r[key]]) for field, key in (
            ("v1", "v1_ns"), ("v2", "v2_ns"), ("paired_delta", "paired_delta_ns"))}
    cpu = platform.processor() or "unreported"
    path = Path("/proc/cpuinfo")
    if path.exists():
        cpu = next((line.split(":", 1)[1].strip() for line in path.read_text().splitlines() if line.startswith("model name")), cpu)
    return {
        "warmup_pairs_per_request": 20, "measured_pairs_per_request": 100,
        "measured_samples_per_gateway": len(cases) * 100,
        "clock": "perf_counter_ns", "percentiles": "nearest-rank", "alternate_order": True,
        "hardware": {"cpu": cpu, "architecture": platform.machine(), "os": platform.platform(),
                     "isolation": "no CPU affinity, frequency or load controls applied by this harness",
                     "python": platform.python_version(), "cryptography": importlib.metadata.version("cryptography"),
                     "jsonschema": importlib.metadata.version("jsonschema")},
        "per_request": stats, "aggregates": aggregates,
        "limits": "Same-host observed timings; scheduler, cache and platform vary. Mixed old-allow/new-deny paths are not equivalent useful work; legitimate_allow gives matched successful work. Setup, construction, revocation and model-state grading are outside timers.",
    }, samples



def render(result):
    fmt, fence = v1.display, chr(96) * 3
    lines = ["# Five-class synthetic replay v2", "", f"**{'PASS' if result['exit_code'] == 0 else 'FAIL'} — synthetic replay in a simulator, not field validation.**", "",
             "[v1 historical FAIL](../replay_v1/report.md) · [machine-readable v2 results](results.json) · [precommitted plan](../../benchmarks/replay_v2/PLAN.md)", "",
             f"Seed {result['seed']}; 135 requests / 125 setups. Corpus, oracle and scoring are inherited unchanged. Guardian changes: {len(result['guardian_changes'])}; new false denies: {len(result['new_false_denies'])}; measurement errors: {result['overall']['cerberus']['measurement_errors']}.", "",
             "## Input preservation", "", fence + "text"]
    lines += [f"{k}: {result[k]}" for k in ("v1_oracle_sha256", "v2_oracle_sha256", "v1_corpus_sha256", "v2_corpus_sha256")]
    lines += [fence, "", "Protected v1 diff:", "", fence + "text",
              "git diff --stat 01ecf6493d4aec1f2a5bfb3963523e68d705a099 -- benchmarks/replay_v1 results/replay_v1 tests/test_replay_v1.py",
              result["source_preservation"]["v1_git_diff_stat"] or "(empty: 0 files changed)", fence, "",
              "## CERBERUS v1 versus v2 by class", "",
              "| Class | v1 false allows | v2 false allows | v1 accuracy | v2 accuracy | v1 violations | v2 violations | v1 Kernel refusals | v2 Kernel refusals |",
              "|---|---|---|---|---|---|---|---|---|"]
    for name, pair in result["v1_comparison"].items():
        a, b = pair["v1"], pair["v2"]
        lines.append(f"| {name} | {fmt(a['false_allow'])} | {fmt(b['false_allow'])} | {fmt(a['accuracy'])} | {fmt(b['accuracy'])} | {a['safety_invariant_violations']} | {b['safety_invariant_violations']} | {fmt(a['kernel_refusal'])} | {fmt(b['kernel_refusal'])} |")
    lines += ["", "Kernel probe counts follow the unchanged v1 observer: a replay probe is added after an acceptance, so eliminating unsafe acceptances also eliminates those follow-up probes. Compare fractions and request-level outcomes, not probe totals alone.", ""]
    for name, values in list(result["per_class"].items()) + [("overall", result["overall"])]:
        lines += [f"## {name.replace('_',' ').title()}: same-label baseline comparison", "",
                  "| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations | Kernel refusals |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for system in SYSTEMS:
            m = values[system]
            lines.append("| " + " | ".join([system, fmt(m["accuracy"]), fmt(m["false_allow"]), fmt(m["false_deny"]), fmt(m["escalation_rate"]), fmt(m["escalation_correctness"]), fmt(m["escalation_recall"]), str(m["safety_invariant_violations"]), fmt(m["kernel_refusal"])]) + " |")
        lines.append("")
    lines += ["## Observed simulator-state mutations", "",
              "| Class | Total changed resources | Authorized | Out of scope |", "|---|---|---|---|"]
    for name, state in result["simulator_state"].items():
        lines.append(f"| {name} | {state['total']} | {state['authorized']} | {state['out_of_scope']} |")
    lines += ["", f"Isolated setup-control mutations: {result['setup_control_mutations']}; excluded from functional totals. Main-path state snapshots and each changed key are in JSON. Every accepted receipt is applied before grading; expected labels cannot prevent a mutation. These are symbolic in-memory transitions, not physical containment.", "",
              "## Latency impact", ""]
    latency = result.get("latency")
    if latency:
        lines += [f"20 warmup pairs and 100 measured pairs per request; {latency['measured_samples_per_gateway']} samples per gateway. Same host: {json.dumps(latency['hardware'], sort_keys=True)}.", "",
                  "| Group | v1 p50 / p95 / max (µs) | v2 p50 / p95 / max (µs) | Paired added p50 / p95 / max (µs) |", "|---|---|---|---|"]
        def timing(value):
            return " / ".join(f"{value[k]/1000:.3f}" for k in ("p50_ns","p95_ns","max_ns"))
        for name, values in latency["aggregates"].items():
            lines.append(f"| {name} | {timing(values['v1'])} | {timing(values['v2'])} | {timing(values['paired_delta'])} |")
        lines += ["", latency["limits"], "Per-request statistics are in results.json; all raw paired samples are in [latency_samples.jsonl](latency_samples.jsonl). Timings vary across runs; deterministic scoring excludes them.", ""]
    else:
        lines += ["Not measured because functional preconditions were invalid.", ""]
    lines += ["## Remaining CERBERUS failures and new false denies", ""]
    remaining = [f for f in result["failures"] if f["system"] == "cerberus"]
    lines += ["None." if not remaining and not result["new_false_denies"] else json.dumps({"failures": remaining, "new_false_denies": result["new_false_denies"]}, indent=2), "",
              "## Every failed case, including simplified comparators", "",
              "| Case | Expected | Failed systems / observed decisions | Reason |", "|---|---|---|---|"]
    for row in result["observations"]:
        failed = [f for f in result["failures"] if f["id"] == row["id"]]
        if not failed:
            continue
        systems = "; ".join(f"{f['system']}: {f['observed'] or 'measurement error'}" for f in failed)
        actual = next((f for f in failed if f["system"] == "cerberus"), None)
        reason = actual["reason"] if actual else "Comparator lacks the required check: " + row["basis"]
        lines.append(f"| {row['id']} | {row['expected']} | {systems} | {reason.replace('|', '/')} |")
    lines += ["", "## Limits and label review", "", result["limits"], "",
              "The following are inherited historical v1 label-review notes. V2 addresses the measured Kernel gaps without changing these labels or their recorded provenance.", ""]
    lines += ["- " + item for item in result["label_review"]]
    lines += ["", "Only these measured cases support the reported result. No claim that the system is secure, production ready, independently validated or operationally effective follows.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results/replay_v2")
    args = parser.parse_args()
    try:
        result, cases, contexts = measure_functional(verbose=True)
        if result["overall"]["cerberus"]["measurement_errors"] == 0:
            result["latency"], samples = measure_latency(cases, contexts)
        else:
            result["latency"], samples = None, []
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(2, f"INVALID MEASUREMENT: {exc}\n")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "results.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (args.output_dir / "report.md").write_text(render(result), encoding="utf-8")
    (args.output_dir / "latency_samples.jsonl").write_text("".join(json.dumps(s, sort_keys=True) + "\n" for s in samples), encoding="utf-8")
    print(json.dumps({"exit_code": result["exit_code"], "cerberus": result["overall"]["cerberus"],
                      "simulator_state": result["simulator_state"]["overall"]}, sort_keys=True))
    raise SystemExit(result["exit_code"])


if __name__ == "__main__":
    main()
