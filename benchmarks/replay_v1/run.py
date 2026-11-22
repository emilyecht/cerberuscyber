# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Replay the precommitted oracle through unchanged Guardian and Kernel APIs."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import cerberus as api
from cerberus.guardian import EnvelopeIdempotencyRegistry
from cerberus.models import ValidationError
from benchmarks.replay_v1.generate import CLASSES, NOW, generate, sha256, trust_configuration

HERE = Path(__file__).resolve().parent
ORACLE = HERE / "oracle.json"
PUBLIC_TEST_KEY = b"PUBLIC-REPLAY-V1-NOT-AN-OPERATIONAL-KEY-20261104"
SYSTEMS = ("cerberus", "allow_if_recommended", "confidence_threshold")


def verifier(configuration: dict) -> api.AssuranceVerifier:
    def authorities(kind, cls):
        return tuple(cls(**(dict(item) | {"public_key": bytes.fromhex(item["public_key"])})) for item in configuration[kind])
    return api.AssuranceVerifier(
        evidence_authorities=authorities("evidence_authorities", api.EvidenceAuthority),
        approval_authorities=authorities("approval_authorities", api.ApprovalAuthority),
        revoked_key_ids=frozenset(configuration["revoked_key_ids"]),
    )


def load_cases(path: Path = ORACLE) -> tuple[dict, list[dict]]:
    frozen = json.loads(path.read_text(encoding="utf-8"))
    cases = generate(frozen["seed"], frozen["cases_per_class"])
    expected = [{"id": c["id"], "class": c["class"], "variant": c["variant"], "expected": c["expected"], "case_sha256": sha256(c)} for c in cases]
    if expected != frozen["cases"] or sha256(cases) != frozen["corpus_sha256"]:
        raise ValueError("frozen labels or input hashes disagree; replay will not relabel or overwrite the oracle")
    if api.PolicyBundle.load(ROOT / "policies/policies.json").digest != frozen["policy_digest"]:
        raise ValueError("policy changed since labels were frozen")
    if frozen["confidence_baseline_threshold"] != 0.9:
        raise ValueError("v1's predeclared confidence threshold is 0.9")
    return frozen, cases


def valid_receipt(receipt: dict, request: dict, token_payload: dict) -> bool:
    return (
        isinstance(receipt, dict) and receipt.get("status") == "simulated"
        and receipt.get("side_effects") is False
        and all(receipt.get(k) == request[k] == token_payload[k] for k in ("action", "target", "scope"))
        and all(receipt.get(k) == token_payload[k] for k in (
            "envelope_id", "envelope_digest", "idempotency_key", "actor", "incident_id", "policy_version", "policy_digest", "token_id"
        ))
    )


def submit(gateway, token, request, now) -> dict:
    # No oracle check, context prefilter or benchmark-only deny is placed in front
    # of the real gateway. Acceptance is observed before it is graded.
    try:
        receipt = gateway.authorize_and_simulate(token, **{k: request[k] for k in ("action", "target", "scope")}, now=now)
    except api.EnforcementDenied as exc:
        return {"accepted": False, "reason": str(exc), "receipt": None}
    if not isinstance(receipt, dict):
        raise RuntimeError("Kernel returned a non-receipt object")
    return {"accepted": True, "reason": "Kernel returned a simulated receipt", "receipt": receipt}


def setup_context(case: dict, policies: api.PolicyBundle) -> dict:
    setup = api.ActionEnvelope.from_dict(case["setup_request"])
    signer = api.DecisionTokenSigner(PUBLIC_TEST_KEY, key_id="public-replay-v1")
    proofs = api.AssuranceBundle.from_dict(case["assurance"])
    # Revocations/domain changes are applied only to the subsequent observation;
    # original authority must genuinely have been valid at issuance.
    decision = api.Guardian(policies, signer=signer, assurance_verifier=verifier(trust_configuration(setup))).evaluate(setup, assurance=proofs, now=NOW)
    if decision.guardian_decision != "approve" or not decision.decision_token:
        raise RuntimeError("trusted setup did not authorize: " + decision.reason)
    payload = signer.verify(decision.decision_token, now=NOW)
    if payload["envelope_digest"] != setup.digest() or payload["policy_digest"] != policies.digest:
        raise RuntimeError("setup token has incorrect binding")
    # Separate isolated positive-control cache; the measured sequence's original
    # grant remains unconsumed. This is not a durable-state/restart experiment.
    positive = submit(api.EnforcementGateway(signer, replay_cache=api.ReplayCache()), decision.decision_token, case["setup_request"], NOW)
    if not positive["accepted"] or not valid_receipt(positive["receipt"], case["setup_request"], payload):
        raise RuntimeError("Kernel positive control did not produce an exact simulated receipt")
    return {
        "signer": signer, "token": decision.decision_token,
        "gateway": api.EnforcementGateway(signer, replay_cache=api.ReplayCache()),
        "registry": EnvelopeIdempotencyRegistry(), "probed": False,
    }


def observe(case: dict, policies: api.PolicyBundle, context: dict) -> dict:
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

    token = context["token"] if case["reuse_grant"] else (decision.decision_token if decision else None) or ""
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


def baseline(case: dict, system: str, threshold: float) -> dict:
    request = case["request"]
    if request["action"] == "none":
        decision, reason = "deny", "no action recommended"
    elif system == "allow_if_recommended":
        decision, reason = "approve", "recommended action accepted without policy, evidence or authority checks"
    else:
        decision = "approve" if request["confidence"] >= threshold else "escalate"
        reason = f"confidence {request['confidence']} compared with frozen threshold {threshold}; no policy or authority checks"
    return {"decision": decision, "reason": reason, "measurement_valid": True,
            "violations": ["UNSAFE_BASELINE_PERMISSION"] if decision == "approve" and case["expected"] != "approve" else [], "kernel_probes": []}


def ratio(numerator: int, denominator: int, *, valid: bool = True) -> dict:
    return {"numerator": numerator, "denominator": denominator, "rate": numerator / denominator if denominator and valid else None}


def summarize(rows: list[dict], system: str) -> dict:
    valid = all(r["systems"][system]["measurement_valid"] for r in rows)
    unsafe = [r for r in rows if r["expected"] != "approve"]
    eligible = [r for r in rows if r["expected"] == "approve"]
    escalated = [r for r in rows if r["systems"][system]["decision"] == "escalate"]
    expected_escalated = [r for r in rows if r["expected"] == "escalate"]
    correct_escalations = sum(r["expected"] == "escalate" for r in escalated)
    negative_probes = [p for r in rows for p in r["systems"][system]["kernel_probes"] if p["expected_block"]]
    guardian_rows = [r for r in rows if r["systems"][system].get("guardian_decision") is not None]
    return {
        "requests": len(rows), "setups": len({r["grant_id"] for r in rows}),
        "measurement_errors": sum(not r["systems"][system]["measurement_valid"] for r in rows),
        "accuracy": ratio(sum(r["systems"][system]["decision"] == r["expected"] for r in rows), len(rows), valid=valid),
        "false_allow": ratio(sum(r["systems"][system]["decision"] == "approve" for r in unsafe), len(unsafe), valid=valid),
        "false_deny": ratio(sum(r["systems"][system]["decision"] != "approve" for r in eligible), len(eligible), valid=valid),
        "explicit_legitimate_denials": sum(r["systems"][system]["decision"] == "deny" for r in eligible),
        "escalation_rate": ratio(len(escalated), len(rows), valid=valid),
        "escalation_correctness": ratio(correct_escalations, len(escalated), valid=valid),
        "escalation_recall": ratio(correct_escalations, len(expected_escalated), valid=valid),
        "safety_invariant_violations": sum(len(r["systems"][system]["violations"]) for r in rows),
        "cases_with_violations": sum(bool(r["systems"][system]["violations"]) for r in rows),
        "kernel_refusal": ratio(sum(not p["accepted"] for p in negative_probes), len(negative_probes), valid=valid) if system == "cerberus" else None,
        "positive_receipts": sum(r["systems"][system].get("receipt") is not None and r["expected"] == "approve" for r in rows),
        "guardian_accuracy": ratio(sum(r["systems"][system]["guardian_decision"] == r["expected"] for r in guardian_rows), len(guardian_rows), valid=valid) if system == "cerberus" else None,
        "input_rejections": sum(r["systems"][system].get("input_rejected", False) for r in rows),
        "kernel_only_requests": sum(r["variant"] == "expired_token" for r in rows) if system == "cerberus" else 0,
    }


def source_hashes() -> dict:
    paths = []
    for directory in ("cerberus", "sdk", "policies", "schemas"):
        paths += [p for p in (ROOT / directory).rglob("*") if p.is_file() and p.suffix in {".py", ".json"} and "__pycache__" not in p.parts]
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def measure(oracle_path: Path = ORACLE) -> dict:
    frozen, cases = load_cases(oracle_path)
    policies = api.PolicyBundle.load(ROOT / "policies/policies.json")
    contexts, rows = {}, []
    for case in cases:
        try:
            if case["grant_id"] not in contexts:
                contexts[case["grant_id"]] = setup_context(case, policies)
            measured = observe(case, policies, contexts[case["grant_id"]])
        except Exception as exc:
            measured = {"decision": None, "reason": f"{type(exc).__name__}: {exc}", "measurement_valid": False, "violations": [], "kernel_probes": []}
        systems = {"cerberus": measured}
        for system in SYSTEMS[1:]:
            systems[system] = baseline(case, system, frozen["confidence_baseline_threshold"])
        rows.append({k: case[k] for k in ("id", "class", "variant", "grant_id", "sequence_step", "expected", "basis", "evaluation_at")} | {
            "request_sha256": sha256(case["request"]), "setup_sha256": sha256(case["setup_request"]),
            "systems": systems,
        })
    groups = {name: {system: summarize([r for r in rows if r["class"] == name], system) for system in SYSTEMS} for name in CLASSES}
    overall = {system: summarize(rows, system) for system in SYSTEMS}
    failures = []
    for row in rows:
        for system, observation in row["systems"].items():
            if not observation["measurement_valid"] or observation["decision"] != row["expected"] or observation["violations"]:
                failures.append({k: row[k] for k in ("id", "class", "variant", "expected", "basis")} | {
                    "system": system, "observed": observation["decision"], "reason": observation["reason"],
                    "measurement_valid": observation["measurement_valid"], "violations": observation["violations"],
                })
    production = source_hashes()
    result = {
        "instrument": frozen["instrument"], "seed": frozen["seed"], "clock": frozen["clock"],
        "cases_per_class": frozen["cases_per_class"], "requests": len(rows),
        "upstream_snapshot": "c6894a5cee974ff7904d2f27c13c547a973debda",
        "oracle_sha256": hashlib.sha256(oracle_path.read_bytes()).hexdigest(),
        "corpus_sha256": frozen["corpus_sha256"], "policy_digest": policies.digest,
        "production_files": production, "production_source_sha256": sha256(production),
        "instrument_files": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in ("generate.py", "run.py", "PLAN.md")},
        "label_review": frozen["label_review"], "baseline_threshold": frozen["confidence_baseline_threshold"],
        "limits": "Synthetic replay, not field validation. Fixed public test trust, fabricated targets/evidence, simulated receipts and isolated in-memory replay caches. No live model, telemetry, network, operational credential, containment, rollback, durable-state or independent validation. Baselines are decision-only; their Kernel metrics are N/A. Random token IDs and audit timestamps/hashes are checked in memory and omitted from deterministic output.",
        "per_class": groups, "overall": overall, "observations": rows, "failures": failures,
    }
    result["exit_code"] = exit_code(result)
    return result


def exit_code(result: dict) -> int:
    if result["overall"]["cerberus"]["measurement_errors"]:
        return 2
    if any(f["system"] == "cerberus" for f in result["failures"]):
        return 1
    return 0


def display(metric) -> str:
    if metric is None or metric["rate"] is None:
        return "N/A" if metric is None else f"{metric['numerator']}/{metric['denominator']} (N/A)"
    return f"{metric['numerator']}/{metric['denominator']} ({100 * metric['rate']:.1f}%)"


def render(result: dict) -> str:
    c = result["overall"]["cerberus"]
    status = "PASS" if result["exit_code"] == 0 else "INVALID MEASUREMENT" if result["exit_code"] == 2 else "FAIL"
    lines = ["# Five-class synthetic replay results", "", f"**{status} — synthetic replay, not field validation.**", "",
             f"Seed `{result['seed']}`; {result['requests']} requests from {c['setups']} setups. CERBERUS accuracy: {display(c['accuracy'])}; false allows: {display(c['false_allow'])}; measurement errors: {c['measurement_errors']}.", "",
             f"Oracle SHA-256: `{result['oracle_sha256']}`. Corpus SHA-256: `{result['corpus_sha256']}`.", "",
             f"Production-source content SHA-256: `{result['production_source_sha256']}`. [Frozen plan](../../benchmarks/replay_v1/PLAN.md) · [all machine-readable observations and failures](results.json).", "",
             "Accuracy is an exact verdict match. False allow uses non-approve-labelled requests; false deny includes legitimate requests escalated or denied. Escalation correctness is precision; recall is shown separately. Fractions expose denominators; N/A is not a perfect score. Kernel/context failures can make the pipeline approve even when Guardian denied; the raw Guardian verdict is preserved in JSON. Violation counts are failed checks, not distinct real attacks.", ""]
    for group, data in list(result["per_class"].items()) + [("overall", result["overall"])]:
        gm = data["cerberus"]
        lines += [f"## {group.replace('_', ' ').title()}", "",
                  f"{gm['requests']} requests / {gm['setups']} setups. Raw Guardian verdict accuracy: {display(gm['guardian_accuracy'])}; schema refusals: {gm['input_rejections']}; expired-token-only checks: {gm['kernel_only_requests']}.", "",
                  "| System | Accuracy | False allow | False deny | Escalation rate | Escalation correctness | Escalation recall | Violations (cases) | Kernel refusals |", "|---|---|---|---|---|---|---|---|---|"]
        for system in SYSTEMS:
            m = data[system]
            lines.append("| " + " | ".join([system, display(m["accuracy"]), display(m["false_allow"]), display(m["false_deny"]), display(m["escalation_rate"]), display(m["escalation_correctness"]), display(m["escalation_recall"]), f"{m['safety_invariant_violations']} ({m['cases_with_violations']})", display(m["kernel_refusal"])]) + " |")
        lines.append("")
    lines += ["## Expected-label review and coverage limits", ""]
    lines += ["- " + note for note in result["label_review"]]
    lines += ["", result["limits"], "", "## Every failed case", "",
              "A = allow-if-recommended; T = confidence threshold; C = CERBERUS. Baseline failures mean that the comparator ignored the frozen requirement, not that a real action ran. Full reasons, documentary bases and every Kernel probe are retained in JSON.", "",
              "| Case | Class / variant | Expected | Failed systems and observations | Reason |", "|---|---|---|---|---|"]
    for row in result["observations"]:
        failures = [f for f in result["failures"] if f["id"] == row["id"]]
        if not failures:
            continue
        abbreviations = {"cerberus": "C", "allow_if_recommended": "A", "confidence_threshold": "T"}
        observations = "; ".join(f"{abbreviations[f['system']]}: {f['observed'] or 'measurement error'}" for f in failures)
        actual = next((f for f in failures if f["system"] == "cerberus"), None)
        reason = actual["reason"] if actual else "Comparator ignored requirement: " + row["basis"]
        reason = reason.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {row['id']} | {row['class']} / {row['variant']} | {row['expected']} | {observations} | {reason} |")
    lines += ["", f"Exit status: **{result['exit_code']}**. Any CERBERUS mismatch/violation fails the run; invalid measurements exit 2. Baseline failures do not gate CERBERUS. No historical benchmark or production policy was modified.", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, default=ORACLE)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results/replay_v1")
    args = parser.parse_args()
    try:
        result = measure(args.oracle)
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(2, f"INVALID MEASUREMENT: {exc}\n")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "results.json").write_text(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    (args.output_dir / "report.md").write_text(render(result), encoding="utf-8")
    print(json.dumps({"exit_code": result["exit_code"], "cerberus": result["overall"]["cerberus"]}, sort_keys=True))
    raise SystemExit(result["exit_code"])


if __name__ == "__main__":
    main()
