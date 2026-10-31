"""Frozen-corpus authorization benchmark. No operational connectors or payloads.

Run each target in a separate interpreter. Expected outcomes are explicit fixture
data and are never derived from Guardian's policies or decisions.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any
from uuid import NAMESPACE_URL, uuid5

sys.dont_write_bytecode = True
CASE_FILE = Path(__file__).with_name("cases.json")
TEST_KEY = b"cerberus-benchmark-only-public-test-key-0000000001"
KINDS = {"unsafe", "valid", "review", "benign", "gateway", "lifecycle"}
EXPECTED = {"withhold", "reject", "deny", "escalate", "approve", "block"}
SOURCE_DIRS = ("cerberus", "sdk", "schemas", "policies")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_corpus(path: Path = CASE_FILE) -> dict[str, Any]:
    corpus = json.loads(path.read_text(encoding="utf-8"))
    if corpus.get("benchmark_version") != "1.0.0" or not corpus.get("cases"):
        raise ValueError("unsupported or empty benchmark corpus")
    ids = [case["id"] for case in corpus["cases"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate benchmark case IDs")
    for case in corpus["cases"]:
        if (case["kind"] not in KINDS or case["expected"] not in EXPECTED
                or case["basis"] not in {"existing_contract", "extended_assurance"}
                or case["profile"] not in corpus["profiles"] or not case["description"]):
            raise ValueError(f"invalid benchmark case: {case['id']}")
        if case["kind"] == "valid" and case["expected"] != "approve":
            raise ValueError("eligible responses must require approval and an exact receipt")
        if case["kind"] == "unsafe" and case["expected"] not in {"reject", "deny", "withhold"}:
            raise ValueError("unsafe requests must require authority to be withheld")
        if case["kind"] in {"gateway", "lifecycle"} and (
                case["expected"] != "block" or not case.get("operation")):
            raise ValueError("gateway/lifecycle cases need an explicit blocked operation")
    return corpus


def make_payload(corpus: dict, case: dict) -> dict:
    """Build canonical input without importing implementation models or policies."""
    profile = deepcopy(corpus["profiles"][case["profile"]])
    now = datetime.fromisoformat(corpus["now"].replace("Z", "+00:00"))
    target = f"sandbox:{case['profile']}:{case['id']}"
    evidence = []
    for i, signal in enumerate(profile.pop("signals")):
        ref = {"signal": signal, "source_id": f"trusted-observer:{i}",
               "observed_at": timestamp(now - timedelta(seconds=5))}
        ref["digest"] = digest(canonical({**ref, "target": target}))
        evidence.append(ref)
    payload = {
        **profile, "schema_version": "1.0.0", "envelope_id": f"benchmark:{case['id']}",
        "incident_id": f"BENCH-{case['id']}", "actor": "sentinel:benchmark-sandbox",
        "target": target, "evidence_refs": evidence,
        "freshness": {"timestamp": timestamp(now - timedelta(seconds=1)),
                      "expires_at": timestamp(now + timedelta(seconds=120)),
                      "nonce": digest(case["id"].encode())[:32]},
        "idempotency_key": str(uuid5(NAMESPACE_URL, f"cerberus-benchmark-v1:{case['id']}")),
        "reversibility_flag": True, "policy_version": corpus["policy_version"],
        "mission_impact": "low",
    }
    for patch in case.get("patches", []):
        parent = payload
        for part in patch["path"][:-1]:
            parent = parent[part]
        key = patch["path"][-1]
        if patch.get("remove"):
            del parent[key]
        else:
            parent[key] = deepcopy(patch["value"])
    return payload


def git(target: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(target), *args], text=True).strip()


def target_metadata(target: Path) -> dict:
    if git(target, "status", "--porcelain", "--untracked-files=no", "--", *SOURCE_DIRS):
        raise ValueError("target production sources have uncommitted changes")
    untracked = git(target, "ls-files", "--others", "--exclude-standard", "--", *SOURCE_DIRS)
    if any(Path(name).suffix in {".py", ".json"} for name in untracked.splitlines()):
        raise ValueError("target has untracked Python or JSON production sources")
    files = git(target, "ls-files", "--", *SOURCE_DIRS).splitlines()
    hashes = {name: digest((target / name).read_bytes()) for name in files}
    return {"commit": git(target, "rev-parse", "HEAD"),
            "git_tree": git(target, "rev-parse", "HEAD^{tree}"),
            "production_source_sha256": digest(canonical(hashes)),
            "policy_sha256": digest((target / "policies/policies.json").read_bytes())}


def load_target(target: Path):
    for name in ("cerberus", "sdk"):
        module = sys.modules.get(name)
        if module and not Path(module.__file__).resolve().is_relative_to(target):
            raise RuntimeError("target module contamination; use a fresh interpreter")
    sys.path.insert(0, str(target))
    api = importlib.import_module("cerberus")
    if not Path(api.__file__).resolve().is_relative_to(target):
        raise RuntimeError("wrong target implementation imported")
    return api


def valid_receipt(receipt: dict, request: dict) -> bool:
    return (receipt.get("status") == "simulated" and receipt.get("side_effects") is False
            and all(receipt.get(key) == request[key] for key in ("action", "target", "scope")))


def issue_request(decision) -> dict:
    return {"action": decision.authorized_action, "target": decision.target, "scope": decision.scope}


def simulate(api, gateway, token: str, request: dict, now: datetime) -> str:
    try:
        receipt = gateway.authorize_and_simulate(token, **request, now=now)
    except api.EnforcementDenied:
        return "blocked"
    if not valid_receipt(receipt, request):
        raise RuntimeError("unexpected or side-effecting receipt")
    return "accepted"


def gateway_worker(target: Path) -> None:
    api = load_target(target)
    data = json.load(sys.stdin)
    now = datetime.fromisoformat(data["now"].replace("Z", "+00:00"))
    gateway = api.EnforcementGateway(api.DecisionTokenSigner(TEST_KEY))
    result = simulate(api, gateway, data["token"], data["request"], now)
    print(json.dumps({"probe": result}))


def grade(case: dict, observation: dict) -> dict:
    """Pure oracle: errors stay visible and never count as successful defenses."""
    is_probe = case["kind"] in {"gateway", "lifecycle"}
    outcomes = {"accepted", "blocked"} if is_probe else {"approve", "deny", "escalate", "reject"}
    if (observation.get("error") or observation.get("outcome") not in outcomes
            or (is_probe and not observation.get("precondition_met", False))):
        return {"expected_met": False, "measurement_valid": False,
                "unauthorized_approval": None, "unauthorized_receipt": None}
    expected = case["expected"]
    approved = observation.get("token_valid", False)
    outcome = observation["outcome"]
    if case["kind"] in {"gateway", "lifecycle"}:
        met = observation.get("precondition_met", False) and outcome == "blocked"
        return {"expected_met": met, "measurement_valid": True,
                "unauthorized_approval": None,
                "unauthorized_receipt": observation.get("precondition_met", False) and outcome == "accepted"}
    if expected == "approve":
        met = approved and outcome == "approve" and observation.get("exact_binding", False)
        met = met and observation.get("simulated_receipts", 0) == 1
    elif expected == "withhold":
        met = outcome in {"reject", "deny", "escalate"} and not approved
    else:
        met = outcome == expected and not approved
    return {"expected_met": met, "measurement_valid": True,
            "unauthorized_approval": approved if case["kind"] == "unsafe" else None,
            "unauthorized_receipt": (observation.get("simulated_receipts", 0) > 0)
                if case["kind"] in {"unsafe", "benign", "review"} else None}


def observe(api, policies: dict, corpus: dict, case: dict, target: Path) -> dict:
    raw = make_payload(corpus, case)
    now = datetime.fromisoformat(corpus["now"].replace("Z", "+00:00"))
    obs = {"input_sha256": digest(canonical(raw)), "token_valid": False,
           "simulated_receipts": 0, "exact_binding": False, "outcome": "not_run"}
    try:
        try:
            envelope = api.ActionEnvelope.from_dict(raw)
        except api.ValidationError as exc:
            obs.update(outcome="reject", reason=str(exc))
            if case["kind"] in {"gateway", "lifecycle"}:
                raise RuntimeError("probe could not establish its valid-input precondition") from exc
            return obs
        signer = api.DecisionTokenSigner(TEST_KEY)
        guardian = api.Guardian(deepcopy(policies), signer=signer)
        decision = guardian.evaluate(envelope, now=now)
        obs.update(outcome=decision.guardian_decision, reason=decision.reason,
                   action=decision.authorized_action, scope=decision.scope,
                   policy=decision.policy)
        if decision.decision_token is not None:
            signed = signer.verify(decision.decision_token, now=now)
            obs["token_valid"] = True
            obs["exact_binding"] = all(signed.get(key) == raw[key] for key in ("action", "target", "scope"))
            obs["exact_binding"] = obs["exact_binding"] and (
                type(signed.get("reversible")) is bool
                and signed["reversible"] is raw["reversibility_flag"])

        operation = case.get("operation", "evaluate")
        if operation == "evaluate":
            if obs["token_valid"]:
                probe = simulate(api, api.EnforcementGateway(signer), decision.decision_token,
                                 issue_request(decision), now)
                obs["simulated_receipts"] = int(probe == "accepted")
            return obs

        if not obs["token_valid"] or not obs["exact_binding"] or decision.guardian_decision != "approve":
            raise RuntimeError("probe did not receive a valid exact authorization")
        obs["precondition_met"] = True
        request = issue_request(decision)
        token = decision.decision_token
        gateway = api.EnforcementGateway(signer)

        if operation.startswith("gateway_"):
            if operation == "gateway_action":
                request["action"] = "preserve_evidence"
            elif operation == "gateway_target":
                request["target"] = "sandbox:unauthorized-other-target"
            elif operation == "gateway_scope":
                request["scope"] = "enterprise"
            elif operation == "gateway_signature":
                body, signature = token.split(".", 1)
                signature = ("A" if signature[0] != "A" else "B") + signature[1:]
                token = body + "." + signature
            elif operation == "gateway_expiry":
                now += timedelta(seconds=121)
            else:
                raise ValueError(f"unknown operation: {operation}")
            obs["outcome"] = simulate(api, gateway, token, request, now)
            obs["simulated_receipts"] = int(obs["outcome"] == "accepted")
            return obs

        if simulate(api, gateway, token, request, now) != "accepted":
            raise RuntimeError("first authorized action failed; replay probe is invalid")
        obs["simulated_receipts"] = 1
        if operation == "replay_same_gateway":
            probe = simulate(api, gateway, token, request, now)
        elif operation == "replay_new_gateway":
            probe = simulate(api, api.EnforcementGateway(signer), token, request, now)
        elif operation == "replay_new_process":
            child = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--target", str(target), "--gateway-worker"],
                input=json.dumps({"token": token, "request": request, "now": timestamp(now)}),
                text=True, capture_output=True, timeout=30, check=True,
            )
            probe = json.loads(child.stdout)["probe"]
            if probe not in {"accepted", "blocked"}:
                raise RuntimeError("invalid worker result")
        elif operation in {"repeat_same_guardian", "repeat_new_guardian"}:
            second_guardian = guardian if operation == "repeat_same_guardian" else api.Guardian(deepcopy(policies), signer=signer)
            second = second_guardian.evaluate(envelope, now=now)
            obs["second_decision"] = second.guardian_decision
            probe = "blocked"
            if second.decision_token is not None:
                signer.verify(second.decision_token, now=now)
                probe = simulate(api, gateway, second.decision_token, issue_request(second), now)
        else:
            raise ValueError(f"unknown operation: {operation}")
        obs["outcome"] = probe
        obs["simulated_receipts"] += int(probe == "accepted")
        return obs
    except Exception as exc:
        obs["error"] = f"{type(exc).__name__}: {exc}"
        obs["outcome"] = "error"
        return obs


def ratio(numerator: int, denominator: int, errors: int = 0) -> dict:
    return {"numerator": numerator, "denominator": denominator, "errors": errors,
            "rate": numerator / denominator if denominator and not errors else None}


def summarize(rows: list[dict]) -> dict:
    groups = defaultdict(list)
    for row in rows:
        groups[(row["kind"], row["family"], row["basis"])].append(row)
    family = []
    for (kind, name, basis), group in groups.items():
        errors = sum(not x["measurement_valid"] for x in group)
        metric = "unauthorized_approval" if kind == "unsafe" else "unauthorized_receipt"
        family.append({"kind": kind, "family": name, "basis": basis,
                       "cases": len(group), "expected_met": sum(x["expected_met"] for x in group),
                       "violations": sum(x.get(metric) is True for x in group), "errors": errors})
    unsafe = [x for x in rows if x["kind"] == "unsafe"]
    valid = [x for x in rows if x["kind"] == "valid"]
    benign = [x for x in rows if x["kind"] == "benign"]
    probe = [x for x in rows if x["kind"] in {"gateway", "lifecycle"}]
    return {
        "total_cases": len(rows), "expected_met": sum(x["expected_met"] for x in rows),
        "measurement_errors": sum(not x["measurement_valid"] for x in rows),
        "unsafe_authorization": ratio(sum(x["unauthorized_approval"] is True for x in unsafe), len(unsafe), sum(not x["measurement_valid"] for x in unsafe)),
        "eligible_response_success": ratio(sum(x["expected_met"] for x in valid), len(valid), sum(not x["measurement_valid"] for x in valid)),
        "benign_disruption_proxy": ratio(sum(x["token_valid"] for x in benign), len(benign), sum(not x["measurement_valid"] for x in benign)),
        "benign_review_rate": ratio(sum(x["outcome"] == "escalate" for x in benign), len(benign), sum(not x["measurement_valid"] for x in benign)),
        "unsafe_probe_receipts": ratio(sum(x["unauthorized_receipt"] is True for x in probe), len(probe), sum(not x["measurement_valid"] for x in probe)),
        "families": family,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=Path, help="Clean Git checkout of the target implementation")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--gateway-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--fail-on-violation", action="store_true")
    args = parser.parse_args()
    target = args.target.resolve()
    if args.gateway_worker:
        gateway_worker(target)
        return 0
    if args.output is None:
        parser.error("--output is required")
    corpus = load_corpus()
    cases = corpus["cases"]
    if args.case_ids:
        known = {case["id"] for case in cases}
        if set(args.case_ids) - known:
            parser.error("unknown case ID")
        cases = [case for case in cases if case["id"] in args.case_ids]
    metadata = target_metadata(target)
    policies = json.loads((target / "policies/policies.json").read_text())
    if policies["version"] != corpus["policy_version"]:
        raise ValueError("benchmark requires its frozen policy version; do not silently update the oracle")
    api = load_target(target)
    rows = []
    for case in cases:
        obs = observe(api, policies, corpus, case, target)
        rows.append({key: case[key] for key in ("id", "kind", "family", "basis", "expected", "description")} | obs | grade(case, obs))
    summary = summarize(rows)
    packages = {}
    for name in ("jsonschema", "rfc3339-validator"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = "not installed"
    result = {"benchmark_version": corpus["benchmark_version"], "corpus_sha256": digest(CASE_FILE.read_bytes()),
              "runner_sha256": digest(Path(__file__).read_bytes()), "target": metadata,
              "environment": {"python": platform.python_version(), "packages": packages},
              "clock": corpus["now"], "selection": corpus["selection"], "complete_corpus": not bool(args.case_ids),
              "rate_interpretation": "Exact fractions of purposively selected cases, not population estimates. No IID confidence intervals or overall security score.",
              "summary": summary, "cases": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    if summary["measurement_errors"]:
        return 2
    return int(args.fail_on_violation and summary["expected_met"] != summary["total_cases"])


if __name__ == "__main__":
    raise SystemExit(main())
