"""Run a trust-aware comparison in a clean target interpreter; simulated effects only."""

import argparse
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime

HERE = Path(__file__).resolve().parent
TEST_KEY = b"public-assurance-benchmark-v2-test-key-material-32-bytes"


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_api(target):
    sys.path.insert(0, str(target))
    api = importlib.import_module("cerberus")
    if not Path(api.__file__).resolve().is_relative_to(target):
        raise RuntimeError("wrong target imported")
    if api.DecisionTokenSigner.TOKEN_VERSION not in {"1.1.0", "1.2.0"}:
        raise RuntimeError("unsupported target interface")
    return api


def assured(api):
    return api.DecisionTokenSigner.TOKEN_VERSION == "1.2.0"


def verifier(api, configuration):
    def objects(kind, cls):
        return tuple(cls(**(dict(item) | {"public_key": bytes.fromhex(item["public_key"])})) for item in configuration[kind])
    return api.AssuranceVerifier(
        evidence_authorities=objects("evidence_authorities", api.EvidenceAuthority),
        approval_authorities=objects("approval_authorities", api.ApprovalAuthority),
        revoked_key_ids=frozenset(configuration["revoked_key_ids"]),
    )


def decide(api, policies, case, now, state_path, *, create=False):
    signer = api.DecisionTokenSigner(TEST_KEY)
    envelope = api.ActionEnvelope.from_dict(case["request"])
    kwargs, evaluate_kwargs = {}, {}
    if assured(api):
        kwargs = {
            "assurance_verifier": verifier(api, case["trust_configuration"]),
            "idempotency_registry": api.SQLiteStateStore(state_path, create=create),
        }
        evaluate_kwargs["assurance"] = api.AssuranceBundle.from_dict(case["assurance"])
    return api.Guardian(policies, signer=signer, **kwargs).evaluate(envelope, now=now, **evaluate_kwargs)


def gateway(api, path):
    kwargs = {"replay_cache": api.SQLiteStateStore(path)} if assured(api) else {}
    return api.EnforcementGateway(api.DecisionTokenSigner(TEST_KEY), **kwargs)


def submit(api, instance, token, request, now):
    try:
        receipt = instance.authorize_and_simulate(token, **{k: request[k] for k in ("action", "target", "scope")}, now=now)
    except api.EnforcementDenied as exc:
        return {"outcome": "blocked", "reason": str(exc), "receipt": None}
    if receipt.get("status") != "simulated" or receipt.get("side_effects") is not False or any(receipt.get(k) != request[k] for k in ("action", "target", "scope")):
        raise RuntimeError("invalid or mismatched simulated receipt")
    return {"outcome": "accepted", "receipt": receipt}


def run_request(api, policies, case, now, path):
    if digest(canonical(case["request"])) != case["input_sha256"]:
        raise RuntimeError("input hash mismatch")
    decision = decide(api, policies, case, now, path, create=True)
    token_valid, exact, receipt = False, False, None
    if decision.decision_token:
        payload = api.DecisionTokenSigner(TEST_KEY).verify(decision.decision_token, now=now)
        token_valid = True
        exact = all(payload[k] == case["request"][k] for k in ("action", "target", "scope", "idempotency_key")) and payload["envelope_digest"] == case["input_sha256"]
        action = submit(api, gateway(api, path), decision.decision_token, case["request"], now)
        if action["outcome"] != "accepted":
            raise RuntimeError("first authorized submission unexpectedly blocked")
        receipt = action["receipt"]
    expected = case["definition"]["expected"]
    met = (decision.guardian_decision == "approve" and token_valid and exact and receipt is not None) if expected == "approve" else (decision.guardian_decision in {"deny", "escalate", "reject"} and not token_valid and receipt is None)
    return {
        "id": case["definition"]["id"], "kind": case["definition"]["kind"],
        "family": case["definition"]["family"], "expected": expected,
        "input_sha256": case["input_sha256"], "outcome": decision.guardian_decision,
        "reason": decision.reason, "policy": decision.policy,
        "token_valid": token_valid, "exact_binding": exact,
        "simulated_receipts": int(receipt is not None), "receipt": receipt,
        "expected_met": met, "measurement_valid": True,
    }


def run_lifecycle(api, target, policies, case, now, path, mode):
    first = decide(api, policies, case, now, path, create=True)
    if first.guardian_decision != "approve" or not first.decision_token:
        raise RuntimeError("lifecycle positive setup did not authorize")
    api.DecisionTokenSigner(TEST_KEY).verify(first.decision_token, now=now)
    initial_gateway = gateway(api, path)
    initial = submit(api, initial_gateway, first.decision_token, case["request"], now)
    if initial["outcome"] != "accepted":
        raise RuntimeError("lifecycle positive setup did not execute")
    if mode == "new_gateway":
        second = submit(api, gateway(api, path), first.decision_token, case["request"], now)
    elif mode == "new_process":
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--gateway-worker", "--target", str(target)],
            input=json.dumps({"token": first.decision_token, "request": case["request"], "now": now.isoformat(), "path": str(path)}),
            text=True, capture_output=True, check=True,
        )
        second = json.loads(result.stdout)
    else:
        renewed = decide(api, policies, case, now, path)
        if renewed.guardian_decision in {"deny", "escalate"} and not renewed.decision_token:
            second = {"outcome": "blocked", "reason": renewed.reason, "receipt": None}
        elif renewed.guardian_decision == "approve" and renewed.decision_token:
            second = submit(api, initial_gateway, renewed.decision_token, case["request"], now)
        else:
            raise RuntimeError("invalid reauthorization observation")
    return {
        "id": mode, "kind": "lifecycle", "initial": initial, "second": second,
        "precondition_met": True, "measurement_valid": True,
        "additional_receipts": int(second["receipt"] is not None),
        "expected_met": second["outcome"] == "blocked",
    }


def measure(target):
    api = load_api(target)
    corpus = json.loads((HERE / "cases.json").read_text())
    policies = json.loads((target / "policies/policies.json").read_text())
    now = datetime.fromisoformat(corpus["now"].replace("Z", "+00:00"))
    rows = []
    with tempfile.TemporaryDirectory(prefix="cerberus-v2-") as temporary:
        directory = Path(temporary)
        for case in corpus["cases"]:
            try:
                row = run_request(api, policies, case, now, directory / (case["definition"]["id"] + ".db"))
            except Exception as exc:
                row = {"id": case["definition"]["id"], "measurement_valid": False, "expected_met": False, "error": f"{type(exc).__name__}: {exc}"}
            rows.append(row)
        control = next(c for c in corpus["cases"] if c["definition"]["id"] == "V01")
        for mode in ("new_gateway", "new_process", "new_guardian"):
            try:
                row = run_lifecycle(api, target, policies, control, now, directory / (mode + ".db"), mode)
            except Exception as exc:
                row = {"id": mode, "measurement_valid": False, "expected_met": False, "error": f"{type(exc).__name__}: {exc}"}
            rows.append(row)
    errors = sum(not r["measurement_valid"] for r in rows)
    git = lambda *args: subprocess.check_output(["git", "-C", str(target), *args], text=True).strip()
    if git("status", "--porcelain", "--untracked-files=all", "--", "cerberus", "sdk", "policies", "schemas", ":(exclude)**/__pycache__/**"):
        raise RuntimeError("target production sources must be committed before measurement")
    files = git("ls-files", "cerberus", "sdk", "policies", "schemas").splitlines()
    hashes = {p: digest((target / p).read_bytes()) for p in files}
    return {
        "benchmark": "assurance-boundaries-v3", "now": corpus["now"],
        "target_commit": git("rev-parse", "HEAD"), "target_tree": git("rev-parse", "HEAD^{tree}"),
        "production_source_sha256": digest(canonical(hashes)), "production_files": hashes,
        "policy_sha256": digest((target / "policies/policies.json").read_bytes()),
        "corpus_sha256": digest((HERE / "cases.json").read_bytes()),
        "runner_sha256": digest(Path(__file__).read_bytes()),
        "interface": "authenticated-sidecar-and-shared-SQLite" if assured(api) else "v1.1-raw-envelope-and-default-memory",
        "limits": "New project-authored trust fixtures; same 19 envelope values as v1. Legacy target ignores sidecars and uses its default memory state. Simulated effects only; no independent, continuous or adaptive evaluation.",
        "summary": {
            "cases": len(rows), "measurement_errors": errors,
            "unsafe_authorizations": None if errors else sum(r.get("kind") == "unsafe" and r.get("token_valid", False) for r in rows),
            "unsafe_requests": 11,
            "eligible_successes": None if errors else sum(r.get("kind") == "valid" and r["expected_met"] for r in rows),
            "eligible_requests": 8,
            "duplicate_effects": None if errors else sum(r.get("additional_receipts", 0) for r in rows),
            "lifecycle_episodes": 3,
        },
        "observations": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--gateway-worker", action="store_true")
    parser.add_argument("--fail-on-violation", action="store_true")
    args = parser.parse_args()
    target = args.target.resolve()
    if args.gateway_worker:
        data = json.load(sys.stdin)
        api = load_api(target)
        print(json.dumps(submit(api, gateway(api, data["path"]), data["token"], data["request"], datetime.fromisoformat(data["now"])) ))
        return
    if args.worker:
        print(json.dumps(measure(target)))
        return
    if args.output is None:
        parser.error("--output is required")
    worker = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--target", str(target), "--worker"], text=True, capture_output=True, check=True)
    result = json.loads(worker.stdout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"]))
    if result["summary"]["measurement_errors"]:
        raise SystemExit(2)
    if args.fail_on_violation and not all(r["expected_met"] for r in result["observations"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
