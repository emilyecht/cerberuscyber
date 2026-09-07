"""Check the measuring instrument, including controls that prevent inflated scores."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "benchmarks/guardian_authorization_v1/run.py"
spec = importlib.util.spec_from_file_location("guardian_benchmark", SCRIPT)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def observation(**changes):
    return {"outcome": "approve", "token_valid": True, "exact_binding": True,
            "simulated_receipts": 1, **changes}


def test_deny_everything_cannot_pass_eligible_response_controls():
    corpus = bench.load_corpus()
    cases = [case for case in corpus["cases"] if case["kind"] == "valid"]
    assert cases
    for case in cases:
        result = bench.grade(case, observation(outcome="deny", token_valid=False, simulated_receipts=0))
        assert result["expected_met"] is False


def test_allow_everything_exposes_every_unsafe_authorization():
    corpus = bench.load_corpus()
    cases = [case for case in corpus["cases"] if case["kind"] == "unsafe"]
    assert cases
    for case in cases:
        result = bench.grade(case, observation())
        assert result["unauthorized_approval"] is True
        assert result["expected_met"] is False


@pytest.mark.parametrize("changes", [{"exact_binding": False}, {"simulated_receipts": 0}, {"token_valid": False}])
def test_eligible_response_requires_valid_token_exact_binding_and_receipt(changes):
    assert not bench.grade({"kind": "valid", "expected": "approve"}, observation(**changes))["expected_met"]


def test_crashes_are_not_credited_as_successful_defenses():
    case = {"id": "error", "kind": "unsafe", "family": "input_integrity", "basis": "existing_contract", "expected": "reject"}
    obs = observation(outcome="error", token_valid=False, simulated_receipts=0, error="unexpected crash")
    result = bench.grade(case, obs)
    assert result["measurement_valid"] is False
    assert result["expected_met"] is False
    assert result["unauthorized_approval"] is None
    summary = bench.summarize([{**case, **obs, **result}])
    assert summary["unsafe_authorization"]["denominator"] == 1
    assert summary["unsafe_authorization"]["rate"] is None
    assert summary["measurement_errors"] == 1


def test_gateway_denial_without_valid_precondition_is_not_a_pass():
    result = bench.grade({"kind": "gateway", "expected": "block"},
                         {"outcome": "blocked", "precondition_met": False})
    assert result["expected_met"] is False
    assert result["measurement_valid"] is False


def test_even_a_denied_decision_with_a_valid_token_is_an_authorization_leak():
    result = bench.grade({"kind": "unsafe", "expected": "withhold"}, observation(outcome="deny"))
    assert result["unauthorized_approval"] is True
    assert result["expected_met"] is False


def test_payload_generation_is_stable_and_does_not_mutate_the_oracle():
    corpus = bench.load_corpus()
    frozen = bench.canonical(corpus)
    first = [bench.make_payload(corpus, case) for case in corpus["cases"]]
    second = [bench.make_payload(corpus, case) for case in corpus["cases"]]
    assert first == second
    assert bench.canonical(corpus) == frozen
    assert len({value["idempotency_key"] for value in first}) == len(first)


@pytest.mark.parametrize("change", [{"side_effects": True}, {"side_effects": "false"}, {"target": "other"}, {"status": "executed"}])
def test_receipt_validation_rejects_real_effects_or_wrong_bindings(change):
    request = {"action": "isolate_endpoint", "target": "sandbox:test", "scope": "single_endpoint"}
    receipt = {**request, "status": "simulated", "side_effects": False, **change}
    assert not bench.valid_receipt(receipt, request)


def test_observed_engine_failure_is_reported_as_an_error(monkeypatch):
    import cerberus
    corpus = bench.load_corpus()
    case = next(case for case in corpus["cases"] if case["id"] == "V01")
    policies = json.loads((ROOT / "policies/policies.json").read_text())
    def broken_evaluate(*args, **kwargs):
        raise RuntimeError("injected engine failure")
    monkeypatch.setattr(cerberus.Guardian, "evaluate", broken_evaluate)
    obs = bench.observe(cerberus, policies, corpus, case, ROOT)
    assert obs["outcome"] == "error"
    assert "injected engine failure" in obs["error"]
    assert not bench.grade(case, obs)["measurement_valid"]


def test_fresh_process_probe_and_positive_control_use_actual_target(tmp_path):
    destination = tmp_path / "result.json"
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--target", str(ROOT), "--output", str(destination),
         "--case", "V01", "--case", "G08"], text=True, capture_output=True, timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(destination.read_text())
    rows = {case["id"]: case for case in result["cases"]}
    assert result["summary"]["measurement_errors"] == 0
    assert result["complete_corpus"] is False
    assert rows["V01"]["expected_met"] is True
    # This is a measurement test, not an assertion that replay must stay broken.
    assert rows["G08"]["precondition_met"] is True
    assert rows["G08"]["outcome"] in {"accepted", "blocked"}


def test_checked_in_comparison_uses_identical_cases_policy_and_runner():
    outputs = [json.loads((ROOT / f"results/guardian_authorization_v1/{name}.json").read_text())
               for name in ("baseline", "repaired")]
    before, after = outputs
    assert before["corpus_sha256"] == after["corpus_sha256"] == bench.digest(bench.CASE_FILE.read_bytes())
    assert before["runner_sha256"] == after["runner_sha256"] == bench.digest(SCRIPT.read_bytes())
    assert before["target"]["policy_sha256"] == after["target"]["policy_sha256"]
    assert [(x["id"], x["input_sha256"]) for x in before["cases"]] == [(x["id"], x["input_sha256"]) for x in after["cases"]]
    for result in outputs:
        assert result["complete_corpus"]
        assert result["summary"]["measurement_errors"] == 0
        assert result["summary"] == bench.summarize(result["cases"])
