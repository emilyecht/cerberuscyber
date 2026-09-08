"""Exercise every carried-forward assurance request using actual proof verification."""

from datetime import datetime
import hashlib
import json
from pathlib import Path

import pytest
import cerberus

from benchmarks.assurance_boundaries_v2.prepare import build
from benchmarks.assurance_boundaries_v2.run import canonical, run_request

ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / "benchmarks/assurance_boundaries_v2/cases.json").read_text())
POLICIES = json.loads((ROOT / "policies/policies.json").read_text())
NOW = datetime.fromisoformat(CORPUS["now"].replace("Z", "+00:00"))


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["definition"]["id"])
def test_each_assurance_request_and_genuine_control(case, tmp_path):
    assert hashlib.sha256(canonical(case["request"])).hexdigest() == case["input_sha256"]
    result = run_request(cerberus, POLICIES, case, NOW, tmp_path / "case.db")
    assert result["measurement_valid"]
    assert result["expected_met"], result
    if case["definition"]["kind"] == "valid":
        assert result["token_valid"] and result["exact_binding"]
        assert result["simulated_receipts"] == 1
    else:
        assert not result["token_valid"] and result["simulated_receipts"] == 0


def test_prepared_proofs_reproduce_from_the_recorded_external_facts():
    assert build() == CORPUS
    assert len([c for c in CORPUS["cases"] if c["definition"]["kind"] == "unsafe"]) == 11
    assert len([c for c in CORPUS["cases"] if c["definition"]["kind"] == "valid"]) == 8


def test_a_deny_everything_boundary_fails_the_eligible_controls(tmp_path):
    class RejectingGuardian(cerberus.Guardian):
        def evaluate(self, envelope, **kwargs):
            return self._finalize(envelope, decision="deny", reason="instrument negative control", policy_id=None)
    class API:
        Guardian = RejectingGuardian
        def __getattr__(self, name):
            return getattr(cerberus, name)
    case = next(c for c in CORPUS["cases"] if c["definition"]["kind"] == "valid")
    result = run_request(API(), POLICIES, case, NOW, tmp_path / "deny-all.db")
    assert result["measurement_valid"] and not result["expected_met"]


def test_an_instrument_error_does_not_become_a_successful_defense(tmp_path):
    class BrokenGuardian(cerberus.Guardian):
        def evaluate(self, *args, **kwargs):
            raise RuntimeError("instrument fault")
    class API:
        Guardian = BrokenGuardian
        def __getattr__(self, name):
            return getattr(cerberus, name)
    with pytest.raises(RuntimeError, match="instrument fault"):
        run_request(API(), POLICIES, CORPUS["cases"][0], NOW, tmp_path / "error.db")
