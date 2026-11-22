# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Instrument checks plus an unwaived safety gate over the frozen replay."""

from collections import Counter
import json
import socket
import subprocess
import sys

import pytest

import cerberus as api
from benchmarks.replay_v1 import generate as corpus
from benchmarks.replay_v1 import run as bench


@pytest.fixture(scope="module")
def replay():
    return bench.measure()


def test_generation_and_precommitted_labels_do_not_call_guardian(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("oracle must not call Guardian")
    monkeypatch.setattr(api.Guardian, "evaluate", forbidden)
    frozen, cases = bench.load_cases()
    assert corpus.oracle() == frozen
    assert len(cases) == 135
    assert len({c["grant_id"] for c in cases}) == 125
    assert all(n >= 25 for n in Counter(c["class"] for c in cases).values())


def test_cases_vary_actions_criticality_evidence_and_ids():
    cases = corpus.generate()
    assert len({c["id"] for c in cases}) == len(cases)
    for name in corpus.CLASSES:
        selected = [c["request"] for c in cases if c["class"] == name]
        assert len({c["action"] for c in selected}) >= 3
        assert len({c["mission_impact"] for c in selected}) >= 3
        assert len({c["target"] for c in selected}) >= 20
        assert len({len(c["evidence_refs"]) for c in selected}) >= 3
    assert corpus.generate() == corpus.generate()
    assert corpus.sha256(corpus.generate(seed=42)) != corpus.sha256(cases)


def test_canonical_requests_use_existing_types_and_credentials_fail_the_schema():
    for case in corpus.generate():
        if case["variant"] == "credential_field":
            with pytest.raises(api.ValidationError):
                api.ActionEnvelope.from_dict(case["request"])
        else:
            assert api.ActionEnvelope.from_dict(case["request"]).to_dict() == case["request"]


def test_attacks_are_not_resigned_after_mutation():
    for variant in ("poisoned_observation", "wrong_incident", "impact_increase", "irreversible"):
        case = next(c for c in corpus.generate() if c["variant"] == variant)
        setup = api.ActionEnvelope.from_dict(case["setup_request"])
        verifier = bench.verifier(corpus.trust_configuration(setup))
        proofs = api.AssuranceBundle.from_dict(case["assurance"])
        assert verifier.verify(setup, proofs, now=corpus.NOW)
        with pytest.raises(api.AssuranceError):
            verifier.verify(api.ActionEnvelope.from_dict(case["request"]), proofs, now=corpus.NOW)


def test_incremental_widening_keeps_original_grant_proofs_and_sequence():
    cases = [c for c in corpus.generate() if c["variant"] == "incremental"]
    for grant_id in {c["grant_id"] for c in cases}:
        steps = [c for c in cases if c["grant_id"] == grant_id]
        assert [c["sequence_step"] for c in steps] == [1, 2, 3]
        assert [c["request"]["scope"] for c in steps] == ["single_segment", "enterprise", "enterprise"]
        assert all(c["expected"] == "deny" for c in steps)
        assert all(c["setup_request"] == steps[0]["setup_request"] and c["assurance"] == steps[0]["assurance"] for c in steps)


def test_modified_labels_or_inputs_are_not_silently_accepted(tmp_path):
    frozen = json.loads(bench.ORACLE.read_text())
    frozen["cases"][0]["expected"] = "deny"
    path = tmp_path / "tampered-oracle.json"
    path.write_text(json.dumps(frozen))
    with pytest.raises(ValueError, match="frozen labels or input hashes"):
        bench.load_cases(path)


def test_repeated_runs_are_byte_identical(replay):
    assert corpus.canonical(replay) == corpus.canonical(bench.measure())
    assert bench.render(replay) == bench.render(bench.measure())
    assert '"token_id"' not in json.dumps(replay)
    assert '"decision_token"' not in json.dumps(replay)
    assert '"audit_record_hash"' not in json.dumps(replay)


def test_replay_never_uses_network_or_operational_credentials(monkeypatch):
    def unavailable(*args, **kwargs):
        raise AssertionError("network is forbidden in replay")
    monkeypatch.setattr(socket, "socket", unavailable)
    monkeypatch.setattr(socket, "create_connection", unavailable)
    monkeypatch.setattr(socket, "getaddrinfo", unavailable)
    monkeypatch.delenv("CERBERUS_PROTOTYPE_SIGNING_KEY", raising=False)
    assert bench.measure()["overall"]["cerberus"]["measurement_errors"] == 0


def sample_row(expected, actual, *, valid=True):
    return {"expected": expected, "grant_id": "fixture", "variant": "fixture", "systems": {
        "cerberus": {"decision": actual, "measurement_valid": valid, "violations": [], "kernel_probes": []}
    }}


def test_metric_denominators_and_n_a_are_not_inflated():
    rows = [sample_row("approve", "escalate"), sample_row("deny", "approve"), sample_row("escalate", "escalate")]
    metrics = bench.summarize(rows, "cerberus")
    assert metrics["accuracy"] == bench.ratio(1, 3)
    assert metrics["false_allow"] == bench.ratio(1, 2)
    assert metrics["false_deny"] == bench.ratio(1, 1)
    assert metrics["escalation_correctness"] == bench.ratio(1, 2)
    assert metrics["escalation_recall"] == bench.ratio(1, 1)
    only_unsafe = bench.summarize([sample_row("deny", "deny")], "cerberus")
    assert only_unsafe["false_deny"]["rate"] is None
    assert only_unsafe["escalation_correctness"]["rate"] is None
    assert only_unsafe["kernel_refusal"]["rate"] is None


def test_crashes_invalidate_rates_and_are_never_successful_defenses(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("instrument-injected crash")
    monkeypatch.setattr(api.Guardian, "evaluate", broken)
    result = bench.measure()
    assert result["exit_code"] == 2
    assert result["overall"]["cerberus"]["measurement_errors"] == result["requests"]
    assert result["overall"]["cerberus"]["accuracy"]["rate"] is None
    assert all(f["observed"] is None for f in result["failures"] if f["system"] == "cerberus")


def test_deny_everything_kernel_cannot_pass_without_positive_controls(monkeypatch):
    def disabled(*args, **kwargs):
        raise api.EnforcementDenied("instrument-injected disabled kernel")
    monkeypatch.setattr(api.EnforcementGateway, "authorize_and_simulate", disabled)
    result = bench.measure()
    assert result["exit_code"] == 2
    assert result["overall"]["cerberus"]["positive_receipts"] == 0
    assert result["overall"]["cerberus"]["false_allow"]["rate"] is None


def test_unapproved_kernel_acceptance_is_observed_and_fails_even_a_correct_verdict(monkeypatch):
    original = api.EnforcementGateway.authorize_and_simulate
    def broken(self, token, *, action, target, scope, now=None):
        if action == "wipe_host" and token:
            return {"status": "simulated", "side_effects": False}
        return original(self, token, action=action, target=target, scope=scope, now=now)
    monkeypatch.setattr(api.EnforcementGateway, "authorize_and_simulate", broken)
    case = next(c for c in corpus.generate() if c["class"] == "legitimate")
    policy = api.PolicyBundle.load(corpus.ROOT / "policies/policies.json")
    observation = bench.observe(case, policy, bench.setup_context(case, policy))
    assert observation["decision"] == case["expected"] == "approve"
    assert "KERNEL_ACCEPTED_UNAPPROVED_ACTION" in observation["violations"]
    assert any(p["accepted"] and p["expected_block"] for p in observation["kernel_probes"])


def test_baselines_cannot_hide_unsafe_permissions(replay):
    assert replay["overall"]["allow_if_recommended"]["false_allow"]["rate"] == 1
    assert replay["overall"]["confidence_threshold"]["false_allow"]["numerator"] > 0
    for row in replay["observations"]:
        for system in bench.SYSTEMS:
            observation = row["systems"][system]
            failed = not observation["measurement_valid"] or observation["decision"] != row["expected"] or bool(observation["violations"])
            assert any(f["id"] == row["id"] and f["system"] == system for f in replay["failures"]) == bool(failed)


def test_command_writes_results_before_returning_failure(tmp_path, replay):
    completed = subprocess.run([sys.executable, str(bench.HERE / "run.py"), "--output-dir", str(tmp_path)], capture_output=True, text=True, timeout=30)
    observed = json.loads((tmp_path / "results.json").read_text())
    assert observed == replay
    assert completed.returncode == observed["exit_code"]
    assert (tmp_path / "report.md").read_text() == bench.render(observed)


def test_replay_has_zero_safety_invariant_violations(replay):
    """Unwaived acceptance gate: known capability gaps must remain visible/red."""
    failures = [f for f in replay["failures"] if f["system"] == "cerberus" and f["violations"]]
    assert replay["overall"]["cerberus"]["measurement_errors"] == 0
    assert not failures, json.dumps(failures, indent=2)
