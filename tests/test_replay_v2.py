# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""The strict pipeline is gated independently of the immutable historical FAIL."""

from contextlib import contextmanager
import itertools
import json
import socket
import subprocess
import sys

import pytest

import cerberus as api
from benchmarks.replay_v2 import run as bench


@pytest.fixture(scope="module")
def replay():
    return bench.measure_functional()


def test_full_pipeline_has_no_unsafe_authorizations_or_new_false_denies(replay):
    result, _, _ = replay
    assert result["overall"]["cerberus"]["measurement_errors"] == 0
    assert result["overall"]["cerberus"]["accuracy"] == bench.v1.ratio(135, 135)
    assert result["overall"]["cerberus"]["false_allow"] == bench.v1.ratio(0, 110)
    assert result["overall"]["cerberus"]["false_deny"] == bench.v1.ratio(0, 25)
    assert result["overall"]["cerberus"]["safety_invariant_violations"] == 0
    assert result["guardian_changes"] == []
    assert result["baseline_changes"] == []
    assert result["new_false_denies"] == []
    assert result["exit_code"] == 0


def test_v1_inputs_scoring_and_recorded_failure_are_unchanged(replay):
    result, _, _ = replay
    assert result["v1_oracle_sha256"] == result["v2_oracle_sha256"] == bench.ORACLE_HASH
    assert result["v1_corpus_sha256"] == result["v2_corpus_sha256"] == bench.CORPUS_HASH
    assert result["source_preservation"]["v1_git_diff_stat"] == ""
    assert result["v1_comparison"]["overall"]["v1"]["false_allow"] == bench.v1.ratio(16, 110)
    assert result["v1_comparison"]["overall"]["v1"]["safety_invariant_violations"] == 29


def test_symbolic_state_changes_are_observed_and_in_scope(replay):
    result, _, _ = replay
    assert result["simulator_state"]["overall"] == {"total": 25, "authorized": 25, "out_of_scope": 0}
    assert result["setup_control_mutations"] == 125
    observed = [e for r in result["observations"] for e in r["systems"]["cerberus"]["simulator_state"]["mutations"]]
    assert len(observed) == 25
    assert all(e["before"] != e["after"] and e["in_authorized_scope"] for e in observed)


def test_functional_observations_are_repeatable(replay):
    assert replay[0] == bench.measure_functional()[0]


def test_no_network_or_operational_credentials_are_needed(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network is forbidden")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.delenv("CERBERUS_PROTOTYPE_SIGNING_KEY", raising=False)
    assert bench.measure_functional()[0]["exit_code"] == 0


def test_missing_binding_check_is_detected_without_editing_labels(monkeypatch):
    def unbound(self, payload, expected):
        return api.ActionEnvelope.from_dict(expected)
    monkeypatch.setattr(api.EnforcementGateway, "_bind_expected", unbound)
    result, _, _ = bench.measure_functional()
    assert result["overall"]["cerberus"]["false_allow"]["numerator"] > 0
    assert result["simulator_state"]["overall"]["out_of_scope"] > 0
    assert result["exit_code"] == 1
    assert result["guardian_changes"] == []


def test_missing_live_status_check_is_detected_without_editing_labels(monkeypatch):
    @contextmanager
    def unchecked(self, *args, **kwargs):
        yield
    monkeypatch.setattr(api.TokenAuthorityRegistry, "authorize", unchecked)
    result, _, _ = bench.measure_functional()
    assert result["overall"]["cerberus"]["false_allow"]["numerator"] > 0
    assert result["simulator_state"]["overall"]["out_of_scope"] > 0
    assert result["exit_code"] == 1


def test_broken_positive_controls_are_errors_not_safe_results(monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("instrument fault")
    monkeypatch.setattr(api.EnforcementGateway, "authorize_and_simulate", broken)
    result, _, _ = bench.measure_functional()
    assert result["overall"]["cerberus"]["measurement_errors"] == 135
    assert result["overall"]["cerberus"]["false_allow"]["rate"] is None
    assert result["exit_code"] == 2


def test_soar_b2_is_the_predeclared_scalar_gate(replay):
    _, cases, contexts = replay
    for variant in ("forbidden_recovery", "forbidden_outbound", "expired_token", "host_to_segment", "identity_to_group"):
        case = next(c for c in cases if c["variant"] == variant)
        assert bench.b2(case, contexts[case["grant_id"]])["decision"] == "deny"
    for variant in ("wrong_incident", "impact_increase", "irreversible", "revoked_issued_token"):
        case = next(c for c in cases if c["variant"] == variant)
        assert bench.b2(case, contexts[case["grant_id"]])["decision"] == "approve"
    assert replay[0]["overall"]["soar_b2"]["kernel_refusal"] is None


def test_latency_protocol_preserves_warmup_pairs_samples_and_percentiles(monkeypatch, replay):
    _, cases, contexts = replay
    clock = itertools.count(step=7)
    monkeypatch.setattr(bench, "perf_counter_ns", lambda: next(clock))
    monkeypatch.setattr(bench, "CLASSES", ("legitimate",))
    timing, raw = bench.measure_latency([cases[0]], contexts)
    assert timing["warmup_pairs_per_request"] == 20
    assert timing["measured_pairs_per_request"] == 100
    assert timing["measured_samples_per_gateway"] == 100
    assert raw[0]["v1_ns"] == raw[0]["v2_ns"] == [7] * 100
    assert raw[0]["paired_delta_ns"] == [0] * 100
    assert bench.percentiles(list(range(1, 101))) == {"p50_ns": 50, "p95_ns": 95, "max_ns": 100}
    assert bench.percentiles([-4, -3, -2, -1])["p50_ns"] == -3


def test_default_command_writes_full_comparison_latency_and_state(tmp_path, replay):
    completed = subprocess.run([sys.executable, str(bench.HERE / "run.py"), "--output-dir", str(tmp_path)],
        capture_output=True, text=True, timeout=180)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    observed = json.loads((tmp_path / "results.json").read_text())
    assert observed["observations"] == replay[0]["observations"]
    assert observed["latency"]["measured_samples_per_gateway"] == 13500
    assert len((tmp_path / "latency_samples.jsonl").read_text().splitlines()) == 135
    assert "v1 historical FAIL" in (tmp_path / "report.md").read_text()
    for key in ("v1_oracle_sha256", "v2_oracle_sha256", "v1_corpus_sha256", "v2_corpus_sha256"):
        assert key + ": " in completed.stdout
