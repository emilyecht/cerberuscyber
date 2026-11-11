# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Instrument tests do not relax the frozen oracle or repair target pins."""
from copy import deepcopy

import pytest

from benchmarks.replay_v4 import run as v4
from cerberus.assurance import AssuranceError


@pytest.fixture(scope="module")
def instrument():
    oracle, preservation = v4.frozen_inputs()
    assert preservation["source_diff_stat"] == ""
    assert preservation["historical_diff_stat"] == ""
    return v4.Instrument(oracle)


def case(ins, name):
    return next(c for c in ins.oracle["cases"] if c["id"] == name)


def test_all_frozen_mutation_guards_and_exact_denominators(instrument):
    rows = [c for c in instrument.oracle["cases"] if c["family"] == "W"]
    assert len(rows) == 725
    assert sum(c["identity_guard"]["canonical_bytes_equal"] for c in rows) == 100
    assert len({c["parent_cluster"] for c in rows}) == 25
    assert sum(len(c["attempts"]) for c in instrument.oracle["cases"]) == 1100


def test_candidate_cannot_broaden_operator_allowlist(instrument):
    ref = "S-001"
    raw = deepcopy(instrument.oracle["templates"][ref]["envelope"])
    raw["target"] += ":not-allowlisted"
    env, verifier, proofs = instrument.get_material(ref, raw)
    with pytest.raises(AssuranceError, match="not authorized"):
        verifier.verify(env, proofs, now=instrument.now)


def test_duplicate_prefix_is_retained(instrument):
    rows = v4.episode(instrument, case(instrument,"U-R-001"))
    assert [r["systems"]["cerberus"]["decision"] for r in rows] == ["allow","deny"]
    assert rows[0]["systems"]["cerberus"]["execution_claim_added"]
    assert not rows[1]["systems"]["cerberus"]["execution_claim_added"]
    assert rows[1]["systems"]["cerberus"]["state_after"] == rows[0]["systems"]["cerberus"]["state_after"]


def test_unexpected_crash_is_invalid_measurement(instrument, monkeypatch):
    def crash(*a, **k):
        raise RuntimeError("instrument-test injected unexpected failure")
    monkeypatch.setattr(v4.World,"start",crash)
    rows = v4.episode(instrument,case(instrument,"S-001"))
    assert not rows[0]["systems"]["cerberus"]["measurement_valid"]
    metric = v4.summarize(rows,"cerberus")
    assert metric["measurement_errors"] == 1
    assert metric["false_allows"]["denominator"] == 0
    assert metric["correct"] == 0


def test_unsafe_receipt_always_mutates_and_fails_grading(instrument,monkeypatch):
    c = case(instrument,"W-0002")
    world = v4.World(instrument,c)
    try:
        world.start()
        payload = world.payload
        # An intentionally defective gateway returns a receipt for the original
        # grant after a different candidate is submitted. Observers must retain it.
        forged = {k:payload[k] for k in ("token_id","envelope_id","envelope_digest","idempotency_key",
            "actor","incident_id","policy_version","policy_digest","action","target","scope")}
        forged.update(status="simulated",side_effects=False,executed_at=instrument.oracle["clock"],audit_record_hash="fake")
        monkeypatch.setattr(world.gateway,"authorize_and_simulate",lambda *a,**k:forged)
        row = v4.observe(world,0)
        obs = row["systems"]["cerberus"]
        assert obs["symbolic_writes"] == 1
        assert obs["state_after"][payload["target"]]["writes"] == 1
        assert "OUT_OF_SCOPE_SIMULATOR_MUTATION" in obs["violations"]
        assert v4.summarize([row],"cerberus")["false_allows"]["numerator"] == 1
    finally:
        world.close()


def test_baselines_are_unchanged_calls(instrument):
    c = case(instrument,"U-C-001")
    raw = v4.request_for(instrument,c,c["attempts"][0])
    now = v4.parse(c["execute_at"])
    rows = v4.baseline(instrument,c,raw,now)
    assert rows["allow_if_recommended"]["decision"] == "allow"
    assert rows["confidence_0.9"]["decision"] == "allow"
    assert rows["soar_b2"]["decision"] == "deny"
    assert all(r["effects_measured"] is False for r in rows.values())
