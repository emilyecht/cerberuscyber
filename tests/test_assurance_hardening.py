"""Adversarial checks against the real Guardian, with trust frozen before mutation."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from cerberus import (
    ActionEnvelope, ApprovalProof, AssuranceBundle, AssuranceVerifier,
    DecisionTokenSigner, EnforcementDenied, EnforcementGateway, Guardian,
    SQLiteStateStore, StateUnavailable,
)
from cerberus.assurance import approval_message
from cerberus.models import format_time, parse_time
from simulator.assurance_fixtures import fixture_assurance, fixture_key
from simulator.cerberus_sim import evaluate as simulate_incident

ROOT = Path(__file__).resolve().parents[1]
POLICIES = json.loads((ROOT / "policies/policies.json").read_text())
NOW = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
KEY = b"public-assurance-regression-test-material-32-bytes"


def request(approvals=0):
    incident = {
        "incident_id": "ASSURANCE-TEST", "threat": "ransomware", "confidence": 0.99,
        "signals": ["rapid_file_rewrite", "recovery_deletion_attempt"],
        "proposed_action": "isolate_endpoint", "target": "endpoint:assurance-sandbox",
    }
    if approvals:
        incident.update(
            threat="data_exfiltration", signals=["large_outbound_transfer", "new_destination"],
            proposed_action="temporary_egress_hold", target="workload:assurance-sandbox",
            human_approvals=["commander"],
        )
    return ActionEnvelope.from_legacy_incident(incident, policy_version=POLICIES["version"], now=NOW)


def evaluate(envelope, verifier, bundle, *, now=NOW, state=None):
    return Guardian(
        POLICIES, signer=DecisionTokenSigner(KEY), assurance_verifier=verifier,
        idempotency_registry=state,
    ).evaluate(envelope, assurance=bundle, now=now)


def gateway_call(gateway, decision, *, now=NOW):
    return gateway.authorize_and_simulate(
        decision.decision_token, action=decision.authorized_action,
        target=decision.target, scope=decision.scope, now=now,
    )


def assert_withheld(decision):
    assert decision.guardian_decision in {"deny", "escalate"}
    assert decision.decision_token is None


def test_missing_configuration_or_proofs_cannot_grant_authority():
    envelope = request()
    verifier, bundle = fixture_assurance(envelope)
    assert_withheld(evaluate(envelope, None, bundle))
    assert_withheld(evaluate(envelope, verifier, None))
    assert_withheld(evaluate(envelope, verifier, AssuranceBundle()))
    assert_withheld(evaluate(envelope, verifier, object()))
    assert evaluate(envelope, verifier, bundle).guardian_decision == "approve"


def test_simulator_requires_an_explicit_fixture_trust_assumption():
    incident = {"threat": "ransomware", "confidence": 0.99,
                "signals": ["rapid_file_rewrite", "recovery_deletion_attempt"],
                "proposed_action": "isolate_endpoint"}
    denied = simulate_incident(incident, POLICIES)
    assert denied["guardian_decision"] == "deny"
    assert denied["decision_token"] is None
    approved = simulate_incident(incident, POLICIES, assume_trusted_fixture=True)
    assert approved["guardian_decision"] == "approve"
    assert approved["fixture_trust_assumption"] is True


@pytest.mark.parametrize("age,allowed", [
    (59.999999, True), (60, False), (60.000001, False), (61, False),
    (120, False), (86400 * 365, False), (-5, True), (-5.000001, False), (-31, False),
])
def test_signed_observation_age_boundaries(age, allowed):
    envelope = request()
    envelope = replace(envelope, evidence=(
        replace(envelope.evidence[0], observed_at=format_time(NOW - timedelta(seconds=age))),
        envelope.evidence[1],
    ))
    # A genuine producer signs the old/future timestamp. Signature validity must
    # not override the freshness rule, including one stale item among fresh ones.
    verifier, bundle = fixture_assurance(envelope)
    result = evaluate(envelope, verifier, bundle)
    if allowed:
        assert result.guardian_decision == "approve"
        DecisionTokenSigner(KEY).verify(result.decision_token, now=NOW)
    else:
        assert_withheld(result)
        assert result.policy == "GLOBAL-EVIDENCE-FRESHNESS"


def test_queued_token_cannot_outlive_the_oldest_observation(tmp_path):
    envelope = request()
    envelope = replace(envelope, evidence=(
        replace(envelope.evidence[0], observed_at=format_time(NOW - timedelta(seconds=50))),
        envelope.evidence[1],
    ))
    verifier, bundle = fixture_assurance(envelope)
    result = evaluate(envelope, verifier, bundle)
    token = DecisionTokenSigner(KEY).verify(result.decision_token, now=NOW)
    assert parse_time(token["expires_at"]) == NOW + timedelta(seconds=10)
    gateway = EnforcementGateway(DecisionTokenSigner(KEY), replay_cache=SQLiteStateStore(tmp_path / "state.db", create=True))
    with pytest.raises(EnforcementDenied, match="expired"):
        gateway_call(gateway, result, now=NOW + timedelta(seconds=10))


@pytest.mark.parametrize("field,value", [
    ("digest", "b" * 64), ("source_id", "fabricated-observer"),
    ("signal", "hidden_persistence"), ("observed_at", "2026-09-07T11:59:59Z"),
])
def test_evidence_edits_cannot_reuse_an_original_attestation(field, value):
    envelope = request()
    verifier, bundle = fixture_assurance(envelope)
    changed = replace(envelope, evidence=(replace(envelope.evidence[0], **{field: value}), envelope.evidence[1]))
    assert_withheld(evaluate(changed, verifier, bundle))
    assert evaluate(envelope, verifier, bundle).guardian_decision == "approve"


@pytest.mark.parametrize("kind", ["evidence", "approval"])
@pytest.mark.parametrize("attack", ["unknown_key", "wrong_signature", "malformed_signature", "revoked"])
def test_forged_or_revoked_authority_never_counts(kind, attack):
    envelope = request(approvals=1)
    verifier, bundle = fixture_assurance(envelope)
    collection = bundle.evidence if kind == "evidence" else bundle.approvals
    proof = collection[0]
    if attack == "revoked":
        verifier = AssuranceVerifier(
            evidence_authorities=tuple(verifier._evidence.values()),
            approval_authorities=tuple(verifier._approvals.values()), revoked_key_ids=frozenset({proof.key_id}),
        )
    else:
        changes = {"key_id": "attacker:invented-key"} if attack == "unknown_key" else {
            "signature": "0" * 128 if attack == "wrong_signature" else "not-a-signature",
        }
        bundle = replace(bundle, **{kind if kind == "evidence" else "approvals": (replace(proof, **changes),) + collection[1:]})
    assert_withheld(evaluate(envelope, verifier, bundle))


@pytest.mark.parametrize("field,value", [
    ("target", "workload:another-sandbox"), ("requested_scope", "single_identity"),
    ("proposed_action", "preserve_evidence"), ("policy_version", "9.9.9"),
    ("nonce", "different-request-nonce-00001"), ("actor", "different-actor"),
    ("incident_id", "different-incident"), ("envelope_id", "different-envelope"),
    ("idempotency_key", "342e7339-a32e-4378-b99f-1a61d6263002"),
])
def test_approval_cannot_be_transferred_to_an_altered_request(field, value):
    envelope = request(approvals=1)
    verifier, bundle = fixture_assurance(envelope)
    changed = replace(envelope, **{field: value})
    assert_withheld(evaluate(changed, verifier, bundle))
    assert evaluate(envelope, verifier, bundle).guardian_decision == "approve"


def test_approval_expiry_bounds_the_token_and_tampering_fails(tmp_path):
    envelope = request(approvals=1)
    verifier, bundle = fixture_assurance(envelope)
    proof = bundle.approvals[0]
    expiry = format_time(NOW + timedelta(seconds=3))
    signature = fixture_key(proof.key_id).sign(approval_message(envelope, "commander", proof.key_id, expiry)).hex()
    bundle = replace(bundle, approvals=(ApprovalProof(proof.key_id, expiry, signature),))
    decision = evaluate(envelope, verifier, bundle)
    assert parse_time(DecisionTokenSigner(KEY).verify(decision.decision_token, now=NOW)["expires_at"]) == NOW + timedelta(seconds=3)
    with pytest.raises(EnforcementDenied, match="expired"):
        gateway_call(EnforcementGateway(DecisionTokenSigner(KEY), replay_cache=SQLiteStateStore(tmp_path / "expiry.db", create=True)), decision, now=NOW + timedelta(seconds=3))
    assert_withheld(evaluate(envelope, verifier, bundle, now=NOW + timedelta(seconds=3)))
    tampered = replace(bundle, approvals=(replace(bundle.approvals[0], expires_at=envelope.expires_at),))
    assert_withheld(evaluate(envelope, verifier, tampered))


def test_unauthenticated_probe_cannot_poison_a_valid_idempotency_key(tmp_path):
    envelope = request()
    verifier, bundle = fixture_assurance(envelope)
    state = SQLiteStateStore(tmp_path / "guardian.db", create=True)
    assert_withheld(evaluate(envelope, verifier, None, state=state))
    assert evaluate(envelope, verifier, bundle, state=state).guardian_decision == "approve"
    assert_withheld(evaluate(envelope, verifier, bundle, state=SQLiteStateStore(tmp_path / "guardian.db")))


@pytest.mark.parametrize("replicas", [2, 12])
def test_concurrent_gateway_replay_produces_only_one_receipt(tmp_path, replicas):
    envelope = request()
    verifier, bundle = fixture_assurance(envelope)
    decision = evaluate(envelope, verifier, bundle)
    path = tmp_path / "gateway.db"
    SQLiteStateStore(path, create=True)

    def consume(_):
        gateway = EnforcementGateway(DecisionTokenSigner(KEY), replay_cache=SQLiteStateStore(path))
        try:
            receipt = gateway_call(gateway, decision)
            assert receipt["status"] == "simulated" and receipt["side_effects"] is False
            return "accepted"
        except EnforcementDenied:
            return "blocked"

    with ThreadPoolExecutor(max_workers=replicas) as workers:
        outcomes = list(workers.map(consume, range(replicas)))
    assert outcomes.count("accepted") == 1
    assert outcomes.count("blocked") == replicas - 1


def test_different_valid_tokens_for_one_request_cannot_duplicate_execution(tmp_path):
    envelope = request()
    verifier, bundle = fixture_assurance(envelope)
    first = evaluate(envelope, verifier, bundle)
    second = evaluate(envelope, verifier, bundle)  # a fresh Guardian without shared state
    assert first.decision_token != second.decision_token
    path = tmp_path / "gateway.db"
    gateway_call(EnforcementGateway(DecisionTokenSigner(KEY), replay_cache=SQLiteStateStore(path, create=True)), first)
    with pytest.raises(EnforcementDenied, match="consumed"):
        gateway_call(EnforcementGateway(DecisionTokenSigner(KEY), replay_cache=SQLiteStateStore(path)), second)


def test_actual_fresh_process_cannot_replay_a_consumed_token(tmp_path):
    envelope = request()
    verifier, bundle = fixture_assurance(envelope)
    decision = evaluate(envelope, verifier, bundle)
    path = tmp_path / "process.db"
    gateway_call(EnforcementGateway(DecisionTokenSigner(KEY), replay_cache=SQLiteStateStore(path, create=True)), decision)
    code = '''import json,sys
from cerberus import DecisionTokenSigner,EnforcementGateway,EnforcementDenied,SQLiteStateStore
from cerberus.models import parse_time
d=json.load(sys.stdin)
g=EnforcementGateway(DecisionTokenSigner(bytes.fromhex(d["key"])),replay_cache=SQLiteStateStore(d["path"]))
try:
 g.authorize_and_simulate(d["token"],action=d["action"],target=d["target"],scope=d["scope"],now=parse_time(d["now"]))
 print("accepted")
except EnforcementDenied:
 print("blocked")
'''
    output = subprocess.run([sys.executable, "-c", code], input=json.dumps({
        "key": KEY.hex(), "path": str(path), "token": decision.decision_token,
        "action": decision.authorized_action, "target": decision.target,
        "scope": decision.scope, "now": format_time(NOW),
    }), text=True, capture_output=True, cwd=ROOT, check=True)
    assert output.stdout.strip() == "blocked"


def test_missing_or_corrupt_state_never_falls_back_to_memory(tmp_path):
    path = tmp_path / "state.db"
    with pytest.raises(StateUnavailable):
        SQLiteStateStore(path)
    state = SQLiteStateStore(path, create=True)
    path.unlink()
    with pytest.raises(StateUnavailable):
        state.consume("token", "request", "digest")
    assert not path.exists()
    path.write_text("corrupt store")
    with pytest.raises(StateUnavailable):
        SQLiteStateStore(path)
    with pytest.raises(ValueError, match="supply durable"):
        EnforcementGateway(DecisionTokenSigner(KEY))


def test_locked_state_denies_without_issuing_a_token(tmp_path):
    envelope = request()
    verifier, bundle = fixture_assurance(envelope)
    path = tmp_path / "locked.db"
    state = SQLiteStateStore(path, create=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        decision = evaluate(envelope, verifier, bundle, state=state)
        assert_withheld(decision)
        assert decision.policy == "GLOBAL-STATE-AVAILABILITY"
    finally:
        connection.rollback()
        connection.close()
    assert evaluate(envelope, verifier, bundle, state=state).guardian_decision == "approve"


def test_failure_after_consumption_does_not_make_authority_reusable(tmp_path):
    envelope = request()
    verifier, bundle = fixture_assurance(envelope)
    decision = evaluate(envelope, verifier, bundle)
    path = tmp_path / "crash.db"
    class FailedLedger:
        def append(self, *args):
            raise OSError("simulated audit failure after durable claim")
    gateway = EnforcementGateway(DecisionTokenSigner(KEY), replay_cache=SQLiteStateStore(path, create=True), ledger=FailedLedger())
    with pytest.raises(OSError, match="audit failure"):
        gateway_call(gateway, decision)
    with pytest.raises(EnforcementDenied):
        gateway_call(EnforcementGateway(DecisionTokenSigner(KEY), replay_cache=SQLiteStateStore(path)), decision)


@pytest.mark.parametrize("token", [None, 123, [], "", "bad", "é.bad", "a" * 17000, "x.!", "[].invalid"])
def test_malformed_tokens_are_controlled_refusals(tmp_path, token):
    gateway = EnforcementGateway(DecisionTokenSigner(KEY), replay_cache=SQLiteStateStore(tmp_path / "malformed.db", create=True))
    with pytest.raises(EnforcementDenied):
        gateway.authorize_and_simulate(token, action="isolate_endpoint", target="endpoint:assurance-sandbox", scope="single_endpoint", now=NOW)
