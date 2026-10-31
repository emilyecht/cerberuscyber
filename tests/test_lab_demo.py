# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Broker contract and independent-effect checks; real Landlock integration last."""

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from importlib.resources import files
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys

import pytest

from cerberus import ActionEnvelope, DecisionTokenSigner, Guardian, PolicyBundle, SQLiteStateStore
from cerberus.audit import AuditLedger
from cerberus.evaluation import _demo_proofs
from cerberus import _lab_worker, lab_demo as lab


@pytest.fixture
def authorized_lab(tmp_path):
    policy = PolicyBundle.from_dict(json.loads(files("cerberus").joinpath("data/policies.json").read_text()))
    now = datetime.now(timezone.utc)
    envelope = ActionEnvelope.from_legacy_incident({
        "incident_id": "LAB-TEST", "threat": "data_exfiltration", "confidence": 0.99,
        "signals": ["large_outbound_transfer", "new_destination"],
        "proposed_action": lab.ACTION, "target": lab.TARGET,
        "human_approvals": ["fabricated-approver"],
    }, policy_version=policy.version, now=now)
    verifier, proofs = _demo_proofs(envelope)
    signer = DecisionTokenSigner(secrets.token_bytes(32))
    ledger = AuditLedger()
    state = SQLiteStateStore(tmp_path / "claims.db", create=True)
    guardian = Guardian(policy, signer=signer, assurance_verifier=verifier, idempotency_registry=state)
    decision = guardian.evaluate(envelope, assurance=proofs, now=now)
    assert decision.guardian_decision == "approve"
    (tmp_path / "egress.marker").write_bytes(lab.OPEN)
    (tmp_path / "backup.canary").write_bytes(lab.CANARY)
    broker = lab._LabBroker(tmp_path, signer, policy, ledger)
    command = {"token": decision.decision_token, "action": lab.ACTION, "target": lab.TARGET, "scope": lab.SCOPE}
    return broker, command, envelope, guardian


@pytest.mark.parametrize("change", [
    {"token": ""}, {"token": "e30." + "A" * 43}, {"action": "wipe_host"},
    {"target": "workload:other"}, {"scope": "enterprise"}, {"tool": "shell"},
    {"path": "/unaccepted/path"}, {"token": None},
])
def test_broker_denies_without_effect_or_consuming_valid_token(authorized_lab, change):
    broker, command, _, _ = authorized_lab
    before = lab._snapshot(broker.directory)
    result = broker.execute({**command, **change})
    assert result["status"] == "blocked"
    assert lab._snapshot(broker.directory) == before
    assert broker.writes == 0
    assert broker.execute(command)["status"] == "executed-local-marker"
    assert broker.writes == 1


@pytest.mark.parametrize("command", [None, [], "shell", {}, {"token": "ignored"}])
def test_broker_rejects_malformed_contract(authorized_lab, command):
    broker, _, _, _ = authorized_lab
    assert broker.execute(command)["status"] == "blocked"
    assert (broker.directory / "egress.marker").read_bytes() == lab.OPEN


def test_real_local_write_and_replay_survive_new_broker(authorized_lab):
    broker, command, _, _ = authorized_lab
    before = lab._snapshot(broker.directory)
    receipt = broker.execute(command)
    assert receipt["status"] == "executed-local-marker"
    assert receipt["authorization_receipt"]["status"] == "simulated"
    assert (broker.directory / "egress.marker").read_bytes() == lab.HELD
    assert (broker.directory / "backup.canary").read_bytes() == lab.CANARY
    after = lab._snapshot(broker.directory)
    assert after != before
    restarted = lab._LabBroker(broker.directory, broker.signer, broker.policy, broker.ledger)
    denied = restarted.execute(command)
    assert denied["status"] == "blocked" and "consumed" in denied["reason"]
    assert lab._snapshot(broker.directory) == after
    assert broker.ledger.verify()


def test_audit_append_snapshots_callers_nested_payload():
    ledger = AuditLedger()
    payload = {"receipt": {"status": "simulated"}}
    record = ledger.append("test.receipt", payload)
    payload["receipt"]["audit_record_hash"] = record.record_hash
    assert ledger.verify()
    assert "audit_record_hash" not in record.payload["receipt"]
    # Deliberate tampering of an actual stored record must still be detectable.
    record.payload["receipt"]["status"] = "changed"
    assert not ledger.verify()


def test_expired_token_cannot_write(authorized_lab, monkeypatch):
    broker, command, envelope, _ = authorized_lab
    from cerberus.models import parse_time
    class ExpiredClock:
        @staticmethod
        def now(_):
            return parse_time(envelope.expires_at)
    monkeypatch.setattr(lab, "datetime", ExpiredClock)
    result = broker.execute(command)
    assert result["status"] == "blocked" and "expired" in result["reason"]
    assert (broker.directory / "egress.marker").read_bytes() == lab.OPEN


def test_old_policy_token_cannot_write(authorized_lab):
    broker, command, _, _ = authorized_lab
    other = broker.policy.to_dict()
    other["decision_ttl_seconds"] += 1
    broker.policy = PolicyBundle.from_dict(other)
    result = broker.execute(command)
    assert result["status"] == "blocked" and "policy" in result["reason"]
    assert broker.writes == 0


def test_guardian_forbidden_action_has_no_bearer_authority(authorized_lab):
    _, _, envelope, guardian = authorized_lab
    forbidden = replace(envelope, proposed_action="wipe_host", requested_scope="single_host")
    decisions = [guardian.evaluate(forbidden) for _ in range(3)]
    assert {d.guardian_decision for d in decisions} == {"deny"}
    assert {d.reason for d in decisions} == {"proposed action is globally forbidden"}
    assert all(d.decision_token is None for d in decisions)


def test_guardian_itself_denies_scope_widening_before_token_issuance(authorized_lab):
    _, _, envelope, guardian = authorized_lab
    widened = replace(envelope, requested_scope="enterprise")
    decision = guardian.evaluate(widened)
    assert decision.guardian_decision == "deny"
    assert decision.reason == "requested scope exceeds policy maximum"
    assert decision.decision_token is None


def test_unsupported_architecture_does_not_guess_syscalls(monkeypatch):
    monkeypatch.setattr(_lab_worker.platform, "machine", lambda: "not-a-supported-architecture")
    with pytest.raises(lab.SandboxUnavailable, match="requires Linux"):
        _lab_worker.landlock_abi()


def test_no_fallback_when_required_kernel_boundary_is_unavailable(monkeypatch):
    def unavailable():
        raise lab.SandboxUnavailable("test: disabled")
    def must_not_launch(*args, **kwargs):
        raise AssertionError("must not run an unrestricted worker")
    monkeypatch.setattr(lab, "landlock_abi", unavailable)
    monkeypatch.setattr(lab.subprocess, "Popen", must_not_launch)
    with pytest.raises(lab.SandboxUnavailable, match="disabled"):
        lab.run_lab_demo()


@contextmanager
def observed_only_worker(directory):
    # Harness mutation tests only. NOT used to claim actual kernel enforcement.
    yield None, {"landlock_abi": 3}


def test_harness_does_not_trust_a_false_refusal(monkeypatch):
    def corrupt_resource(channel, broker, instruction):
        (broker.directory / "backup.canary").write_bytes(b"changed despite refusal")
        return {"status": "blocked"}
    monkeypatch.setattr(lab, "_worker", observed_only_worker)
    monkeypatch.setattr(lab, "_attempt", corrupt_resource)
    with pytest.raises(lab.DemonstrationFailed, match="unexpected filesystem effect"):
        lab.run_lab_demo()


def test_harness_requires_a_real_positive_control_not_a_receipt(monkeypatch):
    def receipt_only(channel, broker, instruction):
        if instruction["op"] == "broker" and instruction["command"].get("token", ""):
            if set(instruction["command"]) == {"token", "action", "target", "scope"} and all(
                instruction["command"][field] == value
                for field, value in (("action", lab.ACTION), ("target", lab.TARGET), ("scope", lab.SCOPE))
            ) and instruction["command"]["token"] != "e30." + "A" * 43:
                return {"status": "executed-local-marker"}  # Lie; no file was changed.
        return {"status": "blocked", "errno": 13}
    monkeypatch.setattr(lab, "_worker", observed_only_worker)
    monkeypatch.setattr(lab, "_attempt", receipt_only)
    with pytest.raises(lab.DemonstrationFailed, match="authorized_positive_control"):
        lab.run_lab_demo()


def test_harness_requires_permission_denial_evidence_not_just_worker_status(monkeypatch):
    def no_kernel_evidence(channel, broker, instruction):
        if instruction["op"] == "broker":
            return broker.execute(instruction["command"])
        return {"status": "blocked"}  # No syscall refusal evidence.
    monkeypatch.setattr(lab, "_worker", observed_only_worker)
    monkeypatch.setattr(lab, "_attempt", no_kernel_evidence)
    with pytest.raises(lab.DemonstrationFailed, match="direct_write"):
        lab.run_lab_demo()


def test_bounded_protocol_rejects_oversize():
    if not hasattr(socket, "SOCK_SEQPACKET"):
        pytest.skip("requires seqpacket")
    first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with pytest.raises(RuntimeError, match="exceeds bound"):
            _lab_worker.send_message(first, {"oversize": "x" * _lab_worker.MAX_MESSAGE})
    finally:
        first.close()
        second.close()


def test_linux_kernel_blocks_bypasses_and_allows_only_the_broker_control():
    try:
        _lab_worker.landlock_abi()
    except lab.SandboxUnavailable as exc:
        pytest.skip(str(exc))
    result = lab.run_lab_demo()  # No mocked worker, broker, decision or effects.
    assert result["cases_passed"] == 14
    assert result["authorized_marker_writes"] == 1
    assert result["unauthorized_resource_changes"] == 0
    assert result["temporary_directory_removed"] is True
    assert result["kernel_refusals_observed"] == 5
    assert result["guardian_scope_denial"]["decision"] == "deny"
    for case in result["cases"]:
        assert case["observed_resource_change"] == (case["case"] == "authorized_positive_control")
    output = json.dumps(result)
    assert '"token"' not in output and '"decision_token"' not in output and '"private_key"' not in output


def test_existing_portable_demo_still_works_without_landlock():
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run([sys.executable, "-m", "cerberus.evaluation", "demo", "--json"],
                          cwd=root, capture_output=True, text=True, timeout=15, check=True)
    result = json.loads(proc.stdout)
    assert result["mode"] == "simulation-only" and result["cases_passed"] == 4
