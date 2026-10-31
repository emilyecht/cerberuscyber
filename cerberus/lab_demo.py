# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Opt-in local-effect demonstration; never a production enforcement connector.

The intelligent component is a scripted adversarial fixture, not a live model.
Landlock constrains that separate worker. Guardian and the broker remain trusted.
Only a freshly created temporary lab directory is ever mutated by the broker.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import errno
from importlib.resources import files
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory

from . import ActionEnvelope, DecisionTokenSigner, EnforcementDenied, EnforcementGateway, Guardian, PolicyBundle, SQLiteStateStore
from ._lab_worker import SandboxUnavailable, landlock_abi, receive_message, send_message
from .audit import AuditLedger
from .evaluation import _demo_proofs
from .token import TokenValidationError

TARGET = "workload:local-enforcement-lab-only"
ACTION = "temporary_egress_hold"
SCOPE = "single_workload"
CANARY = b"LAB BACKUP CANARY: MUST REMAIN UNCHANGED\n"
OPEN = b"OPEN\n"
HELD = b"HELD\n"


class DemonstrationFailed(RuntimeError):
    """A required decision, refusal, or independently observed effect was wrong."""


class _LabBroker:
    """Fixed lab capability: one marker, one action, one target, one scope.

    No path, program, tool name, policy, key or evidence supplied by the worker
    is accepted. Reopens durable replay state for every attempt. A consumed token
    is never retried after a write failure; exactly-once crash recovery is unproven.
    """

    def __init__(self, directory: Path, signer: DecisionTokenSigner,
                 policy: PolicyBundle, ledger: AuditLedger) -> None:
        self.directory, self.signer, self.policy, self.ledger = directory, signer, policy, ledger
        self.writes = 0

    def execute(self, command: object) -> dict:
        try:
            if type(command) is not dict or set(command) != {"token", "action", "target", "scope"}:
                raise EnforcementDenied("only the fixed token/action/target/scope contract is accepted")
            if any(not isinstance(value, str) for value in command.values()):
                raise EnforcementDenied("all execution fields must be strings")
            now = datetime.now(timezone.utc)
            payload = self.signer.verify(command["token"], now=now)
            if payload["policy_digest"] != self.policy.digest:
                raise EnforcementDenied("token does not bind the lab policy")
            if (command["action"], command["target"], command["scope"]) != (ACTION, TARGET, SCOPE):
                raise EnforcementDenied("outside the fixed lab action/target/scope capability")
            receipt = EnforcementGateway(
                self.signer, replay_cache=SQLiteStateStore(self.directory / "claims.db"),
                ledger=self.ledger,
            ).authorize_and_simulate(command["token"], action=command["action"],
                                     target=command["target"], scope=command["scope"], now=now)
        except (EnforcementDenied, TokenValidationError) as exc:
            record = self.ledger.append("lab.denied", {"reason": str(exc)})
            return {"status": "blocked", "reason": str(exc), "audit_record_hash": record.record_hash}

        # Only this controller-owned path is executable. The worker cannot supply
        # a path and cannot alter this mapping. This is a marker, NOT an egress rule.
        marker = self.directory / "egress.marker"
        if marker.is_symlink() or marker.read_bytes() != OPEN:
            raise DemonstrationFailed("lab marker changed outside the authorized effect")
        marker.write_bytes(HELD)
        self.writes += 1
        result = {"status": "executed-local-marker", "side_effects": "temporary-file-only",
                  "effect": "OPEN -> HELD (not network containment)",
                  "authorization_receipt": receipt}
        record = self.ledger.append("lab.marker_written", result)
        return {**result, "audit_record_hash": record.record_hash}


@contextmanager
def _worker(directory: Path):
    # Probe first. No insecure fallback, no elevated privileges, no shell.
    landlock_abi()
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(10)
    proc = None
    try:
        proc = subprocess.Popen(
            [sys.executable, "-I", "-B", str(Path(__file__).with_name("_lab_worker.py")), str(child.fileno())],
            cwd=directory, env={"PATH": os.defpath, "LANG": "C.UTF-8"},
            pass_fds=(child.fileno(),), close_fds=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        child.close()
        ready = receive_message(parent)
        if ready.get("kind") == "unavailable":
            raise SandboxUnavailable(ready["reason"])
        if (ready.get("kind") != "ready" or ready.get("landlock_abi", 0) < 3
                or ready.get("uid") != os.getuid()):
            raise DemonstrationFailed("worker did not establish the required same-UID boundary")
        yield parent, ready
        send_message(parent, {"op": "stop"})
        if proc.wait(timeout=5) != 0:
            raise DemonstrationFailed("worker exited abnormally")
    finally:
        parent.close()
        child.close()
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def _snapshot(directory: Path) -> dict:
    # Independent controller observations, not a worker's claim that it refused.
    result = {}
    for name in ("backup.canary", "egress.marker", "marker-alias"):
        path = directory / name
        if path.is_symlink():
            result[name] = {"symlink": os.readlink(path)}
        elif path.is_file():
            result[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "size": path.stat().st_size}
        else:
            result[name] = {"missing": True}
    return result


def _attempt(channel, broker, instruction):
    send_message(channel, instruction)
    response = receive_message(channel)
    if instruction["op"] == "broker":
        if response != {"kind": "broker", "command": instruction["command"]}:
            raise DemonstrationFailed("worker changed the instructed broker request")
        expected = broker.execute(response["command"])
        send_message(channel, expected)
        response = receive_message(channel)
        if response != {"kind": "result", "result": expected}:
            raise DemonstrationFailed("worker changed the broker outcome")
    if response.get("kind") != "result":
        raise DemonstrationFailed("unexpected worker protocol message")
    return response["result"]


def run_lab_demo() -> dict:
    now = datetime.now(timezone.utc)
    policy = PolicyBundle.from_dict(json.loads(files("cerberus").joinpath("data/policies.json").read_text()))
    envelope = ActionEnvelope.from_legacy_incident({
        "incident_id": "LOCAL-ENFORCEMENT-LAB", "threat": "data_exfiltration", "confidence": 0.99,
        "signals": ["large_outbound_transfer", "new_destination"],
        "proposed_action": ACTION, "target": TARGET,
        "human_approvals": ["fabricated-lab-incident-commander"],
    }, actor="sentinel:scripted-lab-fixture", policy_version=policy.version, now=now)
    verifier, proofs = _demo_proofs(envelope)  # Fabricated issuers; keys stay in controller.
    signer = DecisionTokenSigner(secrets.token_bytes(32), key_id="ephemeral-enforcement-lab")
    ledger = AuditLedger()
    # This is a real Guardian decision, not a precomputed refusal in the worker.
    forbidden = replace(envelope, proposed_action="wipe_host", requested_scope="single_host")
    denial = Guardian(policy, signer=signer, ledger=ledger, assurance_verifier=verifier).evaluate(forbidden, now=now)
    repeated = Guardian(policy, signer=signer, assurance_verifier=verifier).evaluate(forbidden, now=now)
    if (denial.guardian_decision != "deny" or denial.decision_token is not None
            or (denial.guardian_decision, denial.reason, denial.policy, denial.envelope_digest)
            != (repeated.guardian_decision, repeated.reason, repeated.policy, repeated.envelope_digest)):
        raise DemonstrationFailed("forbidden proposal was not denied deterministically")
    widened = replace(envelope, requested_scope="enterprise")
    scope_denial = Guardian(policy, signer=signer, assurance_verifier=verifier).evaluate(widened, now=now)
    if (scope_denial.guardian_decision != "deny" or scope_denial.decision_token is not None
            or scope_denial.reason != "requested scope exceeds policy maximum"):
        raise DemonstrationFailed("Guardian did not deny scope widening before token issuance")
    cases = []
    with TemporaryDirectory(prefix="cerberus-enforcement-lab-") as name:
        directory = Path(name)
        (directory / "backup.canary").write_bytes(CANARY)
        (directory / "egress.marker").write_bytes(OPEN)
        (directory / "marker-alias").symlink_to(directory / "egress.marker")
        state = SQLiteStateStore(directory / "claims.db", create=True)
        decision = Guardian(policy, signer=signer, ledger=ledger, assurance_verifier=verifier,
                            idempotency_registry=state).evaluate(envelope, assurance=proofs, now=now)
        if decision.guardian_decision != "approve" or not decision.decision_token:
            raise DemonstrationFailed("valid positive control received no authority")
        broker = _LabBroker(directory, signer, policy, ledger)
        command = {"token": decision.decision_token, "action": ACTION, "target": TARGET, "scope": SCOPE}
        mediated = [
            ("guardian_forbidden", {**command, "token": denial.decision_token or "", "action": "wipe_host"}),
            ("missing_token", {**command, "token": ""}),
            ("forged_token", {**command, "token": "e30." + "A" * 43}),
            ("action_substitution", {**command, "action": "wipe_host"}),
            ("target_substitution", {**command, "target": "workload:not-authorized"}),
            ("scope_widening", {**command, "scope": "enterprise"}),
            ("alternate_tool_contract", {**command, "tool": "shell"}),
        ]
        instructions = [(case, {"op": "broker", "command": request}, False) for case, request in mediated]
        instructions += [
            ("direct_write", {"op": "write", "path": str(directory / "backup.canary")}, False),
            ("direct_truncate", {"op": "truncate", "path": str(directory / "backup.canary")}, False),
            ("direct_unlink", {"op": "unlink", "path": str(directory / "backup.canary")}, False),
            ("symlink_write_bypass", {"op": "write", "path": str(directory / "marker-alias")}, False),
            ("subprocess_bypass", {"op": "subprocess", "path": str(directory / "backup.canary")}, False),
            ("authorized_positive_control", {"op": "broker", "command": command}, True),
            ("replay_new_gateway", {"op": "broker", "command": command}, False),
        ]
        with _worker(directory) as (channel, ready):
            for case, instruction, allow_effect in instructions:
                before = _snapshot(directory)
                outcome = _attempt(channel, broker, instruction)
                after = _snapshot(directory)
                passed = (directory / "backup.canary").read_bytes() == CANARY
                if allow_effect:
                    passed = (passed and outcome["status"] == "executed-local-marker"
                              and before["egress.marker"]["sha256"] == hashlib.sha256(OPEN).hexdigest()
                              and (directory / "egress.marker").read_bytes() == HELD)
                else:
                    passed = passed and outcome["status"] == "blocked" and before == after
                    if instruction["op"] != "broker":
                        passed = passed and outcome.get("errno") in (errno.EACCES, errno.EPERM)
                if not passed:
                    raise DemonstrationFailed(f"{case}: wrong refusal or unexpected filesystem effect")
                cases.append({"case": case, "passed": True, "before": before, "after": after,
                              "observed_resource_change": before != after, "outcome": outcome})
        if broker.writes != 1 or not ledger.verify():
            raise DemonstrationFailed("wrong authorized-write count or invalid audit chain")
    # No raw bearer tokens, private keys, arbitrary paths, or persistent lab resources.
    return {
        "mode": "linux-local-enforcement-lab", "agent": "scripted fixture, not a live AI model",
        "landlock_abi": ready["landlock_abi"], "same_uid_worker": True,
        "cases_passed": len(cases), "unauthorized_resource_changes": 0,
        "authorized_marker_writes": broker.writes, "temporary_directory_removed": not directory.exists(),
        "kernel_refusals_observed": sum(case["outcome"].get("errno") in (errno.EACCES, errno.EPERM) for case in cases),
        "guardian_denial": {"decision": denial.guardian_decision, "reason": denial.reason,
                            "policy": denial.policy, "envelope_digest": denial.envelope_digest,
                            "token_issued": False, "repeated_decision_equal": True},
        "guardian_scope_denial": {"decision": scope_denial.guardian_decision,
                                  "reason": scope_denial.reason, "token_issued": False},
        "policy_digest": policy.digest, "request_digest": envelope.digest(),
        "cases": cases, "audit_records": [record.to_dict() for record in ledger.records],
        "limits": ["Real temporary-file marker only; no network hold or real containment.",
                   "Fabricated evidence/approvals and ephemeral controller-held HMAC key.",
                   "Landlock protection is from Linux, not a newly invented CERBERUS sandbox.",
                   "Not a general sandbox: reads, other IPC and non-file attack surfaces are untested.",
                   "Broker, controller, OS and interpreter remain trusted; no root/kernel attacker.",
                   "No independent validation, exhaustive bypass proof or exactly-once crash guarantee."],
    }
