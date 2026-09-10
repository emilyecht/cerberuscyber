"""Closed, simulation-only quick start. No external targets or operational keys.

All identities and observations are fabricated locally. The ephemeral signers
below illustrate configured trust; they are not evidence/approval issuer services.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
from importlib.resources import files
import json
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import (
    ActionEnvelope, ApprovalAuthority, ApprovalProof, AssuranceBundle,
    AssuranceVerifier, DecisionTokenSigner, EnforcementDenied, EnforcementGateway,
    EvidenceAuthority, EvidenceProof, Guardian, PolicyBundle, SQLiteStateStore,
)
from .assurance import approval_message, evidence_message


def _demo_proofs(envelope):
    """Only called for the closed demo fixture, before any adversarial changes."""
    evidence_authorities, approval_authorities, evidence, approvals = [], [], [], []
    for i, item in enumerate(envelope.evidence):
        key, key_id = Ed25519PrivateKey.generate(), f"demo-sensor-{i}"
        evidence_authorities.append(EvidenceAuthority(
            key_id, key.public_key().public_bytes_raw(), frozenset({item.source_id}),
            frozenset({item.signal}), frozenset({envelope.target}), f"demo-domain-{i}",
        ))
        evidence.append(EvidenceProof(key_id, key.sign(evidence_message(envelope, item, key_id)).hex()))
    for i, label in enumerate(envelope.human_approvals):
        key, key_id = Ed25519PrivateKey.generate(), f"demo-approver-{i}"
        approval_authorities.append(ApprovalAuthority(
            key_id, key.public_key().public_bytes_raw(), f"demo-principal-{i}",
            frozenset({label}), frozenset({envelope.action}), frozenset({envelope.target}),
        ))
        approvals.append(ApprovalProof(key_id, envelope.expires_at,
            key.sign(approval_message(envelope, label, key_id, envelope.expires_at)).hex()))
    return AssuranceVerifier(evidence_authorities=tuple(evidence_authorities),
                             approval_authorities=tuple(approval_authorities)), AssuranceBundle(tuple(evidence), tuple(approvals))


def run_demo() -> dict:
    now = datetime.now(timezone.utc)
    policy = PolicyBundle.from_dict(json.loads(files("cerberus").joinpath("data/policies.json").read_text()))
    request = ActionEnvelope.from_legacy_incident({
        "incident_id": "EVAL-KIT-DEMO", "threat": "data_exfiltration", "confidence": 0.99,
        "signals": ["large_outbound_transfer", "new_destination"],
        "proposed_action": "temporary_egress_hold", "target": "workload:local-demo-only",
        "human_approvals": ["demo-incident-commander"],
    }, policy_version=policy.version, now=now)
    verifier, proofs = _demo_proofs(request)
    signer = DecisionTokenSigner(secrets.token_bytes(32), key_id="ephemeral-local-demo")
    with TemporaryDirectory(prefix="cerberus-eval-") as directory:
        path = Path(directory) / "claims.db"
        store = SQLiteStateStore(path, create=True)
        guardian = Guardian(policy, signer=signer, assurance_verifier=verifier, idempotency_registry=store)
        forged_evidence = replace(proofs, evidence=(replace(proofs.evidence[0], signature="0" * 128),) + proofs.evidence[1:])
        forged_approval = replace(proofs, approvals=(replace(proofs.approvals[0], signature="0" * 128),))
        rejected = []
        for name, bundle in (("forged_evidence", forged_evidence), ("forged_approval", forged_approval)):
            decision = guardian.evaluate(request, assurance=bundle, now=now)
            if decision.guardian_decision != "deny" or decision.decision_token is not None:
                raise RuntimeError(f"demo failed: {name} received authority")
            rejected.append({"case": name, "decision": decision.guardian_decision, "reason": decision.reason})
        decision = guardian.evaluate(request, assurance=proofs, now=now)
        if decision.guardian_decision != "approve" or decision.decision_token is None:
            raise RuntimeError("demo failed: eligible request received no authority")
        payload = signer.verify(decision.decision_token, now=now)
        if (payload["envelope_digest"] != request.digest()
                or payload["policy_digest"] != policy.digest
                or payload["assurance_digest"] != decision.assurance_digest):
            raise RuntimeError("demo failed: token does not bind evaluated inputs")
        receipt = EnforcementGateway(signer, replay_cache=store).authorize_and_simulate(
            decision.decision_token, action=request.action, target=request.target, scope=request.scope, now=now)
        if (receipt["side_effects"] is not False or receipt["status"] != "simulated"
                or any(receipt.get(field) != payload[field] for field in (
                    "action", "target", "scope", "actor", "envelope_digest",
                    "idempotency_key", "policy_version", "policy_digest", "token_id"))):
            raise RuntimeError("demo failed: receipt is not simulated and exactly bound")
        # A new gateway reopens the existing database: not just reuse of a Python object.
        try:
            EnforcementGateway(signer, replay_cache=SQLiteStateStore(path)).authorize_and_simulate(
                decision.decision_token, action=request.action, target=request.target, scope=request.scope, now=now)
        except EnforcementDenied as exc:
            if "consumed" not in str(exc):
                raise RuntimeError("replay test failed its precondition") from exc
            replay = {"case": "replay_new_gateway", "decision": "blocked", "reason": str(exc)}
        else:
            raise RuntimeError("demo failed: replay created another receipt")
    # Do not expose raw bearer tokens or private key material in the output.
    return {"mode": "simulation-only", "token_version": signer.TOKEN_VERSION,
            "trust": "fabricated local identities; ephemeral demonstration keys",
            "cases_passed": 4, "request": request.to_dict(), "decision": "approve",
            "policy_digest": policy.digest, "assurance_digest": payload["assurance_digest"],
            "receipt": receipt, "refusals": rejected + [replay],
            "limits": "Not independent validation, production protection or real containment."}


def main():
    parser = argparse.ArgumentParser(description="CERBERUS Cyber evaluation kit — simulation only")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="run a closed local demonstration; no external side effects")
    demo.add_argument("--json", action="store_true", help="show inspectable request, decision and receipt metadata")
    args = parser.parse_args()
    result = run_demo()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("CERBERUS CYBER — SIMULATION ONLY")
        print("PASS  authenticated eligible request -> exact simulated receipt")
        for case in result["refusals"]:
            print(f"PASS  {case['case']} -> {case['decision']}")
        print(f"Token {result['token_version']}: policy + assurance digests bound")
        print("No real containment. Demo identities and keys are not operational trust.")


if __name__ == "__main__":
    main()
