"""Fixed, broker-mediated temporary-file evaluation. Run as a module."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
from time import perf_counter_ns

from cerberus import lab_demo as lab

# Expectations are fixed before execution. Each row gets a fresh state directory.
CASES = {
    "authorized": None, "forbidden": "payload and signature",
    "scope": "outside the fixed", "expired": "expired", "revoked": "revoked",
    "replay": "consumed", "missing": "unavailable", "corrupt": "unavailable",
    "replaced": "unavailable",
}


def measure(case, directory):
    now = datetime.now(timezone.utc)
    if case == "expired":
        now -= timedelta(days=1)
    policy = lab.PolicyBundle.from_dict(json.loads(lab.files("cerberus").joinpath("data/policies.json").read_text()))
    proposal = lab.ActionEnvelope.from_legacy_incident({
        "incident_id": "fixture-" + case, "threat": "data_exfiltration", "confidence": 0.99,
        "signals": ["large_outbound_transfer", "new_destination"],
        "proposed_action": lab.ACTION, "target": lab.TARGET,
        "human_approvals": ["fixture-reviewer"],
    }, actor="sentinel:scripted-fixture", policy_version=policy.version, now=now)
    if case == "forbidden":
        proposal = lab.replace(proposal, proposed_action="wipe_host", requested_scope="single_host")
    verifier, proofs = lab._demo_proofs(proposal)
    signer = lab.DecisionTokenSigner(secrets.token_bytes(32))
    ledger = lab.AuditLedger()
    db = directory / "claims.db"
    store = lab.SQLiteStateStore(db, create=True)
    guardian = lab.Guardian(policy, signer=signer, ledger=ledger, assurance_verifier=verifier,
                           idempotency_registry=store)
    decision = guardian.evaluate(proposal, assurance=proofs, now=now)
    registry = lab.TokenAuthorityRegistry()
    token = decision.decision_token
    if case == "forbidden":
        if decision.guardian_decision != "deny" or token is not None:
            raise RuntimeError("forbidden proposal passed Guardian")
    else:
        if decision.guardian_decision != "approve" or not token:
            raise RuntimeError("positive setup failed")
        registry.register(token, signer, now=now, authority_key_ids=frozenset(
            p.key_id for p in proofs.evidence + proofs.approvals))
    marker = directory / "egress.marker"
    marker.write_bytes(lab.OPEN)
    (directory / "backup.canary").write_bytes(lab.CANARY)
    broker = lab._LabBroker(directory, signer, policy, ledger, expected_envelope=proposal,
                            authority_registry=registry)
    command = dict(token=token or "", action=proposal.proposed_action, target=lab.TARGET,
                   scope="enterprise" if case == "scope" else proposal.requested_scope)
    if case == "revoked":
        registry.revoke_token(signer.verify(token)["token_id"])
    elif case == "replay":
        if broker.execute(command)["status"] != "executed-local-marker" or marker.read_bytes() != lab.HELD:
            raise RuntimeError("replay setup failed")
    elif case == "missing":
        db.unlink()
    elif case == "corrupt":
        db.write_bytes(b"invalid synthetic state")
    elif case == "replaced":
        other = directory / "other.db"
        lab.SQLiteStateStore(other, create=True)
        other.replace(db)
    before = lab._snapshot(directory)
    writes = broker.writes
    start = perf_counter_ns()
    result = broker.execute(command)
    elapsed = perf_counter_ns() - start
    after = lab._snapshot(directory)
    changed = after != before
    allowed = result["status"] == "executed-local-marker"
    expected = CASES[case] is None
    reason = result.get("reason", "")
    ok = (allowed == expected and changed == expected and broker.writes - writes == int(expected)
          and (directory / "backup.canary").read_bytes() == lab.CANARY and ledger.verify()
          and result["audit_record_hash"] == ledger.records[-1].record_hash
          and (marker.read_bytes() == lab.HELD if expected
               else result["status"] == "blocked" and CASES[case] in reason))
    return dict(case=case, expected_allow=expected, allowed=allowed, passed=ok, reason=reason,
                changed=changed, elapsed_ns=elapsed, guardian=decision.guardian_decision)


if __name__ == "__main__":
    rows = []
    for repetition in range(10):
        for case in CASES:
            with TemporaryDirectory() as directory:
                rows.append(dict(repetition=repetition, **measure(case, Path(directory))))
    print(json.dumps(rows, indent=2))
    raise SystemExit(int(any(not row["passed"] for row in rows)))
