"""Build deterministic public test attestations from frozen v1 requests.

The stated external facts determine credentials and trust relationships. The
actual verifier is never asked to supply expected answers. Keys are public test
material, and signatures prove fixture behavior, not operational sensor truth.
"""

from dataclasses import asdict, replace
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cerberus import ActionEnvelope, AssuranceVerifier
from cerberus.assurance import approval_message, evidence_message
from simulator.assurance_fixtures import fixture_assurance, fixture_key


def config(verifier):
    def serialize(authority):
        data = asdict(authority)
        for key, value in data.items():
            if isinstance(value, frozenset):
                data[key] = sorted(value)
            elif isinstance(value, bytes):
                data[key] = value.hex()
        return data
    return {
        "evidence_authorities": [serialize(a) for a in verifier._evidence.values()],
        "approval_authorities": [serialize(a) for a in verifier._approvals.values()],
        "revoked_key_ids": sorted(verifier._revoked),
    }


def build():
    source = json.loads(Path(__file__).with_name("source-requests.json").read_text())
    cases = []
    for record in source["cases"]:
        case_id = record["definition"]["id"]
        envelope = ActionEnvelope.from_dict(record["request"])
        reference = ActionEnvelope.from_dict(record["unpatched_reference"])
        # F cases deliberately carry authentic but stale/future observations;
        # valid controls get genuinely bound attestations for their exact input.
        verifier, bundle = fixture_assurance(envelope if case_id[0] in "FV" else reference)
        construction = "genuine configured attestations for the exact supplied observations and request"
        if case_id in {"H01", "H02"}:
            _, forged = fixture_assurance(envelope)
            bundle = replace(bundle, approvals=forged.approvals)
            construction = "approval proofs use untrusted keys for the fabricated labels; evidence remains genuine"
        elif case_id == "H03":
            original, bundle = fixture_assurance(envelope)
            verifier = AssuranceVerifier(
                evidence_authorities=tuple(original._evidence.values()),
                approval_authorities=tuple(replace(a, principal_id="one-person-with-two-credentials") for a in original._approvals.values()),
            )
            construction = "two valid signing credentials resolve to one approving principal"
        elif case_id == "H04":
            other = replace(envelope, target="workload:another-request", proposed_action="preserve_evidence")
            proof = bundle.approvals[0]
            signature = fixture_key(proof.key_id).sign(approval_message(other, envelope.human_approvals[0], proof.key_id, proof.expires_at)).hex()
            bundle = replace(bundle, approvals=(replace(proof, signature=signature),))
            construction = "genuine approver signature binds a different action and target, never the tested request"
        elif case_id == "E01":
            original, bundle = fixture_assurance(envelope)
            verifier = AssuranceVerifier(
                evidence_authorities=tuple(replace(a, independence_domain="one-compromised-sensor") for a in original._evidence.values()),
            )
            construction = "two valid source credentials belong to the same configured independence domain"
        elif case_id == "E02":
            construction = "original genuine evidence proof retained after the submitted digest is altered"
        elif case_id == "E03":
            bundle = replace(bundle, evidence=tuple(
                replace(proof, signature=fixture_key("untrusted-forger").sign(evidence_message(envelope, item, proof.key_id)).hex())
                for item, proof in zip(envelope.evidence, bundle.evidence)
            ))
            construction = "claimed trusted source IDs retain their names but signatures come from an untrusted key"
        cases.append({
            "definition": record["definition"], "request": record["request"],
            "input_sha256": record["input_sha256"], "trust_configuration": config(verifier),
            "assurance": bundle.to_dict(), "proof_construction": construction,
        })
    return {k: v for k, v in source.items() if k != "cases"} | {
        "case_authorship": "Project-authored diagnostic with public test keys; not independent or held out.",
        "freshness_rule": "Evidence age <60 seconds; future skew <=5 seconds; all authority deadlines exclusive.",
        "cases": cases,
    }


if __name__ == "__main__":
    destination = Path(__file__).with_name("cases.json")
    destination.write_text(json.dumps(build(), indent=2) + "\n")
    print(f"Prepared {destination.name}: 11 unsafe requests, 8 eligible controls.")
