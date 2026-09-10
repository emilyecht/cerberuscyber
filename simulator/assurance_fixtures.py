"""Artificial trust for explicitly selected, side-effect-free demonstrations.

THIS IS NOT AN AUTHENTICATION SERVICE. It signs whatever fixture is supplied and
must never be installed as a verifier for attacker-supplied production requests.
The real Guardian does not import or call this module. Security tests must create
their trusted fixture first, then change the adversarial input without re-signing.
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cerberus.assurance import (
    ApprovalAuthority, ApprovalProof, AssuranceBundle, AssuranceVerifier,
    EvidenceAuthority, EvidenceProof, approval_message, evidence_message,
)
from cerberus.models import ActionEnvelope


def fixture_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(("PUBLIC-TEST-MATERIAL-ONLY:" + label).encode()).digest()
    )


def fixture_assurance(envelope: ActionEnvelope) -> tuple[AssuranceVerifier, AssuranceBundle]:
    sources = sorted(envelope.independent_sources)
    evidence_authorities = []
    for source in sources:
        key_id = "fixture-evidence:" + source
        evidence_authorities.append(EvidenceAuthority(
            key_id, fixture_key(key_id).public_key().public_bytes_raw(),
            frozenset({source}),
            frozenset(e.signal for e in envelope.evidence if e.source_id == source),
            frozenset({envelope.target}), "fixture-domain:" + source,
        ))
    approval_authorities = []
    for label in envelope.human_approvals:
        key_id = "fixture-approval:" + label
        approval_authorities.append(ApprovalAuthority(
            key_id, fixture_key(key_id).public_key().public_bytes_raw(),
            "fixture-principal:" + label, frozenset({label}),
            frozenset({envelope.action}), frozenset({envelope.target}),
        ))
    verifier = AssuranceVerifier(
        evidence_authorities=tuple(evidence_authorities),
        approval_authorities=tuple(approval_authorities),
    )
    evidence_proofs = []
    for item in envelope.evidence:
        key_id = "fixture-evidence:" + item.source_id
        evidence_proofs.append(EvidenceProof(
            key_id, fixture_key(key_id).sign(evidence_message(envelope, item, key_id)).hex(),
        ))
    approval_proofs = []
    for label in envelope.human_approvals:
        key_id = "fixture-approval:" + label
        approval_proofs.append(ApprovalProof(
            key_id, envelope.expires_at,
            fixture_key(key_id).sign(approval_message(envelope, label, key_id, envelope.expires_at)).hex(),
        ))
    return verifier, AssuranceBundle(tuple(evidence_proofs), tuple(approval_proofs))
