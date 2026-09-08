"""Public-key verification at the evidence and human-approval trust boundary.

Trust configuration is supplied by the operator, never derived from a proposal.
Signatures authenticate configured producers, not the truth of sensor reports.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .freshness import evidence_deadline
from .models import ActionEnvelope, Evidence, parse_time


class AssuranceError(ValueError):
    """The submitted proof does not establish the required authority."""


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def evidence_message(envelope: ActionEnvelope, item: Evidence, key_id: str) -> bytes:
    return _canonical({
        "purpose": "cerberus.evidence.v2", "key_id": key_id,
        "envelope_digest": envelope.digest(),
        "target": envelope.target, "evidence": item.to_canonical_dict(),
    })


def approval_message(envelope: ActionEnvelope, label: str, key_id: str, expires_at: str) -> bytes:
    # The full envelope digest includes action, target, scope, actor, policy,
    # approvals, evidence, nonce and idempotency key. Approval cannot be moved.
    return _canonical({
        "purpose": "cerberus.approval.v1", "key_id": key_id,
        "approval_label": label, "envelope_digest": envelope.digest(),
        "expires_at": expires_at,
    })


def _strings(values, name: str) -> frozenset[str]:
    if not isinstance(values, (set, frozenset, tuple, list)) or not values:
        raise ValueError(f"{name} must be a non-empty collection")
    if any(not isinstance(v, str) or not v.strip() for v in values):
        raise ValueError(f"{name} must contain non-empty strings")
    return frozenset(values)


@dataclass(frozen=True)
class EvidenceAuthority:
    key_id: str
    public_key: bytes
    source_ids: frozenset[str]
    signals: frozenset[str]
    targets: frozenset[str]
    independence_domain: str

    def __post_init__(self) -> None:
        for name in ("source_ids", "signals", "targets"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        if not isinstance(self.independence_domain, str) or not self.independence_domain.strip():
            raise ValueError("evidence authority needs an independence domain")


@dataclass(frozen=True)
class ApprovalAuthority:
    key_id: str
    public_key: bytes
    principal_id: str
    approval_labels: frozenset[str]
    actions: frozenset[str]
    targets: frozenset[str]

    def __post_init__(self) -> None:
        for name in ("approval_labels", "actions", "targets"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        if not isinstance(self.principal_id, str) or not self.principal_id.strip():
            raise ValueError("approval authority needs a principal identity")


@dataclass(frozen=True)
class EvidenceProof:
    key_id: str
    signature: str


@dataclass(frozen=True)
class ApprovalProof:
    key_id: str
    expires_at: str
    signature: str


@dataclass(frozen=True)
class AssuranceBundle:
    evidence: tuple[EvidenceProof, ...] = ()
    approvals: tuple[ApprovalProof, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, tuple) or not all(type(p) is EvidenceProof for p in self.evidence):
            raise AssuranceError("evidence proofs must be a tuple of EvidenceProof")
        if not isinstance(self.approvals, tuple) or not all(type(p) is ApprovalProof for p in self.approvals):
            raise AssuranceError("approval proofs must be a tuple of ApprovalProof")

    def to_dict(self) -> dict:
        return {"evidence": [asdict(p) for p in self.evidence], "approvals": [asdict(p) for p in self.approvals]}

    @classmethod
    def from_dict(cls, data: dict) -> "AssuranceBundle":
        if not isinstance(data, dict) or set(data) != {"evidence", "approvals"}:
            raise AssuranceError("assurance bundle requires evidence and approvals only")
        if not isinstance(data["evidence"], list) or not isinstance(data["approvals"], list):
            raise AssuranceError("assurance proof collections must be arrays")
        try:
            return cls(
                tuple(EvidenceProof(**p) for p in data["evidence"]),
                tuple(ApprovalProof(**p) for p in data["approvals"]),
            )
        except (TypeError, ValueError) as exc:
            raise AssuranceError("malformed assurance proof") from exc


@dataclass(frozen=True)
class VerifiedAssurance:
    source_domains: frozenset[str]
    approval_principals: frozenset[str]
    expires_at: datetime
    digest: str


class AssuranceVerifier:
    def __init__(
        self, *, evidence_authorities: tuple[EvidenceAuthority, ...],
        approval_authorities: tuple[ApprovalAuthority, ...] = (),
        revoked_key_ids: frozenset[str] = frozenset(),
    ) -> None:
        evidence, approvals, public_keys = {}, {}, {}
        all_ids: set[str] = set()
        public_owners: dict[bytes, tuple[str, str]] = {}
        for kind, authorities, expected_type, table in (
            ("evidence", evidence_authorities, EvidenceAuthority, evidence),
            ("approval", approval_authorities, ApprovalAuthority, approvals),
        ):
            for authority in authorities:
                if type(authority) is not expected_type:
                    raise ValueError("invalid authority configuration")
                if not isinstance(authority.key_id, str) or not authority.key_id.strip() or authority.key_id in all_ids:
                    raise ValueError("authority key IDs must be unique non-empty strings")
                if type(authority.public_key) is not bytes or len(authority.public_key) != 32:
                    raise ValueError("authority public keys must be 32 Ed25519 bytes")
                identity = authority.independence_domain if kind == "evidence" else authority.principal_id
                owner = (kind, identity)
                if authority.public_key in public_owners and public_owners[authority.public_key] != owner:
                    raise ValueError("one signing key cannot establish independent authorities")
                public_owners[authority.public_key] = owner
                all_ids.add(authority.key_id)
                table[authority.key_id] = authority
                public_keys[authority.key_id] = Ed25519PublicKey.from_public_bytes(authority.public_key)
        if not isinstance(revoked_key_ids, (frozenset, set, tuple, list)):
            raise ValueError("revoked key IDs must be a collection")
        if any(not isinstance(k, str) or k not in all_ids for k in revoked_key_ids):
            raise ValueError("revocation refers to an unknown authority")
        self._evidence = MappingProxyType(evidence)
        self._approvals = MappingProxyType(approvals)
        self._public_keys = MappingProxyType(public_keys)
        self._revoked = frozenset(revoked_key_ids)

    def _authority(self, key_id: str, table):
        if not isinstance(key_id, str) or key_id not in table or key_id in self._revoked:
            raise AssuranceError("unknown, revoked or wrong-purpose authority")
        return table[key_id]

    def _verify(self, key_id: str, signature: str, message: bytes) -> None:
        if not isinstance(signature, str) or re.fullmatch(r"[0-9a-f]{128}", signature) is None:
            raise AssuranceError("malformed attestation signature")
        try:
            self._public_keys[key_id].verify(bytes.fromhex(signature), message)
        except InvalidSignature as exc:
            raise AssuranceError("invalid attestation signature or request binding") from exc

    def verify(self, envelope: ActionEnvelope, bundle: AssuranceBundle | None, *, now: datetime) -> VerifiedAssurance:
        if type(bundle) is not AssuranceBundle:
            raise AssuranceError("authenticated evidence and approvals are required")
        if len(bundle.evidence) != len(envelope.evidence):
            raise AssuranceError("every evidence item requires an attestation")
        if len(bundle.approvals) != len(envelope.human_approvals):
            raise AssuranceError("every claimed approval requires an attestation")
        deadline = evidence_deadline(envelope, now)
        domains, principals = set(), set()
        for item, proof in zip(envelope.evidence, bundle.evidence):
            authority = self._authority(proof.key_id, self._evidence)
            if item.source_id not in authority.source_ids or item.signal not in authority.signals or envelope.target not in authority.targets:
                raise AssuranceError("evidence producer is not authorized for this observation or target")
            self._verify(proof.key_id, proof.signature, evidence_message(envelope, item, proof.key_id))
            domains.add(authority.independence_domain)
        for label, proof in zip(envelope.human_approvals, bundle.approvals):
            authority = self._authority(proof.key_id, self._approvals)
            if label not in authority.approval_labels or envelope.action not in authority.actions or envelope.target not in authority.targets:
                raise AssuranceError("approver is not authorized for this action or target")
            try:
                expires = parse_time(proof.expires_at)
            except (ValueError, TypeError) as exc:
                raise AssuranceError("invalid approval expiry") from exc
            if expires <= now or expires > parse_time(envelope.expires_at):
                raise AssuranceError("approval is expired or exceeds the request lifetime")
            self._verify(proof.key_id, proof.signature, approval_message(envelope, label, proof.key_id, proof.expires_at))
            if authority.principal_id in principals:
                raise AssuranceError("multiple approval labels resolve to one principal")
            principals.add(authority.principal_id)
            deadline = min(deadline, expires)
        return VerifiedAssurance(
            frozenset(domains), frozenset(principals), deadline,
            hashlib.sha256(_canonical(bundle.to_dict())).hexdigest(),
        )
