"""Typed data contracts for the CERBERUS authority boundary."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from uuid import uuid4


class ValidationError(ValueError):
    """Raised when an authority-boundary object is malformed."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"invalid RFC3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValidationError("timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Evidence:
    signal: str
    source_id: str
    observed_at: str
    digest: str | None = None

    def validate(self) -> None:
        if not self.signal.strip():
            raise ValidationError("evidence.signal is required")
        if not self.source_id.strip():
            raise ValidationError("evidence.source_id is required")
        parse_time(self.observed_at)
        if self.digest is not None and len(self.digest) < 16:
            raise ValidationError("evidence.digest must be at least 16 characters")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        item = cls(
            signal=str(data.get("signal", "")),
            source_id=str(data.get("source_id", "")),
            observed_at=str(data.get("observed_at", "")),
            digest=data.get("digest"),
        )
        item.validate()
        return item


_ACTION_SCOPE_DEFAULTS = {
    "none": "none",
    "revoke_sessions": "single_identity",
    "require_step_up_auth": "single_identity",
    "isolate_endpoint": "single_endpoint",
    "temporary_egress_hold": "single_workload",
    "preserve_evidence": "single_workload",
}


@dataclass(frozen=True)
class ActionEnvelope:
    schema_version: str
    envelope_id: str
    incident_id: str
    threat: str
    confidence: float
    proposed_action: str
    target: str
    requested_scope: str
    reversible: bool
    mission_impact: str
    created_at: str
    expires_at: str
    nonce: str
    evidence: tuple[Evidence, ...]
    human_approvals: tuple[str, ...] = ()

    def validate(self) -> None:
        required = {
            "schema_version": self.schema_version,
            "envelope_id": self.envelope_id,
            "incident_id": self.incident_id,
            "threat": self.threat,
            "proposed_action": self.proposed_action,
            "target": self.target,
            "requested_scope": self.requested_scope,
            "mission_impact": self.mission_impact,
            "nonce": self.nonce,
        }
        for name, value in required.items():
            if not str(value).strip():
                raise ValidationError(f"{name} is required")
        if self.schema_version != "1.0":
            raise ValidationError("unsupported action-envelope schema version")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValidationError("confidence must be between 0 and 1")
        created = parse_time(self.created_at)
        expires = parse_time(self.expires_at)
        if expires <= created:
            raise ValidationError("expires_at must be later than created_at")
        if len(self.nonce) < 16:
            raise ValidationError("nonce must be at least 16 characters")
        if not self.evidence:
            raise ValidationError("at least one evidence item is required")
        for item in self.evidence:
            item.validate()
        if len(set(self.human_approvals)) != len(self.human_approvals):
            raise ValidationError("human approvals must be unique")

    @property
    def evidence_signals(self) -> set[str]:
        return {item.signal for item in self.evidence}

    @property
    def independent_sources(self) -> set[str]:
        return {item.source_id for item in self.evidence}

    def is_expired(self, now: datetime | None = None) -> bool:
        return parse_time(self.expires_at) <= (now or utc_now())

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = [asdict(item) for item in self.evidence]
        result["human_approvals"] = list(self.human_approvals)
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionEnvelope":
        evidence_raw = data.get("evidence", [])
        if not isinstance(evidence_raw, list):
            raise ValidationError("evidence must be a list")
        approvals_raw = data.get("human_approvals", [])
        if not isinstance(approvals_raw, list):
            raise ValidationError("human_approvals must be a list")
        envelope = cls(
            schema_version=str(data.get("schema_version", "")),
            envelope_id=str(data.get("envelope_id", "")),
            incident_id=str(data.get("incident_id", "")),
            threat=str(data.get("threat", "")),
            confidence=float(data.get("confidence", -1.0)),
            proposed_action=str(data.get("proposed_action", "")),
            target=str(data.get("target", "")),
            requested_scope=str(data.get("requested_scope", "")),
            reversible=bool(data.get("reversible", False)),
            mission_impact=str(data.get("mission_impact", "")),
            created_at=str(data.get("created_at", "")),
            expires_at=str(data.get("expires_at", "")),
            nonce=str(data.get("nonce", "")),
            evidence=tuple(Evidence.from_dict(item) for item in evidence_raw),
            human_approvals=tuple(str(item) for item in approvals_raw),
        )
        envelope.validate()
        return envelope

    @classmethod
    def from_legacy_incident(
        cls,
        incident: dict[str, Any],
        *,
        ttl_seconds: int = 120,
        now: datetime | None = None,
    ) -> "ActionEnvelope":
        """Convert the original simulator input into the typed boundary contract.

        Every legacy signal is assigned a distinct synthetic source so existing scenarios
        remain usable. Real integrations must provide actual source identities.
        """

        created = now or utc_now()
        signals: Iterable[str] = incident.get("signals", [])
        evidence = tuple(
            Evidence(
                signal=str(signal),
                source_id=f"legacy:{signal}",
                observed_at=format_time(created),
            )
            for signal in signals
        )
        action = str(incident.get("proposed_action", "none"))
        envelope = cls(
            schema_version="1.0",
            envelope_id=str(incident.get("envelope_id", uuid4())),
            incident_id=str(incident.get("incident_id", "unknown")),
            threat=str(incident.get("threat", "unknown")),
            confidence=float(incident.get("confidence", 0.0)),
            proposed_action=action,
            target=str(
                incident.get(
                    "target",
                    f"simulated-resource:{incident.get('incident_id', 'unknown')}",
                )
            ),
            requested_scope=str(
                incident.get(
                    "requested_scope",
                    _ACTION_SCOPE_DEFAULTS.get(action, "single_workload"),
                )
            ),
            reversible=bool(incident.get("reversible", True)),
            mission_impact=str(incident.get("mission_impact", "low")),
            created_at=format_time(created),
            expires_at=format_time(created + timedelta(seconds=ttl_seconds)),
            nonce=str(incident.get("nonce", uuid4().hex)),
            evidence=evidence,
            human_approvals=tuple(incident.get("human_approvals", [])),
        )
        envelope.validate()
        return envelope


@dataclass(frozen=True)
class GuardianDecision:
    incident_id: str
    envelope_id: str
    guardian_decision: str
    reason: str
    policy: str | None
    policy_version: str
    proposed_action: str
    authorized_action: str
    target: str
    scope: str
    reversible: bool
    human_approval_required: bool
    evidence: tuple[str, ...]
    independent_source_count: int
    decision_token: str | None = None
    audit_record_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        return result
