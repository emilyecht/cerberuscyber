"""Versioned ActionEnvelope contract for the CERBERUS authority boundary.

The public wire representation uses the canonical v1.0.0 field names from the
JSON Schema. The Python object retains compatibility aliases used by the
original simulator so existing fixtures can migrate without weakening the
boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from uuid import UUID, uuid4

ACTION_ENVELOPE_VERSION = "1.0.0"

# Recognized proposal vocabulary. Destructive values are intentionally parseable
# so Guardian can issue an explicit, auditable deny rather than silently dropping
# the request. They remain globally forbidden by policy.
KNOWN_ACTIONS = {
    "none",
    "revoke_sessions",
    "require_step_up_auth",
    "isolate_endpoint",
    "temporary_egress_hold",
    "preserve_evidence",
    "quarantine_workload",
    "delete_backups",
    "modify_backups",
    "disable_recovery",
    "wipe_host",
    "retaliate",
    "execute_exploit",
    "harvest_credentials",
}

KNOWN_SCOPES = {
    "none",
    "single_identity",
    "single_session",
    "single_endpoint",
    "single_host",
    "single_workload",
    "single_segment",
    "enterprise",
}

APPROVAL_MODES = {"none", "single", "dual", "emergency_breakglass"}
MISSION_IMPACTS = {"low", "medium", "high", "critical"}
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


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


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _is_semver(value: str) -> bool:
    return bool(SEMVER_RE.fullmatch(value))


@dataclass(frozen=True)
class Evidence:
    """Reference to independently produced evidence.

    ``digest`` may be absent only in legacy in-memory fixtures. Canonical wire
    serialization always emits a SHA-256 digest, synthesizing one from immutable
    evidence metadata when a legacy fixture did not supply one.
    """

    signal: str
    source_id: str
    observed_at: str
    digest: str | None = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if not self.signal.strip():
            raise ValidationError("evidence.signal is required")
        if not self.source_id.strip():
            raise ValidationError("evidence.source_id is required")
        parse_time(self.observed_at)
        if self.digest is not None:
            if not re.fullmatch(r"[0-9a-fA-F]{16,128}", self.digest):
                raise ValidationError(
                    "evidence.digest must be a 16-128 character hexadecimal digest"
                )

    @property
    def effective_digest(self) -> str:
        if self.digest is not None:
            return self.digest.lower()
        legacy_body = {
            "signal": self.signal,
            "source_id": self.source_id,
            "observed_at": self.observed_at,
        }
        return hashlib.sha256(_canonical_json(legacy_body).encode("utf-8")).hexdigest()

    def to_canonical_dict(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "digest": self.effective_digest,
            "signal": self.signal,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        return cls(
            signal=str(data.get("signal", "")),
            source_id=str(data.get("source_id", "")),
            observed_at=str(data.get("observed_at", "")),
            digest=data.get("digest"),
        )


@dataclass(frozen=True)
class Freshness:
    timestamp: str
    expires_at: str
    nonce: str

    def __post_init__(self) -> None:
        created = parse_time(self.timestamp)
        expires = parse_time(self.expires_at)
        if expires <= created:
            raise ValidationError("freshness.expires_at must be later than timestamp")
        if len(self.nonce) < 16:
            raise ValidationError("freshness.nonce must be at least 16 characters")

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


_ACTION_SCOPE_DEFAULTS = {
    "none": "none",
    "revoke_sessions": "single_identity",
    "require_step_up_auth": "single_identity",
    "isolate_endpoint": "single_endpoint",
    "temporary_egress_hold": "single_workload",
    "preserve_evidence": "single_workload",
    "quarantine_workload": "single_workload",
}

_APPROVAL_MODE_DEFAULTS = {
    "temporary_egress_hold": "single",
    "quarantine_workload": "dual",
}


@dataclass(frozen=True)
class ActionEnvelope:
    """Typed proposal crossing from untrusted inference into trusted policy.

    The first group of fields preserves the original Python API. New v1.0.0
    metadata is mandatory on the canonical wire representation and is validated
    at construction time. Guardian treats confidence as informational evidence,
    never as independent authorization.
    """

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
    actor: str = "sentinel:legacy-adapter"
    idempotency_key: str = field(default_factory=lambda: str(uuid4()))
    required_approval_mode: str = "none"
    policy_version: str = "0.0.0-legacy"

    def __post_init__(self) -> None:
        self.validate()

    # Canonical field aliases used by the JSON Schema and future services.
    @property
    def action(self) -> str:
        return self.proposed_action

    @property
    def scope(self) -> str:
        return self.requested_scope

    @property
    def reversibility_flag(self) -> bool:
        return self.reversible

    @property
    def freshness(self) -> Freshness:
        return Freshness(self.created_at, self.expires_at, self.nonce)

    @property
    def evidence_refs(self) -> tuple[Evidence, ...]:
        return self.evidence

    def validate(self) -> None:
        required = {
            "schema_version": self.schema_version,
            "envelope_id": self.envelope_id,
            "incident_id": self.incident_id,
            "actor": self.actor,
            "threat": self.threat,
            "proposed_action": self.proposed_action,
            "target": self.target,
            "requested_scope": self.requested_scope,
            "mission_impact": self.mission_impact,
            "nonce": self.nonce,
            "idempotency_key": self.idempotency_key,
            "required_approval_mode": self.required_approval_mode,
            "policy_version": self.policy_version,
        }
        for name, value in required.items():
            if not str(value).strip():
                raise ValidationError(f"{name} is required")

        if self.schema_version != ACTION_ENVELOPE_VERSION:
            raise ValidationError(
                f"unsupported action-envelope schema version: {self.schema_version}"
            )
        if self.proposed_action not in KNOWN_ACTIONS:
            raise ValidationError(f"unknown action type: {self.proposed_action}")
        if self.requested_scope not in KNOWN_SCOPES:
            raise ValidationError(f"unknown scope: {self.requested_scope}")
        if self.required_approval_mode not in APPROVAL_MODES:
            raise ValidationError(
                f"unknown required_approval_mode: {self.required_approval_mode}"
            )
        if self.mission_impact not in MISSION_IMPACTS:
            raise ValidationError(f"unknown mission_impact: {self.mission_impact}")
        if not _is_semver(self.policy_version):
            raise ValidationError("policy_version must be SemVer-compatible")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValidationError("confidence must be between 0 and 1")

        self.freshness  # validates timestamps, expiry ordering, and nonce length

        try:
            parsed_idempotency = UUID(self.idempotency_key)
        except (ValueError, AttributeError) as exc:
            raise ValidationError("idempotency_key must be a UUID") from exc
        if parsed_idempotency.version is None:
            raise ValidationError("idempotency_key must be a versioned UUID")

        if not self.evidence:
            raise ValidationError("at least one evidence_ref is required")
        for item in self.evidence:
            item.validate()

        if len(set(self.human_approvals)) != len(self.human_approvals):
            raise ValidationError("human approvals must be unique")
        if any(not item.strip() for item in self.human_approvals):
            raise ValidationError("human approvals must be non-empty")

    @property
    def evidence_signals(self) -> set[str]:
        return {item.signal for item in self.evidence}

    @property
    def independent_sources(self) -> set[str]:
        return {item.source_id for item in self.evidence}

    def is_expired(self, now: datetime | None = None) -> bool:
        return parse_time(self.expires_at) <= (now or utc_now())

    def to_canonical_dict(self) -> dict[str, Any]:
        """Return the exact v1.0.0 wire payload used for signing and hashing."""

        return {
            "schema_version": self.schema_version,
            "envelope_id": self.envelope_id,
            "incident_id": self.incident_id,
            "actor": self.actor,
            "threat": self.threat,
            "action": self.action,
            "target": self.target,
            "scope": self.scope,
            "evidence_refs": [item.to_canonical_dict() for item in self.evidence_refs],
            "confidence": self.confidence,
            "freshness": self.freshness.to_dict(),
            "idempotency_key": self.idempotency_key,
            "reversibility_flag": self.reversibility_flag,
            "required_approval_mode": self.required_approval_mode,
            "policy_version": self.policy_version,
            "mission_impact": self.mission_impact,
            "human_approvals": list(self.human_approvals),
        }

    def to_dict(self) -> dict[str, Any]:
        return self.to_canonical_dict()

    def to_legacy_dict(self) -> dict[str, Any]:
        """Compatibility representation for pre-v1 fixtures during migration."""

        return {
            "schema_version": "1.0",
            "envelope_id": self.envelope_id,
            "incident_id": self.incident_id,
            "threat": self.threat,
            "confidence": self.confidence,
            "proposed_action": self.proposed_action,
            "target": self.target,
            "requested_scope": self.requested_scope,
            "reversible": self.reversible,
            "mission_impact": self.mission_impact,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "evidence": [asdict(item) for item in self.evidence],
            "human_approvals": list(self.human_approvals),
        }

    def canonical_json(self) -> str:
        return _canonical_json(self.to_canonical_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionEnvelope":
        """Parse canonical v1.0.0 or the deprecated pre-v1 representation."""

        if "action" in data or "freshness" in data or "evidence_refs" in data:
            freshness_raw = data.get("freshness", {})
            if not isinstance(freshness_raw, dict):
                raise ValidationError("freshness must be an object")
            evidence_raw = data.get("evidence_refs", [])
            if not isinstance(evidence_raw, list):
                raise ValidationError("evidence_refs must be a list")
            approvals_raw = data.get("human_approvals", [])
            if not isinstance(approvals_raw, list):
                raise ValidationError("human_approvals must be a list")
            return cls(
                schema_version=str(data.get("schema_version", "")),
                envelope_id=str(data.get("envelope_id", "")),
                incident_id=str(data.get("incident_id", "")),
                threat=str(data.get("threat", "")),
                confidence=float(data.get("confidence", -1.0)),
                proposed_action=str(data.get("action", "")),
                target=str(data.get("target", "")),
                requested_scope=str(data.get("scope", "")),
                reversible=bool(data.get("reversibility_flag", False)),
                mission_impact=str(data.get("mission_impact", "")),
                created_at=str(freshness_raw.get("timestamp", "")),
                expires_at=str(freshness_raw.get("expires_at", "")),
                nonce=str(freshness_raw.get("nonce", "")),
                evidence=tuple(Evidence.from_dict(item) for item in evidence_raw),
                human_approvals=tuple(str(item) for item in approvals_raw),
                actor=str(data.get("actor", "")),
                idempotency_key=str(data.get("idempotency_key", "")),
                required_approval_mode=str(data.get("required_approval_mode", "")),
                policy_version=str(data.get("policy_version", "")),
            )

        return cls._from_legacy_envelope_dict(data)

    @classmethod
    def _from_legacy_envelope_dict(cls, data: dict[str, Any]) -> "ActionEnvelope":
        evidence_raw = data.get("evidence", [])
        approvals_raw = data.get("human_approvals", [])
        if not isinstance(evidence_raw, list):
            raise ValidationError("evidence must be a list")
        if not isinstance(approvals_raw, list):
            raise ValidationError("human_approvals must be a list")
        action = str(data.get("proposed_action", "none"))
        return cls(
            schema_version=ACTION_ENVELOPE_VERSION,
            envelope_id=str(data.get("envelope_id", uuid4())),
            incident_id=str(data.get("incident_id", "unknown")),
            threat=str(data.get("threat", "unknown")),
            confidence=float(data.get("confidence", 0.0)),
            proposed_action=action,
            target=str(data.get("target", "simulated-resource:unknown")),
            requested_scope=str(
                data.get("requested_scope", _ACTION_SCOPE_DEFAULTS.get(action, "none"))
            ),
            reversible=bool(data.get("reversible", True)),
            mission_impact=str(data.get("mission_impact", "low")),
            created_at=str(data.get("created_at", format_time(utc_now()))),
            expires_at=str(
                data.get("expires_at", format_time(utc_now() + timedelta(seconds=120)))
            ),
            nonce=str(data.get("nonce", uuid4().hex)),
            evidence=tuple(Evidence.from_dict(item) for item in evidence_raw),
            human_approvals=tuple(str(item) for item in approvals_raw),
            actor=str(data.get("actor", "sentinel:legacy-adapter")),
            idempotency_key=str(data.get("idempotency_key", uuid4())),
            required_approval_mode=str(
                data.get(
                    "required_approval_mode",
                    _APPROVAL_MODE_DEFAULTS.get(action, "none"),
                )
            ),
            policy_version=str(data.get("policy_version", "0.0.0-legacy")),
        )

    @classmethod
    def from_legacy_incident(
        cls,
        incident: dict[str, Any],
        *,
        policy_version: str = "0.0.0-legacy",
        actor: str = "sentinel:legacy-simulator",
        ttl_seconds: int = 120,
        now: datetime | None = None,
    ) -> "ActionEnvelope":
        """Convert original simulator input into the v1.0.0 boundary contract.

        The shim is intentionally explicit and fail-closed: callers should pass the
        exact policy bundle version. The default legacy version will be rejected by
        a current Guardian, making unpinned migration mistakes visible.
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
        return cls(
            schema_version=ACTION_ENVELOPE_VERSION,
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
                    _ACTION_SCOPE_DEFAULTS.get(action, "none"),
                )
            ),
            reversible=bool(incident.get("reversible", True)),
            mission_impact=str(incident.get("mission_impact", "low")),
            created_at=format_time(created),
            expires_at=format_time(created + timedelta(seconds=ttl_seconds)),
            nonce=str(incident.get("nonce", uuid4().hex)),
            evidence=evidence,
            human_approvals=tuple(incident.get("human_approvals", [])),
            actor=str(incident.get("actor", actor)),
            idempotency_key=str(incident.get("idempotency_key", uuid4())),
            required_approval_mode=str(
                incident.get(
                    "required_approval_mode",
                    _APPROVAL_MODE_DEFAULTS.get(action, "none"),
                )
            ),
            policy_version=str(incident.get("policy_version", policy_version)),
        )
