"""Read-only Sentinel hunt logic for a simulated adversarial AI persistence threat.

This module correlates synthetic telemetry only. It performs no scanning, attribution,
containment, or external mutation. The output is an untrusted recommendation that must
still pass through the deterministic Guardian and signed enforcement boundary.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Any, Iterable

from .models import ActionEnvelope, Evidence, ValidationError, format_time, parse_time, utc_now


@dataclass(frozen=True)
class TelemetryEvent:
    """Normalized, read-only telemetry supplied to Sentinel."""

    event_id: str
    observed_at: str
    source_id: str
    asset: str
    event_type: str
    attributes: dict[str, Any]

    def validate(self) -> None:
        for name, value in {
            "event_id": self.event_id,
            "source_id": self.source_id,
            "asset": self.asset,
            "event_type": self.event_type,
        }.items():
            if not value.strip():
                raise ValidationError(f"telemetry.{name} is required")
        parse_time(self.observed_at)
        if not isinstance(self.attributes, dict):
            raise ValidationError("telemetry.attributes must be an object")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TelemetryEvent":
        event = cls(
            event_id=str(data.get("event_id", "")),
            observed_at=str(data.get("observed_at", "")),
            source_id=str(data.get("source_id", "")),
            asset=str(data.get("asset", "")),
            event_type=str(data.get("event_type", "")),
            attributes=dict(data.get("attributes", {})),
        )
        event.validate()
        return event


@dataclass(frozen=True)
class HuntFinding:
    """Advisory Sentinel result; never executable by itself."""

    threat: str
    target: str
    confidence: float
    signals: tuple[str, ...]
    independent_sources: tuple[str, ...]
    evidence: tuple[TelemetryEvent, ...]
    recommended_action: str
    requested_scope: str
    reversible: bool
    attribution_status: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["signals"] = list(self.signals)
        result["independent_sources"] = list(self.independent_sources)
        result["evidence"] = [asdict(item) for item in self.evidence]
        return result


class EmbeddedAgentHunter:
    """Deterministically correlates behaviors associated with covert AI persistence.

    The hunter intentionally does not infer nationality or sponsor. A claimed foreign
    origin is not evidence of compromise, and national attribution is outside the
    authority of this prototype. The finding is based on observable behavior and
    provenance failures only.

    New explicit event names mirror the defensive scenario vocabulary. Legacy aliases
    remain accepted so older synthetic fixtures continue to work without weakening the
    policy signal model.
    """

    INDICATORS: dict[str, tuple[str, float]] = {
        "anomalous_process_behavior": ("anomalous_process_behavior", 0.12),
        "hidden_persistence": ("hidden_persistence", 0.13),
        "runtime_persistence": ("hidden_persistence", 0.13),
        "credential_misuse": ("credential_misuse", 0.15),
        "service_identity_mismatch": ("credential_misuse", 0.15),
        "model_driven_deception": ("model_driven_deception", 0.15),
        "model_artifact_unsigned": ("model_provenance_failure", 0.10),
        "log_tampering": ("log_tampering", 0.16),
        "telemetry_tamper": ("log_tampering", 0.16),
        "covert_egress": ("covert_egress", 0.12),
        "policy_bypass_attempt": ("policy_bypass_attempt", 0.10),
    }

    REQUIRED_CORE_SIGNALS = {
        "anomalous_process_behavior",
        "hidden_persistence",
        "credential_misuse",
        "model_driven_deception",
        "log_tampering",
    }

    def hunt(
        self,
        events: Iterable[TelemetryEvent],
        *,
        asset: str,
    ) -> HuntFinding | None:
        """Return one advisory finding for ``asset`` or ``None`` when evidence is weak."""

        matched: list[TelemetryEvent] = []
        signals: set[str] = set()
        sources: set[str] = set()
        score = 0.20

        for event in events:
            event.validate()
            if event.asset != asset:
                continue
            indicator = self.INDICATORS.get(event.event_type)
            if indicator is None:
                continue
            signal, weight = indicator
            matched.append(event)
            sources.add(event.source_id)
            if signal not in signals:
                signals.add(signal)
                score += weight

        if len(signals) < 3 or len(sources) < 3:
            return None

        core_coverage = len(self.REQUIRED_CORE_SIGNALS.intersection(signals))
        if core_coverage == len(self.REQUIRED_CORE_SIGNALS):
            score += 0.07

        confidence = round(min(score, 0.99), 2)
        summary = (
            "Correlated process, persistence, credential, model-behavior, log-integrity, "
            "provenance, and egress anomalies indicate a possible embedded autonomous "
            "component. The result is behavior-based; sponsor and national attribution "
            "remain unverified."
        )
        return HuntFinding(
            threat="embedded_ai_agent",
            target=asset,
            confidence=confidence,
            signals=tuple(sorted(signals)),
            independent_sources=tuple(sorted(sources)),
            evidence=tuple(matched),
            recommended_action="quarantine_workload",
            requested_scope="single_workload",
            reversible=True,
            attribution_status="unverified",
            summary=summary,
        )

    def build_action_envelope(
        self,
        finding: HuntFinding,
        *,
        incident_id: str,
        human_approvals: Iterable[str] = (),
        ttl_seconds: int = 120,
    ) -> ActionEnvelope:
        """Convert a finding into an untrusted proposal for Guardian evaluation."""

        now = utc_now()
        evidence = tuple(
            Evidence(
                signal=self.INDICATORS[event.event_type][0],
                source_id=event.source_id,
                observed_at=event.observed_at,
                digest=event.attributes.get("digest"),
            )
            for event in finding.evidence
        )
        envelope = ActionEnvelope(
            schema_version="1.0",
            envelope_id=f"env-{incident_id.lower()}",
            incident_id=incident_id,
            threat=finding.threat,
            confidence=finding.confidence,
            proposed_action=finding.recommended_action,
            target=finding.target,
            requested_scope=finding.requested_scope,
            reversible=finding.reversible,
            mission_impact="high",
            created_at=format_time(now),
            expires_at=format_time(now + timedelta(seconds=ttl_seconds)),
            nonce=f"embedded-agent-{incident_id}-nonce",
            evidence=evidence,
            human_approvals=tuple(human_approvals),
        )
        envelope.validate()
        return envelope
