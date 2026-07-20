"""Typed data contracts for the CERBERUS authority boundary.

The versioned ActionEnvelope implementation lives in ``sdk.shared_types`` so
Sentinel, Guardian, Enforcement, and external integrations share one contract.
This module preserves the original import surface for existing callers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sdk.shared_types.action_envelope import (
    ACTION_ENVELOPE_VERSION,
    ActionEnvelope,
    Evidence,
    Freshness,
    ValidationError,
    format_time,
    parse_time,
    utc_now,
)


@dataclass(frozen=True)
class GuardianDecision:
    incident_id: str
    envelope_id: str
    guardian_decision: str
    reason: str
    policy: str | None
    policy_version: str
    policy_digest: str
    proposed_action: str
    authorized_action: str
    target: str
    scope: str
    reversible: bool
    human_approval_required: bool
    evidence: tuple[str, ...]
    independent_source_count: int
    envelope_digest: str
    idempotency_key: str
    actor: str
    decision_token: str | None = None
    audit_record_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        return result


__all__ = [
    "ACTION_ENVELOPE_VERSION",
    "ActionEnvelope",
    "Evidence",
    "Freshness",
    "GuardianDecision",
    "ValidationError",
    "format_time",
    "parse_time",
    "utc_now",
]
