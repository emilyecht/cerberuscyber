"""Strict, side-effect-free enforcement gateway for the research prototype."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .audit import AuditLedger
from .token import DecisionTokenSigner, TokenValidationError


class EnforcementDenied(PermissionError):
    """Raised when a requested execution is not exactly authorized."""


class ReplayCache:
    """One-time token registry used to reject replayed decisions."""

    def __init__(self) -> None:
        self._used: set[str] = set()

    def consume(self, token_id: str) -> None:
        if token_id in self._used:
            raise EnforcementDenied("decision token replay detected")
        self._used.add(token_id)


class EnforcementGateway:
    """Validates authority and returns a simulated execution receipt.

    This class deliberately has no connector implementations and performs no external
    mutation. Production connectors should remain separate and least-privileged.
    """

    def __init__(
        self,
        signer: DecisionTokenSigner,
        *,
        replay_cache: ReplayCache | None = None,
        ledger: AuditLedger | None = None,
    ) -> None:
        self.signer = signer
        self.replay_cache = replay_cache or ReplayCache()
        self.ledger = ledger or AuditLedger()

    def authorize_and_simulate(
        self,
        token: str,
        *,
        action: str,
        target: str,
        scope: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        try:
            payload = self.signer.verify(token, now=now)
        except TokenValidationError as exc:
            raise EnforcementDenied(str(exc)) from exc

        comparisons = {
            "action": action,
            "target": target,
            "scope": scope,
        }
        for field, requested in comparisons.items():
            if payload[field] != requested:
                raise EnforcementDenied(f"{field} does not match signed authorization")

        self.replay_cache.consume(str(payload["token_id"]))
        executed_at = (now or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
        receipt = {
            "status": "simulated",
            "side_effects": False,
            "token_id": payload["token_id"],
            "envelope_id": payload["envelope_id"],
            "envelope_digest": payload["envelope_digest"],
            "idempotency_key": payload["idempotency_key"],
            "actor": payload["actor"],
            "incident_id": payload["incident_id"],
            "policy_version": payload["policy_version"],
            "policy_digest": payload["policy_digest"],
            "action": action,
            "target": target,
            "scope": scope,
            "executed_at": executed_at,
        }
        record = self.ledger.append("enforcement.simulated", receipt)
        receipt["audit_record_hash"] = record.record_hash
        return receipt
