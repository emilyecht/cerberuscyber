"""Strict, side-effect-free enforcement gateway for the research prototype."""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any

from .audit import AuditLedger
from .token import DecisionTokenSigner, TokenValidationError
from .state import ReplayDetected, SQLiteStateStore, StateUnavailable


class EnforcementDenied(PermissionError):
    """Raised when a requested execution is not exactly authorized."""


class ReplayCache:
    """One-time token registry used to reject replayed decisions."""

    def __init__(self) -> None:
        self._used: set[str] = set()
        self._idempotency: set[str] = set()
        self._lock = Lock()

    def consume(self, token_id: str, idempotency_key: str, envelope_digest: str) -> None:
        with self._lock:
            if token_id in self._used or idempotency_key in self._idempotency:
                raise ReplayDetected("decision token or idempotency replay detected")
            self._used.add(token_id)
            self._idempotency.add(idempotency_key)


class EnforcementGateway:
    """Validates authority and returns a simulated execution receipt.

    This class deliberately has no connector implementations and performs no external
    mutation. Production connectors should remain separate and least-privileged.
    """

    def __init__(
        self,
        signer: DecisionTokenSigner,
        *,
        replay_cache: ReplayCache | SQLiteStateStore | None = None,
        ledger: AuditLedger | None = None,
    ) -> None:
        self.signer = signer
        if replay_cache is None:
            raise ValueError("supply durable SQLiteStateStore, or explicit ReplayCache for an isolated simulation")
        self.replay_cache = replay_cache
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

        try:
            self.replay_cache.consume(
                payload["token_id"], payload["idempotency_key"], payload["envelope_digest"]
            )
        except (ReplayDetected, StateUnavailable) as exc:
            raise EnforcementDenied(str(exc)) from exc
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
            "action": action,
            "target": target,
            "scope": scope,
            "executed_at": executed_at,
        }
        record = self.ledger.append("enforcement.simulated", receipt)
        receipt["audit_record_hash"] = record.record_hash
        return receipt
