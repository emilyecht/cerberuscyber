"""Short-lived signed decision tokens for the prototype enforcement boundary."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from .models import ActionEnvelope, GuardianDecision, format_time, parse_time


class TokenValidationError(ValueError):
    """Raised when a decision token is invalid, expired, or malformed."""


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + padding)
    except (ValueError, TypeError) as exc:
        raise TokenValidationError("invalid base64url token segment") from exc


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class DecisionTokenSigner:
    """HMAC signer for the research prototype.

    Production deployments should replace this with hardware-backed asymmetric keys,
    key rotation, and deployment-specific trust roots.
    """

    TOKEN_VERSION = "1.2.0"

    def __init__(self, key: bytes, *, key_id: str = "prototype-hmac-v1") -> None:
        if len(key) < 32:
            raise ValueError("signing key must be at least 32 bytes")
        self._key = key
        self.key_id = key_id

    def issue(
        self,
        decision: GuardianDecision,
        envelope: ActionEnvelope,
        *,
        ttl_seconds: int,
        now: datetime | None = None,
    ) -> str:
        if decision.guardian_decision != "approve":
            raise ValueError("tokens may only be issued for approved decisions")
        envelope_digest = envelope.digest()
        if decision.envelope_digest != envelope_digest:
            raise ValueError("decision does not bind the supplied ActionEnvelope digest")
        if decision.idempotency_key != envelope.idempotency_key:
            raise ValueError("decision does not bind the supplied idempotency key")
        if len(decision.policy_digest) != 64:
            raise ValueError("decision does not contain a valid policy digest")

        issued = now or datetime.now(timezone.utc)
        expires = min(parse_time(envelope.expires_at), issued + timedelta(seconds=ttl_seconds))
        payload = {
            "token_version": self.TOKEN_VERSION,
            "token_id": uuid4().hex,
            "key_id": self.key_id,
            "envelope_id": envelope.envelope_id,
            "envelope_digest": envelope_digest,
            "idempotency_key": envelope.idempotency_key,
            "actor": envelope.actor,
            "incident_id": envelope.incident_id,
            "action": decision.authorized_action,
            "target": decision.target,
            "scope": decision.scope,
            "policy_id": decision.policy,
            "policy_version": decision.policy_version,
            "policy_digest": decision.policy_digest,
            "issued_at": format_time(issued),
            "expires_at": format_time(expires),
            "nonce": envelope.nonce,
            "reversible": decision.reversible,
        }
        encoded = _b64encode(_canonical(payload))
        signature = _b64encode(
            hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        return f"{encoded}.{signature}"

    def verify(self, token: str, *, now: datetime | None = None) -> dict[str, Any]:
        try:
            encoded, signature = token.split(".", 1)
        except ValueError as exc:
            raise TokenValidationError("token must contain payload and signature") from exc
        expected = hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).digest()
        supplied = _b64decode(signature)
        if not hmac.compare_digest(expected, supplied):
            raise TokenValidationError("invalid token signature")
        try:
            payload = json.loads(_b64decode(encoded))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TokenValidationError("invalid token payload") from exc
        required = {
            "token_version",
            "token_id",
            "key_id",
            "envelope_id",
            "envelope_digest",
            "idempotency_key",
            "actor",
            "incident_id",
            "action",
            "target",
            "scope",
            "policy_id",
            "policy_version",
            "policy_digest",
            "issued_at",
            "expires_at",
            "nonce",
            "reversible",
        }
        missing = sorted(required.difference(payload))
        if missing:
            raise TokenValidationError(f"token missing fields: {', '.join(missing)}")
        if payload["token_version"] != self.TOKEN_VERSION:
            raise TokenValidationError("unsupported token version")
        if payload["key_id"] != self.key_id:
            raise TokenValidationError("unexpected signing key id")
        for field in ("envelope_digest", "policy_digest"):
            value = payload[field]
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise TokenValidationError(f"invalid {field.replace('_', ' ')}")
        current = now or datetime.now(timezone.utc)
        if parse_time(payload["expires_at"]) <= current:
            raise TokenValidationError("decision token expired")
        if parse_time(payload["issued_at"]) > current + timedelta(seconds=30):
            raise TokenValidationError("decision token issued in the future")
        return payload
