"""Short-lived signed decision tokens for the prototype enforcement boundary."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from .models import ActionEnvelope, GuardianDecision, format_time, parse_time
from .freshness import evidence_deadline


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
        envelope.validate()
        if decision.guardian_decision != "approve":
            raise ValueError("tokens may only be issued for approved decisions")
        if decision.assurance_verified is not True or not isinstance(decision.assurance_digest, str) or re.fullmatch(r"[0-9a-f]{64}", decision.assurance_digest) is None:
            raise ValueError("tokens require verified evidence and approval assurance")
        envelope_digest = envelope.digest()
        if decision.envelope_digest != envelope_digest:
            raise ValueError("decision does not bind the supplied ActionEnvelope digest")
        if decision.idempotency_key != envelope.idempotency_key:
            raise ValueError("decision does not bind the supplied idempotency key")
        bindings = {
            "envelope_id": envelope.envelope_id,
            "incident_id": envelope.incident_id,
            "actor": envelope.actor,
            "proposed_action": envelope.proposed_action,
            "authorized_action": envelope.proposed_action,
            "target": envelope.target,
            "scope": envelope.requested_scope,
            "policy_version": envelope.policy_version,
            "reversible": envelope.reversible,
        }
        for name, expected in bindings.items():
            actual = getattr(decision, name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError(f"decision {name} does not match the supplied ActionEnvelope")
        if not envelope.has_supported_action_scope():
            raise ValueError("cannot sign an unsupported action/scope combination")

        issued = now or datetime.now(timezone.utc)
        if type(ttl_seconds) is not int or ttl_seconds <= 0:
            raise ValueError("decision TTL must be a positive integer")
        expires = min(
            evidence_deadline(envelope, issued), issued + timedelta(seconds=ttl_seconds),
            parse_time(decision.assurance_expires_at),
        )
        if expires <= issued:
            raise ValueError("verified assurance expired before token issuance")
        payload = {
            "token_version": self.TOKEN_VERSION,
            "token_id": uuid4().hex,
            "key_id": self.key_id,
            "envelope_id": envelope.envelope_id,
            "envelope_digest": envelope_digest,
            "assurance_digest": decision.assurance_digest,
            "idempotency_key": envelope.idempotency_key,
            "actor": envelope.actor,
            "incident_id": envelope.incident_id,
            "action": decision.authorized_action,
            "target": decision.target,
            "scope": decision.scope,
            "policy_id": decision.policy,
            "policy_version": decision.policy_version,
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
        if not isinstance(token, str) or not token.isascii() or len(token) > 16384:
            raise TokenValidationError("token must be bounded ASCII text")
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
        if not isinstance(payload, dict):
            raise TokenValidationError("token payload must be an object")
        required = {
            "token_version",
            "token_id",
            "key_id",
            "envelope_id",
            "envelope_digest",
            "assurance_digest",
            "idempotency_key",
            "actor",
            "incident_id",
            "action",
            "target",
            "scope",
            "policy_id",
            "policy_version",
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
        for field in ("envelope_digest", "assurance_digest"):
            if not isinstance(payload[field], str) or re.fullmatch(r"[0-9a-f]{64}", payload[field]) is None:
                raise TokenValidationError(f"invalid {field}")
        for field in required - {"reversible", "policy_id"}:
            if not isinstance(payload[field], str) or not payload[field]:
                raise TokenValidationError(f"invalid token field: {field}")
        if type(payload["reversible"]) is not bool:
            raise TokenValidationError("invalid reversibility flag")
        current = now or datetime.now(timezone.utc)
        try:
            expires = parse_time(payload["expires_at"])
            issued = parse_time(payload["issued_at"])
        except (ValueError, TypeError) as exc:
            raise TokenValidationError("invalid token timestamps") from exc
        if expires <= current or expires <= issued:
            raise TokenValidationError("decision token expired")
        if issued > current:
            raise TokenValidationError("decision token issued in the future")
        return payload
