# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Trusted, process-local registration and live revocation of issued tokens.

This is an issuer/controller interface, not a request-side admission service.
All gateways and revocation writers must share the same registry instance.
Loss of the registry makes old tokens unknown; there is no permissive fallback.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import hashlib
from threading import RLock
from typing import Iterator

from .token import DecisionTokenSigner

ENFORCEMENT_PURPOSE = "cerberus.enforcement"


class AuthorityStatusError(PermissionError):
    """Registered, live, correctly purposed authority cannot be established."""


@dataclass(frozen=True)
class _Registration:
    fingerprint: str
    envelope_digest: str
    issuer_key_id: str
    purpose: str
    dependencies: frozenset[str]


class TokenAuthorityRegistry:
    """Small trusted registry with a linearizable enforcement/revocation boundary.

    Registration requires a signature-valid issued token. It is performed by a
    trusted controller after authorization, never by the gateway or a worker.
    Records cannot be repurposed or reassigned; revocation cannot be undone by
    registering the same token again. This registry is deliberately not durable.
    """

    def __init__(self) -> None:
        self._records: dict[str, _Registration] = {}
        self._revoked_tokens: set[str] = set()
        self._revoked_authorities: set[str] = set()
        self._lock = RLock()
        self._available = True

    def _require_available(self) -> None:
        if not self._available:
            raise AuthorityStatusError("token authority registry is unavailable")

    def register(
        self, token: str, signer: DecisionTokenSigner, *,
        authority_key_ids: frozenset[str] = frozenset(),
        purpose: str = ENFORCEMENT_PURPOSE,
        now: datetime | None = None,
    ) -> None:
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValueError("token purpose must be a non-empty string")
        if not isinstance(authority_key_ids, frozenset) or any(not isinstance(k, str) or not k.strip() for k in authority_key_ids):
            raise ValueError("authority dependencies must be a frozenset of key IDs")
        payload = signer.verify(token, now=now)
        registration = _Registration(
            hashlib.sha256(token.encode("ascii")).hexdigest(),
            payload["envelope_digest"], payload["key_id"], purpose, authority_key_ids,
        )
        with self._lock:
            self._require_available()
            previous = self._records.get(payload["token_id"])
            if previous is not None and previous != registration:
                raise AuthorityStatusError("token registration cannot be changed")
            self._records[payload["token_id"]] = registration

    def revoke_token(self, token_id: str) -> None:
        if not isinstance(token_id, str) or not token_id:
            raise ValueError("token ID must be non-empty")
        with self._lock:
            self._require_available()
            self._revoked_tokens.add(token_id)

    def revoke_authority(self, key_id: str) -> None:
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("authority key ID must be non-empty")
        with self._lock:
            self._require_available()
            self._revoked_authorities.add(key_id)

    def close(self) -> None:
        with self._lock:
            self._available = False

    @contextmanager
    def authorize(self, token: str, payload: dict, *, purpose: str) -> Iterator[None]:
        # Hold the lock through replay consumption and receipt/audit commit.
        # A revocation is ordered either before or after that enforcement call.
        with self._lock:
            self._require_available()
            record = self._records.get(payload["token_id"])
            if record is None:
                raise AuthorityStatusError("decision token is not registered")
            if record.purpose != purpose:
                raise AuthorityStatusError("decision token has the wrong purpose")
            if record.fingerprint != hashlib.sha256(token.encode("ascii")).hexdigest() or record.envelope_digest != payload["envelope_digest"] or record.issuer_key_id != payload["key_id"]:
                raise AuthorityStatusError("decision token does not match its registration")
            if payload["token_id"] in self._revoked_tokens:
                raise AuthorityStatusError("decision token is revoked")
            if record.issuer_key_id in self._revoked_authorities or record.dependencies.intersection(self._revoked_authorities):
                raise AuthorityStatusError("decision token depends on revoked authority")
            yield
