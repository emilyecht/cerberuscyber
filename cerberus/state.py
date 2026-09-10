"""Durable atomic replay/idempotency claims for a single-host SQLite store.

All participating instances/processes must use the same trusted database and
namespace. This is not a distributed consensus store or an exactly-once connector.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


class StateUnavailable(PermissionError):
    """No authority may proceed without a confirmed durable claim."""


class ReplayDetected(PermissionError):
    """A token or execution idempotency key has already been consumed."""


class SQLiteStateStore:
    def __init__(self, path: str | Path, *, namespace: str = "cerberus", create: bool = False) -> None:
        if not isinstance(namespace, str) or not namespace.strip():
            raise ValueError("state namespace must be non-empty")
        if str(path) in ("", ":memory:"):
            raise ValueError("durable state requires an explicit filesystem path")
        self.path = str(Path(path).resolve())
        self.namespace = namespace
        connection = None
        try:
            connection = self._connect(create=create)
            with connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS claims ("
                    "namespace TEXT NOT NULL, kind TEXT NOT NULL, claim_key TEXT NOT NULL, "
                    "digest TEXT NOT NULL, PRIMARY KEY(namespace, kind, claim_key))"
                )
        except sqlite3.Error as exc:
            raise StateUnavailable("cannot initialize durable authority state") from exc
        finally:
            if connection is not None:
                connection.close()

    def _connect(self, *, create: bool = False) -> sqlite3.Connection:
        uri = Path(self.path).as_uri() + ("?mode=rwc" if create else "?mode=rw")
        connection = sqlite3.connect(uri, timeout=2.0, uri=True)
        try:
            connection.execute("PRAGMA synchronous=FULL")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    def _claim(self, rows: list[tuple[str, str, str]]) -> bool:
        connection = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            for kind, key, digest in rows:
                if not isinstance(key, str) or not key:
                    raise ValueError("state claim key must be a non-empty string")
                connection.execute(
                    "INSERT INTO claims(namespace, kind, claim_key, digest) VALUES (?, ?, ?, ?)",
                    (self.namespace, kind, key, digest),
                )
            connection.commit()
            return True
        except sqlite3.IntegrityError:
            if connection is not None:
                connection.rollback()
            return False
        except sqlite3.Error as exc:
            if connection is not None:
                connection.rollback()
            raise StateUnavailable("durable authority state unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    def claim(self, idempotency_key: str, envelope_digest: str) -> bool:
        return self._claim([("envelope", idempotency_key, envelope_digest)])

    def consume(self, token_id: str, idempotency_key: str, envelope_digest: str) -> None:
        # Both constraints commit together. A second valid token for the same
        # request cannot create another effect, even after a Guardian restart.
        if not self._claim([
            ("token", token_id, envelope_digest),
            ("execution", idempotency_key, envelope_digest),
        ]):
            raise ReplayDetected("token or execution idempotency key already consumed")
