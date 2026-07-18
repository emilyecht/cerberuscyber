"""Append-only hash-chained audit records for prototype assurance evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def _canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    occurred_at: str
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    record_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "occurred_at": self.occurred_at,
            "event_type": self.event_type,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }


class AuditLedger:
    """In-memory prototype ledger with tamper-evident hash chaining."""

    GENESIS_HASH = "0" * 64

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditRecord:
        previous_hash = self._records[-1].record_hash if self._records else self.GENESIS_HASH
        occurred_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        body = {
            "sequence": len(self._records) + 1,
            "occurred_at": occurred_at,
            "event_type": event_type,
            "payload": payload,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(_canonical(body)).hexdigest()
        record = AuditRecord(record_hash=record_hash, **body)
        self._records.append(record)
        return record

    def verify(self) -> bool:
        previous_hash = self.GENESIS_HASH
        for index, record in enumerate(self._records, start=1):
            body = {
                "sequence": record.sequence,
                "occurred_at": record.occurred_at,
                "event_type": record.event_type,
                "payload": record.payload,
                "previous_hash": record.previous_hash,
            }
            if record.sequence != index:
                return False
            if record.previous_hash != previous_hash:
                return False
            if hashlib.sha256(_canonical(body)).hexdigest() != record.record_hash:
                return False
            previous_hash = record.record_hash
        return True
