# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""The temporary marker effect must stay inside live authority and time bounds."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from threading import Event

import pytest

from cerberus import enforcement, token
from cerberus import lab_demo as lab
from cerberus.models import parse_time
from cerberus.state import ReplayDetected, SQLiteStateStore
from tests.test_lab_demo import authorized_lab


@pytest.mark.parametrize("delay_at", ["consume", "receipt_audit"])
def test_expiry_during_authorization_never_writes_marker(authorized_lab, monkeypatch, delay_at):
    broker, command, _, _ = authorized_lab
    payload = broker.signer.verify(command["token"])
    expiry = parse_time(payload["expires_at"])
    current = [expiry - timedelta(microseconds=1)]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return current[0]

    for module in (lab, enforcement, token):
        monkeypatch.setattr(module, "datetime", Clock)
    if delay_at == "consume":
        original = SQLiteStateStore.consume

        def delayed(store, *args):
            original(store, *args)
            current[0] = expiry

        monkeypatch.setattr(SQLiteStateStore, "consume", delayed)
    else:
        original = broker.ledger.append

        def delayed(kind, data):
            record = original(kind, data)
            if kind == "enforcement.simulated":
                current[0] = expiry
            return record

        monkeypatch.setattr(broker.ledger, "append", delayed)
    result = broker.execute(command)
    assert result["status"] == "blocked" and "expired" in result["reason"]
    assert (broker.directory / "egress.marker").read_bytes() == lab.OPEN
    assert broker.writes == 0
    # Refusal after consumption burns authority; it must not enable a retry.
    with pytest.raises(ReplayDetected):
        SQLiteStateStore(broker.directory / "claims.db").consume(
            payload["token_id"], payload["idempotency_key"], payload["envelope_digest"])


def test_revocation_is_ordered_after_effect_commit(authorized_lab, monkeypatch):
    broker, command, _, _ = authorized_lab
    payload = broker.signer.verify(command["token"])
    entered_write, release_write = Event(), Event()
    revoke_requested, revoke_completed = Event(), Event()
    original_write = Path.write_bytes

    def blocked_write(path, data):
        if path == broker.directory / "egress.marker":
            entered_write.set()
            assert release_write.wait(3), "test did not release marker write"
            # A complete revocation before this write would invalidate the effect.
            assert not revoke_completed.is_set()
        return original_write(path, data)

    def revoke():
        revoke_requested.set()
        broker.authority_registry.revoke_token(payload["token_id"])
        revoke_completed.set()

    monkeypatch.setattr(Path, "write_bytes", blocked_write)
    with ThreadPoolExecutor(max_workers=2) as pool:
        effect = pool.submit(broker.execute, command)
        try:
            assert entered_write.wait(3)
            revocation = pool.submit(revoke)
            assert revoke_requested.wait(3)
            assert not revoke_completed.wait(0.1), "revocation escaped the effect boundary"
        finally:
            release_write.set()
        assert effect.result(timeout=3)["status"] == "executed-local-marker"
        revocation.result(timeout=3)
    assert revoke_completed.is_set()
    assert broker.execute(command)["status"] == "blocked"
    assert broker.writes == 1


@pytest.mark.parametrize("damage", ["missing", "zero", "corrupt"])
def test_unavailable_store_is_a_controlled_broker_refusal(authorized_lab, damage):
    broker, command, _, _ = authorized_lab
    path = broker.directory / "claims.db"
    if damage == "missing":
        path.unlink()
    else:
        path.write_bytes(b"" if damage == "zero" else b"corrupt state")
    assert broker.execute(command)["status"] == "blocked"
    assert (broker.directory / "egress.marker").read_bytes() == lab.OPEN
    assert broker.writes == 0


def test_revoked_authority_never_reaches_effect(authorized_lab):
    broker, command, _, _ = authorized_lab
    payload = broker.signer.verify(command["token"])
    broker.authority_registry.revoke_token(payload["token_id"])
    assert broker.execute(command)["status"] == "blocked"
    assert (broker.directory / "egress.marker").read_bytes() == lab.OPEN
    assert broker.writes == 0
