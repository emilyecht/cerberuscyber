# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Regressions from the separate SQLite review; no frozen benchmark changes."""
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from cerberus import DecisionTokenSigner, EnforcementDenied, Guardian
from cerberus import enforcement, token
from cerberus.state import ReplayDetected, SQLiteStateStore, StateUnavailable
from simulator.assurance_fixtures import fixture_assurance
from tests.assurance_support import registered_gateway
from tests.test_assurance_hardening import KEY, NOW, POLICIES, request


@pytest.mark.parametrize("operation", ["ordinary-open", "existing-claim", "explicit-provision"])
def test_wal_state_cannot_supply_authority(tmp_path, operation):
    path = tmp_path/"state.db"
    store = SQLiteStateStore(path, create=True)
    store.consume("used-token", "used-execution", "synthetic-digest")
    con = sqlite3.connect(path)
    assert con.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    con.close()
    with pytest.raises(StateUnavailable) as refused:
        if operation == "ordinary-open": SQLiteStateStore(path)
        elif operation == "existing-claim": store.consume("fresh-token", "fresh-execution", "synthetic-digest")
        else: SQLiteStateStore(path, create=True)
    assert isinstance(refused.value.__cause__, StateUnavailable)
    assert "DELETE journal" in str(refused.value.__cause__)
    con = sqlite3.connect(path)
    assert con.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    assert con.execute("SELECT count(*) FROM claims").fetchone() == (2,)
    con.close()
    healthy = SQLiteStateStore(tmp_path/"control.db", create=True)
    healthy.consume("token", "execution", "synthetic-digest")
    with pytest.raises(ReplayDetected): healthy.consume("token", "execution", "synthetic-digest")


def test_corrupt_committed_wal_is_not_mistaken_for_verified_history(tmp_path):
    path = tmp_path/"state.db"
    SQLiteStateStore(path, create=True)
    # Build the exact legacy crash artifact with SQLite itself. Both claims are
    # committed and observed by a second connection before abrupt child exit.
    child = '''import os,sqlite3,sys
p=sys.argv[1]
keeper=sqlite3.connect(p)
assert keeper.execute("PRAGMA journal_mode=WAL").fetchone()==("wal",)
keeper.execute("BEGIN")
keeper.execute("SELECT count(*) FROM claims").fetchone()
writer=sqlite3.connect(p)
writer.executemany("INSERT INTO claims VALUES (?,?,?,?)",[
 ("cerberus","token","used-token","synthetic-digest"),
 ("cerberus","execution","used-execution","synthetic-digest")])
writer.commit()
observer=sqlite3.connect(p)
assert observer.execute("SELECT count(*) FROM claims").fetchone()==(2,)
print("two committed claims independently observed",flush=True)
os._exit(0)
'''
    completed = subprocess.run([sys.executable,"-c",child,str(path)],check=True,text=True,capture_output=True)
    assert completed.stdout.strip() == "two committed claims independently observed"
    wal = Path(str(path)+"-wal")
    data = bytearray(wal.read_bytes()); data[-1] ^= 1; wal.write_bytes(data)
    # Demonstrate why structural integrity alone is insufficient after recovery.
    con = sqlite3.connect(path)
    assert con.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
    assert con.execute("SELECT count(*) FROM claims").fetchone() == (0,)
    con.close()
    with pytest.raises(StateUnavailable) as refused:
        SQLiteStateStore(path)
    assert isinstance(refused.value.__cause__, StateUnavailable)
    assert "DELETE journal" in str(refused.value.__cause__)


@pytest.mark.parametrize("crosses_deadline", [False, True])
def test_real_clock_is_rechecked_after_durable_consumption(tmp_path, monkeypatch, crosses_deadline):
    env = request()
    verifier, proofs = fixture_assurance(env)
    signer = DecisionTokenSigner(KEY)
    decision = Guardian(POLICIES,signer=signer,assurance_verifier=verifier).evaluate(env,assurance=proofs,now=NOW)
    expiry = datetime.fromisoformat(signer.verify(decision.decision_token,now=NOW)["expires_at"].replace("Z","+00:00"))
    current = [expiry-timedelta(microseconds=1)]

    class Clock(datetime):
        @classmethod
        def now(cls,tz=None): return current[0]

    store = SQLiteStateStore(tmp_path/"state.db",create=True)

    class BlockingConsumption:
        def consume(self,*args):
            store.consume(*args)
            # Deterministic stand-in for lock wait / integrity scan. No sleep,
            # fake token, disabled replay check, or frozen expected-label edit.
            current[0] = expiry if crosses_deadline else expiry-timedelta(microseconds=1)

    gateway = registered_gateway(signer,decision.decision_token,now=NOW,replay_cache=BlockingConsumption())
    monkeypatch.setattr(enforcement,"datetime",Clock)
    monkeypatch.setattr(token,"datetime",Clock)

    def execute():
        return gateway.authorize_and_simulate(decision.decision_token,expected_envelope=env,
            action=env.action,target=env.target,scope=env.scope)

    if crosses_deadline:
        with pytest.raises(EnforcementDenied,match="expired during durable consumption"): execute()
        assert gateway.ledger.records == ()
    else:
        assert execute()["executed_at"] == current[0].isoformat().replace("+00:00","Z")
        assert len(gateway.ledger.records) == 1
    payload = signer.verify(decision.decision_token,now=NOW)
    with pytest.raises(ReplayDetected):
        store.consume(payload["token_id"],payload["idempotency_key"],payload["envelope_digest"])
