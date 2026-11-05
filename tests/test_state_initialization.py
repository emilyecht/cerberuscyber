# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Offline storage checks, each paired with a provisioned, DDL-free startup.

The positive control matters: refusing unavailable state must not become refusing
all state, and even a successful ordinary open must never attempt schema setup.
"""

import sqlite3

import pytest

from cerberus.state import ReplayDetected, SQLiteStateStore, StateUnavailable


@pytest.fixture
def normal_open(monkeypatch):
    connect = sqlite3.connect

    def open_store(path):
        statements = []

        def traced_connect(*args, **kwargs):
            connection = connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        with monkeypatch.context() as patch:
            patch.setattr(sqlite3, "connect", traced_connect)
            store = SQLiteStateStore(path, create=False)
        assert not any(
            sql.lstrip().upper().startswith(("CREATE", "ALTER", "DROP"))
            for sql in statements
        ), statements
        return store

    return open_store


@pytest.mark.parametrize("fault", [
    "zero-byte", "empty-schema", "truncated-header", "truncated-page", "corrupt",
    "wrong-columns", "missing-primary-key", "weakened-primary-key", "view",
    "claim-trigger", "missing", "directory", "symlink", "read-only", "locked",
])
def test_normal_open_refuses_unverifiable_state(tmp_path, normal_open, fault):
    path = tmp_path / "state.db"
    lock = None
    if fault == "zero-byte":
        path.touch()
    elif fault == "missing":
        pass
    elif fault == "directory":
        path.mkdir()
    else:
        SQLiteStateStore(path, create=True)
        if fault.startswith("truncated"):
            data = path.read_bytes()
            path.write_bytes(data[:64] if fault == "truncated-header" else data[:-1])
        elif fault == "corrupt":
            path.write_bytes(b"not a SQLite database")
        elif fault == "symlink":
            target = tmp_path / "target.db"
            path.rename(target)
            path.symlink_to(target)
        elif fault == "read-only":
            path.chmod(0o444)
        elif fault == "locked":
            lock = sqlite3.connect(path)
            lock.execute("BEGIN IMMEDIATE")
        else:
            with sqlite3.connect(path) as connection:
                if fault == "claim-trigger":
                    connection.execute(
                        "CREATE TRIGGER ignore_claim BEFORE INSERT ON claims "
                        "BEGIN SELECT RAISE(IGNORE); END"
                    )
                else:
                    connection.execute("DROP TABLE claims")
                    if fault == "wrong-columns":
                        connection.execute("CREATE TABLE claims (unrelated TEXT)")
                    elif fault in ("missing-primary-key", "weakened-primary-key"):
                        constraint = (
                            ", PRIMARY KEY(namespace, kind, claim_key, digest)"
                            if fault == "weakened-primary-key" else ""
                        )
                        connection.execute(
                            "CREATE TABLE claims (namespace TEXT NOT NULL, "
                            "kind TEXT NOT NULL, claim_key TEXT NOT NULL, "
                            "digest TEXT NOT NULL" + constraint + ")"
                        )
                    elif fault == "view":
                        connection.execute("CREATE VIEW claims AS SELECT 1 AS unrelated")
            connection.close()

    before = path.read_bytes() if path.is_file() else None
    try:
        with pytest.raises(StateUnavailable):
            SQLiteStateStore(path, create=False)
        if before is not None:
            assert path.read_bytes() == before
        elif fault == "missing":
            assert not path.exists()
        else:
            assert list(path.iterdir()) == []
    finally:
        if lock is not None:
            lock.rollback()
            lock.close()
        if fault == "read-only":
            path.chmod(0o644)

    control = tmp_path / "control.db"
    SQLiteStateStore(control, create=True)
    assert normal_open(control).claim("available-control", "synthetic-digest")


def test_explicit_provisioning_then_normal_use_preserves_claims(tmp_path, normal_open):
    path = tmp_path / "state.db"
    path.touch()
    with pytest.raises(StateUnavailable):
        SQLiteStateStore(path)
    assert path.read_bytes() == b""

    SQLiteStateStore(path, create=True)  # Separate, deliberate provisioning call.
    store = normal_open(path)
    assert store.claim("request", "synthetic-digest")
    store.consume("token", "execution", "synthetic-digest")
    reopened = normal_open(path)
    assert not reopened.claim("request", "another-digest")
    with pytest.raises(ReplayDetected):
        reopened.consume("token", "other-execution", "synthetic-digest")
    with pytest.raises(ReplayDetected):
        reopened.consume("other-token", "execution", "synthetic-digest")
    assert reopened.claim("new-request", "synthetic-digest")


def test_normal_open_never_creates_a_table(tmp_path, monkeypatch, normal_open):
    path = tmp_path / "unprovisioned.db"
    path.touch()
    statements = []
    connect = sqlite3.connect

    def traced_connect(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connection.set_trace_callback(statements.append)
        return connection

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", traced_connect)
        with pytest.raises(StateUnavailable):
            SQLiteStateStore(path)
    assert not any("CREATE" in sql.upper() for sql in statements), statements
    assert path.read_bytes() == b""
    connection = connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        assert connection.execute("SELECT name FROM sqlite_master").fetchall() == []
    finally:
        connection.close()

    SQLiteStateStore(path, create=True)
    before = path.read_bytes()
    normal_open(path)
    assert path.read_bytes() == before


def test_claim_rechecks_schema_after_startup(tmp_path, normal_open):
    path = tmp_path / "state.db"
    SQLiteStateStore(path, create=True)
    store = normal_open(path)
    with sqlite3.connect(path) as connection:
        connection.execute("ALTER TABLE claims RENAME TO old_claims")
        connection.execute("CREATE TABLE claims AS SELECT * FROM old_claims")
    connection.close()
    with pytest.raises(StateUnavailable):
        store.consume("token", "execution", "synthetic-digest")
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("SELECT count(*) FROM claims").fetchone() == (0,)
    finally:
        connection.close()
