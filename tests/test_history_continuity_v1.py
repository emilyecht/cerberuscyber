from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

import pytest

from benchmarks.history_continuity_v1.store import AnchoredHistory
from cerberus.state import ReplayDetected, StateUnavailable


@pytest.fixture
def history(tmp_path):
    anchor = tmp_path / "witness"
    anchor.mkdir()
    store = AnchoredHistory(tmp_path / "live.db", anchor, "fixture")
    store.provision()
    return store


def consume(store):
    store.consume("token", "execution", "fixture-digest")


def backup(store):
    return Path(shutil.copyfile(store.live, store.live.with_suffix(".backup")))


def test_fresh_and_valid_restore(history):
    assert history.claim("request", "digest")
    assert not history.claim("request", "digest")
    consume(history)
    saved = backup(history)
    history.live.unlink()
    with pytest.raises(StateUnavailable):
        consume(history)
    history.recover(saved)
    with pytest.raises(ReplayDetected):
        consume(history)
    assert history.claim("fresh", "digest")


@pytest.mark.parametrize("damage", ["rollback", "erased_rows", "namespace", "replacement",
                                    "missing_anchor", "malformed_anchor"])
def test_unverified_history_refuses_fresh_claim(history, damage):
    saved = backup(history)
    consume(history)
    if damage == "rollback":
        shutil.copyfile(saved, history.live)
        with pytest.raises(StateUnavailable):
            history.recover(saved)
    elif damage == "erased_rows":
        db = sqlite3.connect(history.live)
        with db:
            db.execute("DELETE FROM claims")
        db.close()
    elif damage == "namespace":
        history = AnchoredHistory(history.live, history.anchor.parent, "other")
    elif damage == "replacement":
        backup(history).replace(history.live)
    elif damage == "missing_anchor":
        history.anchor.unlink()
    else:
        history.anchor.write_bytes(b"invalid")
    with pytest.raises(StateUnavailable):
        history.claim("unused", "digest")


def test_process_death_during_restore(history):
    consume(history)
    saved = backup(history)
    script = """
import os, sys
from benchmarks.history_continuity_v1.store import AnchoredHistory
h = AnchoredHistory(sys.argv[1], sys.argv[2], 'fixture')
h._install = lambda stage: os._exit(77)
h.recover(sys.argv[3])
"""
    process = subprocess.run([sys.executable, "-c", script, history.live, history.anchor.parent, saved])
    assert process.returncode == 77
    with pytest.raises(StateUnavailable):
        history.claim("fresh", "digest")
    history.recover(saved)
    with pytest.raises(ReplayDetected):
        consume(history)
    assert history.claim("fresh", "digest")
