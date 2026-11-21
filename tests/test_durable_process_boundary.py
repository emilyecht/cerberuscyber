# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""OS-process contention, atomic two-key claims and interrupted transactions."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from cerberus.state import ReplayDetected, SQLiteStateStore


def test_separate_processes_contend_for_one_execution(tmp_path):
    path = tmp_path / "claims.db"
    SQLiteStateStore(path, create=True)
    child = '''import sys
from cerberus.state import SQLiteStateStore,ReplayDetected
s=SQLiteStateStore(sys.argv[1])
print("ready",flush=True)
assert sys.stdin.readline().strip()=="consume"
try:
 s.consume(sys.argv[2],"same-execution","digest")
 print("consumed",flush=True)
except ReplayDetected:
 print("replay-refused",flush=True)
'''
    children = []
    try:
        for index in range(8):
            children.append(subprocess.Popen(
                [sys.executable, "-c", child, str(path), "token-" + str(index)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        with ThreadPoolExecutor(max_workers=8) as pool:
            readiness = list(pool.map(lambda p: p.stdout.readline().strip(), children))
        assert readiness == ["ready"] * 8
        # All independent processes opened and verified the store before release.
        for process in children:
            process.stdin.write("consume\n")
            process.stdin.flush()
        with ThreadPoolExecutor(max_workers=8) as pool:
            outputs = list(pool.map(lambda p: p.communicate(timeout=10), children))
        assert all(p.returncode == 0 for p in children), outputs
        outcomes = [stdout.strip() for stdout, _ in outputs]
        assert outcomes.count("consumed") == 1
        assert outcomes.count("replay-refused") == 7
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT kind,count(*) FROM claims GROUP BY kind ORDER BY kind").fetchall() == [
                ("execution", 1), ("token", 1)]
    finally:
        for process in children:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)


def test_second_constraint_conflict_rolls_back_the_first_claim(tmp_path):
    path = tmp_path / "claims.db"
    store = SQLiteStateStore(path, create=True)
    store.consume("first-token", "execution", "digest")
    with pytest.raises(ReplayDetected):
        store.consume("new-token", "execution", "digest")
    # A failed second insert must not leave the first insert consumed.
    SQLiteStateStore(path).consume("new-token", "other-execution", "digest")


def test_process_death_before_commit_preserves_prior_claims(tmp_path):
    path = tmp_path / "claims.db"
    store = SQLiteStateStore(path, create=True)
    store.consume("committed-token", "committed-execution", "digest")
    child = '''import os,sqlite3,sys
c=sqlite3.connect(sys.argv[1]);c.execute("PRAGMA synchronous=FULL")
c.execute("BEGIN IMMEDIATE")
c.execute("INSERT INTO claims VALUES ('cerberus','token','uncommitted-token','digest')")
os._exit(17)
'''
    result = subprocess.run([sys.executable, "-c", child, str(path)], timeout=10)
    assert result.returncode == 17
    reopened = SQLiteStateStore(path)
    with pytest.raises(ReplayDetected):
        reopened.consume("committed-token", "committed-execution", "digest")
    reopened.consume("uncommitted-token", "fresh-execution", "digest")
