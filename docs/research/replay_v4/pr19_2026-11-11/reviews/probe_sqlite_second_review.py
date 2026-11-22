"""Local adversarial probes; source tree and benchmark results remain untouched."""
from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path('/workspace/scratch/379e5a226cc0/sqlite-review')
OUT = Path('/workspace/scratch/379e5a226cc0/ai-review')
sys.path.insert(0, str(ROOT))

from cerberus import ActionEnvelope, DecisionTokenSigner, EnforcementGateway, Guardian, TokenAuthorityRegistry
from cerberus.models import parse_time
from cerberus.state import SQLiteStateStore, ReplayDetected, StateUnavailable
from simulator.assurance_fixtures import fixture_assurance

EVENTS = []


def event(name, **data):
    value = {'probe': name, **data}
    EVENTS.append(value)
    print(json.dumps(value), flush=True)


def attempt_claim(args):
    path, i = args
    try:
        SQLiteStateStore(path).consume('shared-token', 'shared-execution', 'a' * 64)
        return 'accepted'
    except ReplayDetected:
        return 'replayed'
    except StateUnavailable:
        return 'unavailable'


def controls(base):
    path = base / 'atomic.db'
    store = SQLiteStateStore(path, create=True)
    store.consume('token-a', 'execution-a', 'a' * 64)
    try:
        store.consume('token-b', 'execution-a', 'b' * 64)
    except ReplayDetected:
        pass
    else:
        raise AssertionError('execution collision accepted')
    # The failed second insert must not consume token-b.
    store.consume('token-b', 'execution-b', 'b' * 64)
    try:
        SQLiteStateStore(path).consume('token-b', 'execution-c', 'b' * 64)
    except ReplayDetected:
        event('atomic_conflict_restart', passed=True)
    else:
        raise AssertionError('restart replay accepted')

    path = base / 'concurrent.db'
    SQLiteStateStore(path, create=True)
    with ProcessPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt_claim, [(str(path), i) for i in range(8)]))
    assert outcomes.count('accepted') == 1, outcomes
    event('multiprocess_replay', outcomes=outcomes)


def trust_boundaries(base):
    path, snapshot = base / 'rollback.db', base / 'snapshot.db'
    store = SQLiteStateStore(path, create=True)
    shutil.copy2(path, snapshot)
    store.consume('already-used', 'already-used', 'a' * 64)
    try:
        store.consume('already-used', 'already-used', 'a' * 64)
    except ReplayDetected:
        pass
    else:
        raise AssertionError('normal replay accepted')
    os.replace(snapshot, path)
    store.consume('already-used', 'already-used', 'a' * 64)
    event('valid_snapshot_rollback', replay_accepted=True,
          scope='Documented trusted-storage limitation; also present in parent')

    path, target = base / 'race.db', base / 'race-target.db'
    SQLiteStateStore(path, create=True)
    SQLiteStateStore(target, create=True)
    real_connect = sqlite3.connect
    injected = False

    def swap_before_open(*args, **kwargs):
        nonlocal injected
        if not injected and str(args[0]).startswith(path.as_uri()):
            path.unlink()
            path.symlink_to(target)
            injected = True
        return real_connect(*args, **kwargs)

    sqlite3.connect = swap_before_open
    try:
        raced = SQLiteStateStore(path)
    finally:
        sqlite3.connect = real_connect
    # The first open follows the newly installed symlink; a later open rejects it.
    try:
        raced.claim('race-claim', 'a' * 64)
    except StateUnavailable:
        subsequent_rejected = True
    else:
        subsequent_rejected = False
    event('lstat_open_race', initialization_accepted_symlink=injected,
          subsequent_claim_rejected=subsequent_rejected,
          scope='Requires modification of trusted path; no authority bypass established')


def benchmark(base):
    old = subprocess.run(['git', 'show',
        'f0ebd38c58e9d40af35d35c5cc32b5614eb60439:cerberus/state.py'],
        cwd=ROOT, check=True, text=True, capture_output=True).stdout
    namespace = {'__name__': 'review_parent_state'}
    exec(compile(old, '<parent-state.py>', 'exec'), namespace)
    ParentState = namespace['SQLiteStateStore']

    path = base / 'history.db'
    SQLiteStateStore(path, create=True)
    previous = 0
    for n in (0, 10_000, 100_000, 500_000):
        with sqlite3.connect(path) as connection:
            connection.executemany(
                'INSERT INTO claims VALUES (?, ?, ?, ?)',
                (('cerberus', 'envelope', f'history-{i:032d}', 'a' * 64)
                 for i in range(previous, n)))
        previous = n
        timing = {}
        for label, klass in (('parent', ParentState), ('pr', SQLiteStateStore)):
            start = time.perf_counter()
            store = klass(path)
            timing[f'{label}_open_seconds'] = time.perf_counter() - start
            durations = []
            for repeat in range(3):
                start = time.perf_counter()
                assert store.claim(f'benchmark-{label}-{n}-{repeat}', 'a' * 64)
                durations.append(time.perf_counter() - start)
            timing[f'{label}_claim_median_seconds'] = statistics.median(durations)
        event('history_cost', history_rows=n, database_bytes=path.stat().st_size, **timing)
        if n == 500_000:
            for label, klass in (('parent', ParentState), ('pr', SQLiteStateStore)):
                store = klass(path)
                barrier = threading.Barrier(8)

                def burst(i):
                    barrier.wait()
                    start = time.perf_counter()
                    try:
                        accepted = store.claim(f'burst-{label}-{i}', 'a' * 64)
                        return {'outcome': 'accepted' if accepted else 'replayed',
                                'seconds': time.perf_counter() - start}
                    except Exception as exc:
                        return {'outcome': type(exc).__name__,
                                'seconds': time.perf_counter() - start}

                with ThreadPoolExecutor(max_workers=8) as pool:
                    outcomes = list(pool.map(burst, range(8)))
                event('healthy_history_burst', implementation=label, history_rows=n,
                      outcomes=outcomes)


def expiry_after_wait(base):
    policies = json.loads((ROOT / 'policies/policies.json').read_text())
    start = datetime.now(timezone.utc)
    incident = {
        'incident_id': 'SECOND-AI-REVIEW', 'threat': 'ransomware', 'confidence': 0.99,
        'signals': ['rapid_file_rewrite', 'recovery_deletion_attempt'],
        'proposed_action': 'isolate_endpoint', 'target': 'endpoint:review-sandbox',
    }
    envelope = ActionEnvelope.from_legacy_incident(incident, policy_version=policies['version'], now=start)
    verifier, bundle = fixture_assurance(envelope)
    signer = DecisionTokenSigner(b'public-second-ai-review-key-material-only-32')
    decision = Guardian(policies, signer=signer, assurance_verifier=verifier).evaluate(envelope, assurance=bundle)
    assert decision.guardian_decision == 'approve'
    # One-second genuine token, registered while valid. No signatures or callers
    # are mutated after issuance.
    token = signer.issue(decision, envelope, ttl_seconds=1)
    payload = signer.verify(token)
    registry = TokenAuthorityRegistry()
    registry.register(token, signer)
    path = base / 'expiry.db'
    store = SQLiteStateStore(path, create=True)
    gateway = EnforcementGateway(signer, replay_cache=store, authority_registry=registry)
    locked = threading.Event()

    def lock_database():
        connection = sqlite3.connect(path)
        connection.execute('BEGIN IMMEDIATE')
        locked.set()
        time.sleep(1.25)
        connection.rollback()
        connection.close()

    blocker = threading.Thread(target=lock_database)
    blocker.start()
    assert locked.wait(2)
    before = datetime.now(timezone.utc)
    receipt = gateway.authorize_and_simulate(token, expected_envelope=envelope,
        action=envelope.action, target=envelope.target, scope=envelope.scope)
    after = datetime.now(timezone.utc)
    blocker.join()
    expiry = parse_time(payload['expires_at'])
    assert before < expiry < after
    event('expiry_during_sqlite_wait', call_started=before.isoformat(), expires_at=expiry.isoformat(),
          receipt_returned=after.isoformat(), receipt_executed_at=receipt['executed_at'],
          receipt_status=receipt['status'], seconds_past_expiry=(after - expiry).total_seconds(),
          scope='Enforcement placement predates PR; new full scans enlarge gap')


if __name__ == '__main__':
    event('environment', python=sys.version.split()[0], sqlite=sqlite3.sqlite_version)
    with tempfile.TemporaryDirectory(prefix='second-ai-', dir=OUT) as temporary:
        base = Path(temporary)
        controls(base)
        trust_boundaries(base)
        benchmark(base)
        expiry_after_wait(base)
    (OUT / 'probe_results.json').write_text(json.dumps(EVENTS, indent=2) + '\n')
