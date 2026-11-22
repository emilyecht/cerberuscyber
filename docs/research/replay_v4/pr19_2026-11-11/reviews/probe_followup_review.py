"""Separate post-v4-exposure review of the proposed WAL/expiry followups."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path('/workspace/scratch/379e5a226cc0/sqlite-followups')
OUT = Path('/workspace/scratch/379e5a226cc0/ai-review')
sys.path.insert(0, str(ROOT))
from cerberus import ActionEnvelope, DecisionTokenSigner, EnforcementGateway, Guardian, TokenAuthorityRegistry, EnforcementDenied
from cerberus.models import parse_time
from cerberus.state import SQLiteStateStore, StateUnavailable, ReplayDetected
from simulator.assurance_fixtures import fixture_assurance

events = []


def event(name, **data):
    result = {'probe': name, **data}
    events.append(result)
    print(json.dumps(result), flush=True)


def wal(base):
    path = base / 'wal.db'
    store = SQLiteStateStore(path, create=True)
    child = '''from pathlib import Path
import os,sqlite3,sys
p=Path(sys.argv[1]); k=sqlite3.connect(p)
assert k.execute('PRAGMA journal_mode=WAL').fetchone()==('wal',)
k.execute('BEGIN');k.execute('SELECT count(*) FROM claims').fetchone()
w=sqlite3.connect(p);w.executemany('INSERT INTO claims VALUES (?,?,?,?)',[
 ('cerberus','token','used-token','a'*64),('cerberus','execution','used-execution','a'*64)])
w.commit();o=sqlite3.connect(p)
assert o.execute('SELECT count(*) FROM claims').fetchone()==(2,)
print('committed',flush=True);os._exit(0)
'''
    subprocess.run([sys.executable, '-c', child, str(path)], check=True, capture_output=True)
    wal_path = Path(str(path) + '-wal')
    data = bytearray(wal_path.read_bytes())
    data[-1] ^= 1
    wal_path.write_bytes(data)
    for operation in ('ordinary-open', 'existing-claim', 'explicit-provision'):
        try:
            if operation == 'ordinary-open':
                SQLiteStateStore(path)
            elif operation == 'existing-claim':
                store.consume('used-token', 'used-execution', 'a' * 64)
            else:
                SQLiteStateStore(path, create=True)
        except StateUnavailable as exc:
            assert exc.__cause__ and 'DELETE journal' in str(exc.__cause__)
            event('corrupt_wal_rejected', operation=operation, outer_error=str(exc), cause=str(exc.__cause__))
        else:
            raise AssertionError('WAL artifact accepted')
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA journal_mode').fetchone() == ('wal',)
        assert connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        assert connection.execute('SELECT count(*) FROM claims').fetchone() == (0,)
    event('wal_never_converted', journal_mode='wal', recovered_rows=0)


def live_clock(base, crosses):
    policies = json.loads((ROOT / 'policies/policies.json').read_bytes())
    incident = {'incident_id': 'FOLLOWUP-AI-REVIEW', 'threat': 'ransomware', 'confidence': 0.99,
        'signals': ['rapid_file_rewrite', 'recovery_deletion_attempt'],
        'proposed_action': 'isolate_endpoint', 'target': 'endpoint:followup-review'}
    env = ActionEnvelope.from_legacy_incident(incident, policy_version=policies['version'], now=datetime.now(timezone.utc))
    verifier, proofs = fixture_assurance(env)
    signer = DecisionTokenSigner(b'public-followup-review-test-material-32-bytes')
    decision = Guardian(policies, signer=signer, assurance_verifier=verifier).evaluate(env, assurance=proofs)
    assert decision.guardian_decision == 'approve'
    token = signer.issue(decision, env, ttl_seconds=1 if crosses else 30)
    payload = signer.verify(token)
    registry = TokenAuthorityRegistry()
    registry.register(token, signer)
    path = base / ('expiry.db' if crosses else 'healthy.db')
    store = SQLiteStateStore(path, create=True)
    gateway = EnforcementGateway(signer, replay_cache=store, authority_registry=registry)
    locked = threading.Event()

    def blocker():
        connection = sqlite3.connect(path)
        connection.execute('BEGIN IMMEDIATE')
        locked.set()
        time.sleep(1.25 if crosses else 0.15)
        connection.rollback()
        connection.close()

    thread = threading.Thread(target=blocker)
    thread.start()
    assert locked.wait(2)
    before = datetime.now(timezone.utc)
    try:
        receipt = gateway.authorize_and_simulate(token, expected_envelope=env,
            action=env.action, target=env.target, scope=env.scope)
    except EnforcementDenied as exc:
        assert crosses and 'expired during durable consumption' in str(exc)
        assert gateway.ledger.records == ()
        receipt = None
        error = str(exc)
    else:
        assert not crosses
        assert parse_time(receipt['executed_at']) > before
        assert len(gateway.ledger.records) == 1
        error = None
    after = datetime.now(timezone.utc)
    thread.join()
    try:
        store.consume(payload['token_id'], payload['idempotency_key'], payload['envelope_digest'])
    except ReplayDetected:
        consumed = True
    else:
        raise AssertionError('durable claim was not retained')
    event('real_clock_deadline' if crosses else 'real_clock_healthy_control',
          call_started=before.isoformat(), expires_at=payload['expires_at'], finished=after.isoformat(),
          receipt=receipt is not None, error=error, claim_retained=consumed)


with tempfile.TemporaryDirectory(prefix='followup-review-', dir=OUT) as temporary:
    base = Path(temporary)
    wal(base)
    live_clock(base, True)
    live_clock(base, False)
result = {'stage': 'separate post-v4-exposure AI examination; no blindness claim',
          'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
              for p in ('cerberus/state.py', 'cerberus/enforcement.py')},
          'performance_regression': 'Open; full integrity_check retained', 'observations': events}
(OUT / 'followup_probe_results_v1.json').write_text(json.dumps(result, indent=2) + '\n')
