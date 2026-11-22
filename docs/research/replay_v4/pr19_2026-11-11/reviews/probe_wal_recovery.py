"""One-bit committed-WAL corruption, compared against the parent state store."""
from pathlib import Path
import json
import os
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path('/workspace/scratch/379e5a226cc0/sqlite-review')
OUT = Path('/workspace/scratch/379e5a226cc0/ai-review')
sys.path.insert(0, str(ROOT))
from cerberus.state import SQLiteStateStore

parent_source = subprocess.run(['git', 'show',
    'f0ebd38c58e9d40af35d35c5cc32b5614eb60439:cerberus/state.py'],
    cwd=ROOT, check=True, text=True, capture_output=True).stdout
parent_globals = {'__name__': 'review_parent_state'}
exec(compile(parent_source, '<parent-state.py>', 'exec'), parent_globals)
ParentState = parent_globals['SQLiteStateStore']

events = []
for implementation, Store in [('parent', ParentState), ('pr', SQLiteStateStore)]:
    with tempfile.TemporaryDirectory(prefix='wal-recovery-', dir=OUT) as temporary:
        path = Path(temporary) / 'state.db'
        Store(path, create=True)
        child = '''from pathlib import Path
import json, os, sqlite3, sys
from cerberus.state import SQLiteStateStore
if sys.argv[2] == 'parent':
 source = json.loads(sys.argv[3]); ns={'__name__':'review_parent_child'}
 exec(compile(source,'<parent-state.py>','exec'),ns)
 Store = ns['SQLiteStateStore']
else:
 Store = SQLiteStateStore
p=Path(sys.argv[1]); keeper=sqlite3.connect(p)
assert keeper.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',)
keeper.execute('BEGIN'); keeper.execute('SELECT count(*) FROM claims').fetchone()
Store(p).consume('used-token','used-execution','a'*64)
observer=sqlite3.connect(p)
assert observer.execute('SELECT count(*) FROM claims').fetchone() == (2,)
observer.close()
print('two committed claims observed before simulated process crash',flush=True)
os._exit(0)
'''
        result = subprocess.run([sys.executable, '-c', child, str(path), implementation,
            json.dumps(parent_source)], cwd=ROOT, check=True, text=True, capture_output=True)
        wal = Path(str(path) + '-wal')
        data = bytearray(wal.read_bytes())
        wal_size = len(data)
        # Flip one bit in the final frame payload, invalidating its checksum.
        data[-1] ^= 1
        wal.write_bytes(data)
        store = Store(path)
        with sqlite3.connect(path) as connection:
            integrity = connection.execute('PRAGMA integrity_check').fetchall()
            rows_before_replay = connection.execute('SELECT count(*) FROM claims').fetchone()[0]
            mode = connection.execute('PRAGMA journal_mode').fetchone()[0]
        store.consume('used-token', 'used-execution', 'a' * 64)
        event = {'implementation': implementation, 'wal_bytes_before_corruption': wal_size,
                 'changed_bits': 1, 'journal_mode': mode, 'integrity_after_recovery': integrity,
                 'rows_before_replay': rows_before_replay, 'replay_accepted': True,
                 'child_output': result.stdout.strip()}
        events.append(event)
        print(json.dumps(event), flush=True)
(OUT / 'wal_probe_results.json').write_text(json.dumps(events, indent=2) + '\n')
