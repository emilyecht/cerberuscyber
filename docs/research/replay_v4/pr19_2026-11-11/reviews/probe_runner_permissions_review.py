"""Small post-discovery check of corrected permission prerequisites."""
from pathlib import Path
import hashlib
import json
import sys
import types

ROOT = Path('/workspace/scratch/379e5a226cc0/cerberuscyber')
OUT = Path('/workspace/scratch/379e5a226cc0/ai-review')
sys.path.insert(0, str(ROOT))
path = ROOT / 'benchmarks/replay_v4/run.py'
source = path.read_bytes()
runner = types.ModuleType('v4_permission_runner_review')
runner.__file__ = str(path)
exec(compile(source, str(path), 'exec'), runner.__dict__)
oracle = json.loads((ROOT / 'benchmarks/replay_v4/oracle.json').read_bytes())
ins = runner.Instrument(oracle)
events = []
with runner.offline():
    for id in ('S-021', 'S-022', 'S-023', 'S-024', 'S-025', 'S-036', 'S-046'):
        case = next(c for c in oracle['cases'] if c['id'] == id)
        row = runner.episode(ins, case)[0]
        obs = row['systems']['cerberus']
        assert obs['measurement_valid'] and obs['decision'] == row['expected'], row
        value = {'id': id, 'mode': case['store_recipe'].get('mode_octal'),
                 'expected': row['expected'], 'decision': obs['decision'],
                 'measurement_valid': obs['measurement_valid'],
                 'permission_probes': obs['permission_probes']}
        events.append(value)
        print(json.dumps(value), flush=True)
(OUT / 'runner_permissions_results_v2.json').write_text(json.dumps(
    {'runner_sha256_loaded': hashlib.sha256(source).hexdigest(),
     'runner_sha256_at_finish': hashlib.sha256(path.read_bytes()).hexdigest(),
     'stage': 'post-instrument-v1-discovery AI examination; not blinded',
     'full_run_executed': False, 'observations': events}, indent=2) + '\n')
