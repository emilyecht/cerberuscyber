"""Small, explicitly post-review runner examination; never invokes full run()."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import sys

ROOT = Path('/workspace/scratch/379e5a226cc0/cerberuscyber')
OUT = Path('/workspace/scratch/379e5a226cc0/ai-review')
sys.path.insert(0, str(ROOT))
path = ROOT / 'benchmarks/replay_v4/run.py'
spec = importlib.util.spec_from_file_location('v4_runner_review', path)
runner = importlib.util.module_from_spec(spec)
source = path.read_bytes()
loaded_sha256 = hashlib.sha256(source).hexdigest()
exec(compile(source, str(path), 'exec'), runner.__dict__)
oracle = json.loads((ROOT / 'benchmarks/replay_v4/oracle.json').read_bytes())
ins = runner.Instrument(oracle)
selected_ids = ['S-001', 'S-011', 'S-016', 'S-021', 'S-036', 'S-041', 'S-046', 'S-051',
                'T-001', 'T-016', 'T-031', 'T-036', 'T-041', 'T-046',
                'U-C-021', 'U-R-011', 'U-O-011', 'U-K-016', 'U-K-017',
                'U-K-022', 'U-K-023', 'U-P-025', 'V-021', 'V-031', 'V-041']
selected = [next(c for c in oracle['cases'] if c['id'] == id) for id in selected_ids]
selected += [next(c for c in oracle['cases'] if c['family'] == 'W' and c['variant'] == variant)
             for variant in ('field:confidence', 'identity_noop_assignment',
                             'identity_object_order_and_whitespace',
                             'identity_escaped_ASCII_identifier', 'identity_change_then_restore')]
events = []
with runner.offline():
    for case in selected:
        rows = runner.episode(ins, case)
        event = {'case': case['id'], 'variant': case['variant'], 'attempts': [
            {'id': r['id'], 'expected': r['expected'],
             'decision': r['systems']['cerberus']['decision'],
             'valid': r['systems']['cerberus']['measurement_valid'],
             'layer': r['systems']['cerberus']['layer'],
             'violations': r['systems']['cerberus'].get('violations', []),
             'constructor_ns': r['systems']['cerberus'].get('constructor_ns'),
             'guardian_ns': r['systems']['cerberus'].get('guardian_ns'),
             'kernel_ns': r['systems']['cerberus'].get('kernel_ns'),
             'execution_claim_added': r['systems']['cerberus'].get('execution_claim_added'),
             'controller_events': r['systems']['cerberus'].get('controller_events'),
             'permission_probes': r['systems']['cerberus'].get('permission_probes'),
             'baseline_decisions': {s:r['systems'][s]['decision'] for s in runner.SYSTEMS[1:]}}
             for r in rows]}
        events.append(event)
        print(json.dumps(event), flush=True)
result = {'stage': 'post-SQLite-review exposure; not blinded evaluation',
          'runner_sha256_loaded': loaded_sha256,
          'runner_sha256_at_finish': hashlib.sha256(path.read_bytes()).hexdigest(),
          'euid': os.geteuid(), 'selected_episodes': len(selected),
          'full_run_executed': False, 'observations': events}
(OUT / 'runner_probe_results_v2.json').write_text(json.dumps(result, indent=2) + '\n')
