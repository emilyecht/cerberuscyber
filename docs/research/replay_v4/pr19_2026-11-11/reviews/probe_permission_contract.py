"""Unprivileged OS probes for the exact frozen permission modes; no full v4."""
from pathlib import Path
import errno
import json
import os
import tempfile

OUT = Path('/workspace/scratch/379e5a226cc0/ai-review')
caps = next(line.split(':', 1)[1].strip() for line in
            Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
assert os.geteuid() != 0 and int(caps, 16) == 0
events = []
with tempfile.TemporaryDirectory(prefix='permission-contract-', dir=OUT) as temporary:
    path = Path(temporary) / 'synthetic-file'
    path.write_bytes(b'synthetic permission probe; open flags never truncate')
    for mode in (0o000, 0o111, 0o200, 0o300, 0o100, 0o400, 0o600):
        path.chmod(mode)
        probes = {}
        for name, flags in (('read', os.O_RDONLY), ('write', os.O_WRONLY), ('read_write', os.O_RDWR)):
            try:
                fd = os.open(path, flags)
            except OSError as exc:
                probes[name] = {'denied': exc.errno in (errno.EACCES, errno.EPERM), 'errno': exc.errno}
            else:
                os.close(fd)
                probes[name] = {'denied': False}
        event = {'mode': f'{mode:04o}', 'os_open': probes}
        if mode in (0o000, 0o111, 0o200, 0o300, 0o100):
            assert probes['read_write']['denied']
        elif mode == 0o400:
            assert not probes['read']['denied'] and probes['write']['denied'] and probes['read_write']['denied']
        else:
            assert not any(p['denied'] for p in probes.values())
        events.append(event)
        print(json.dumps(event), flush=True)
    path.chmod(0o600)
(OUT / 'permission_contract_results_v1.json').write_text(json.dumps(
    {'euid': os.geteuid(), 'effective_capabilities': caps, 'observations': events}, indent=2) + '\n')
