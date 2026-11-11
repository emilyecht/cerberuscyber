Separate AI runner examination — version 2 permission addendum

Retain `runner_second_review_v1.md` as the initial examination record. This
addendum corrects its overbroad assessment of permission-fixture fidelity. The
owner's first full instrument run subsequently identified invalid setup for
S-023 and S-024. This reviewer missed those two write-only modes during the
initial static check; the initial smoke had exercised S-021's mode 0000 and
S-036's mode 0400, which did not expose the distinction. A selected smoke pass
was not a full coverage check. This addendum is explicitly post-discovery
exposure and is not blindness or independent human evidence.

The frozen PLAN requires independently confirmed effective OS access denial
under an unprivileged identity without override capabilities. It does not
require both separate O_RDONLY and O_WRONLY calls to fail. The frozen
wrong_permissions recipes say `independently confirmed OS denial of read/write
access` and specifically prescribe:

| Case | Frozen mode | O_RDONLY | O_WRONLY | Combined O_RDWR |
| --- | --- | --- | --- | --- |
| S-021 | 0000 | denied | denied | denied |
| S-022 | 0111 | denied | denied | denied |
| S-023 | 0200 | denied | allowed | denied |
| S-024 | 0300 | denied | allowed | denied |
| S-025 | 0100 | denied | denied | denied |
| S-036 | 0400 | allowed | denied | denied |

SQLite's requested writable database connection needs combined read/write
access. The write-only modes 0200/0300 are therefore unavailable to that
connection despite permitting a standalone write-only open. The concrete frozen
modes resolve the intended meaning of read/write access; changing the probe to
test O_RDWR neither changes a fault nor revises its deny label. The old probe
incorrectly invalidated a valid fixture because it required O_WRONLY denial too.
The correct result for the first instrument version remains INVALID_MEASUREMENT,
not a defensive pass or a relabeled case. Its runner/results should remain
preserved separately from a corrected rerun.

The corrected runner now probes all three modes. Wrong-permission fixtures
require confirmed O_RDWR denial. Read-only fixtures additionally require
successful read-only access and denied write-only access. It still requires a
non-root identity and zero effective capabilities; a failed or unsupported
combined-access denial remains invalid setup. Separate read/write outcomes are
retained as diagnostics rather than forced to match an incorrect prerequisite.

I independently reproduced the access matrix above, plus a mode-0600 positive
control for which all three opens succeeded. Every denied open produced EACCES
under euid 1000 with CapEff=0. The script does not truncate or write through the
tested file descriptors:

```sh
env PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/379e5a226cc0/venv312/bin/python /workspace/scratch/379e5a226cc0/ai-review/probe_permission_contract.py
```

Output is `permission_contract_results_v1.json`. A second small runner probe
exercised the five exact wrong-permission cases, one read-only case and one
healthy allow control:

```sh
env PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/379e5a226cc0/venv312/bin/python /workspace/scratch/379e5a226cc0/ai-review/probe_runner_permissions_review.py
```

All seven attempts were valid and matched their frozen expectations. S-023 and
S-024 recorded read denial, write-only success and combined-access denial; the
healthy control produced a receipt. Loaded and finish runner SHA-256 both equal
`1bb4b9250032f51b7d4c558e770cfd24dc4a63e3d31960342b6d011efa760521`.
Raw observations are in `runner_permissions_results_v2.json`. This reviewer did
not execute a full replay_v4 run or inspect the full run's prior result files.

No additional blocking issue was found in this permission correction. This
statement is scoped to the correction and seven-case check; the eventual full
run remains responsible for instrument validity across all frozen fixtures.
No frozen artifact, production source, existing benchmark result or runner code
was modified by this reviewer.
