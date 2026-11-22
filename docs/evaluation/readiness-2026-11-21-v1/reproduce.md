# Installation and reproduction

Use separate full clones or detached worktrees of both repositories. Linux with
an unprivileged user, no effective capabilities, Python 3.10 or 3.12 and a
Landlock ABI >=3 kernel is required for the complete enforcement procedure.
Install dependencies before offline evaluation. Unsupported confinement or
unconfirmed permission faults are unavailable/invalid, never successful defenses.

## Cyber source and historical measurement

```sh
git clone https://github.com/emilyecht/cerberuscyber.git
cd cerberuscyber
git checkout 94c5b746100bf82ad1d405cef0ef348c56667e4f
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt -r requirements-build.txt
.venv/bin/python -m pip check
.venv/bin/python benchmarks/replay_v4/restore_local_commits.py
.venv/bin/python benchmarks/replay_v4/run.py --verify-inputs-only
.venv/bin/python benchmarks/replay_v4/verify_results.py results/replay_v4/pr19_2026-11-11
.venv/bin/python benchmarks/replay_v4/verify_results.py results/replay_v4/pr19_2026-11-11_v2 --require-pass
.venv/bin/python -m pytest -q --ignore=benchmarks/replay_v3/test_instrument.py
.venv/bin/python benchmarks/replay_v4/run.py --output-dir /tmp/cerberus-v4-fresh
.venv/bin/python benchmarks/replay_v4/verify_results.py /tmp/cerberus-v4-fresh --require-pass
```

The full v4 measurement takes roughly 13-15 minutes on the recorded hosts, because
lock timeouts are retained across every repetition. Inspect both scored and
ambiguous outcomes. The first original artifact must remain INVALID_MEASUREMENT;
do not pass `--require-pass` for that original invalid artifact.

On the evidence-package publication branch, verify the new result using the same
unchanged v4 verifier:

```sh
python scripts/verify_readiness_evidence.py
python benchmarks/replay_v4/verify_results.py results/readiness_2026-11-21/v4_fresh --require-pass
```

The new evidence commit does not change v4's target. Exact original measurement
commit objects are reconstructed only through the checked, preserved restoration
script; the checkout and oracle are not changed by that restoration.

## Current repaired broker

```sh
git worktree add --detach /tmp/cerberus-current 7f0174e14c710cd1d3834fc57af3e05ea110f37f
cd /tmp/cerberus-current
/absolute/path/to/cerberuscyber/.venv/bin/python -m pytest -q --ignore=benchmarks/replay_v3/test_instrument.py
/absolute/path/to/cerberuscyber/.venv/bin/python -m cerberus.evaluation enforcement-demo --json
/absolute/path/to/cerberuscyber/.venv/bin/python benchmarks/release_candidate/run.py --target . --output /tmp/combined-contract.json --fail-on-violation
/absolute/path/to/cerberuscyber/.venv/bin/python -m build
```

Install the wheel in a second new virtual environment and execute
`python -I scripts/verify_installed.py --repo-root /absolute/current/checkout`
using that installed environment. It must validate four portable simulation cases
and 14 native lab cases on a supported Linux host. Do not edit the verifier to
turn unsupported kernel isolation into a pass. New current-source tests are
`tests/test_lab_authority_boundary.py` and `tests/test_durable_process_boundary.py`.

## Historical v3 checks and functional reproduction

```sh
git worktree add --detach /tmp/cerberus-v3 f0ebd38c58e9d40af35d35c5cc32b5614eb60439
cd /tmp/cerberus-v3
/absolute/path/to/cerberuscyber/.venv/bin/python -m pytest -q benchmarks/replay_v3/test_instrument.py
/absolute/path/to/cerberuscyber/.venv/bin/python - <<'PY'
from benchmarks.replay_v3 import run
with run.offline():
    oracle, cases, preservation = run.frozen_inputs()
    result, _ = run.functional(oracle, cases, preservation)
print(result['overall']['cerberus'])
assert result['exit_code'] == 1
assert result['overall']['cerberus']['false_allow']['numerator'] == 9
assert result['overall']['cerberus']['false_allow']['denominator'] == 3484
PY
```

This reproduces functional failures only, with no new v3 timing. The original
`python benchmarks/replay_v3/run.py` also runs its full timing protocol and should
return 1 for the historical safety failure. Executing the frozen v3 instrument on
repaired current source must reject its changed-source pin. That is an integration
problem to resolve explicitly, not a license to loosen the historical contract.

## Protocol

```sh
git clone https://github.com/emilyecht/cerberus-runtime-assurance.git
cd cerberus-runtime-assurance
git checkout 47cc290a9f1b5c7ba17f569071895c0be5390b3b
python -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m unittest discover -s tests/fcoi -v
.venv/bin/python -m cerberus_fcoi examples/fcoi/authority-boundary.json
```

Verify frozen schema SHA-256
`a5cbde024b7dae09d09fc65898b9874d8a6b7c63672d138f318e17a93eb999a8`.
Malformed models, incomplete evidence and exceeded exact-enumeration budgets must
not yield an exact numeric assurance result. The example's assumptions are
hypothetical. Do not connect its output to runtime authorization.
