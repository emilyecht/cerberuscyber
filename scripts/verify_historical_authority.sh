#!/usr/bin/env bash
# Run immutable research instruments on their original source in disposable worktrees.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
temp=$(mktemp -d)
cleanup() {
    git -C "$root" worktree remove --force "$temp/v1" 2>/dev/null || true
    git -C "$root" worktree remove --force "$temp/v3" 2>/dev/null || true
    rm -rf "$temp"
}
trap cleanup EXIT
git worktree add --quiet --detach "$temp/v1" 48eefd82cee2c47c5ffc4f79de392ce3b0049ffe
git worktree add --quiet --detach "$temp/v3" f0ebd38c58e9d40af35d35c5cc32b5614eb60439
cd "$temp/v1"
status=0
python benchmarks/replay_v1/run.py --output-dir "$temp/results" || status=$?
test "$status" -eq 1
cmp "$temp/results/results.json" results/replay_v1/results.json
cd "$temp/v3"
python -m pytest -q benchmarks/replay_v3/test_instrument.py
python - <<'PY'
from benchmarks.replay_v3 import run
with run.offline():
    oracle, cases, preservation = run.frozen_inputs()
    result, _ = run.functional(oracle, cases, preservation)
metric = result['overall']['cerberus']['false_allow']
print("historical v3", result['exit_code'], metric)
assert result['exit_code'] == 1 and (metric['numerator'], metric['denominator']) == (9, 3484)
PY
