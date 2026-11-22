#!/usr/bin/env bash
# Execute the pinned grader against the candidate's preserved artifacts.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
pin=ef6e014e5fc2e9e3d31898d993c1e5c26398398d
git diff --exit-code "$pin" HEAD -- benchmarks/replay_v4 tests/test_replay_v4_instrument.py results/replay_v4 results/readiness_2026-11-21 docs/evaluation/readiness-2026-11-21-v1 scripts/verify_readiness_evidence.py
temp=$(mktemp -d)
trap 'git -C "$root" worktree remove --force "$temp/history" 2>/dev/null || true; rm -rf "$temp"' EXIT
git worktree add --quiet --detach "$temp/history" "$pin"
cd "$temp/history"
python scripts/verify_readiness_evidence.py
python benchmarks/replay_v4/restore_local_commits.py
python benchmarks/replay_v4/run.py --verify-inputs-only
python -m pytest -q tests/test_replay_v4_instrument.py
python benchmarks/replay_v4/verify_results.py "$root/results/replay_v4/pr19_2026-11-11"
python benchmarks/replay_v4/verify_results.py "$root/results/replay_v4/pr19_2026-11-11_v2" --require-pass
python benchmarks/replay_v4/verify_results.py "$root/results/readiness_2026-11-21/v4_fresh" --require-pass
