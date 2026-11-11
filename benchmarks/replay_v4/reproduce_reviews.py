# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Run a preserved review probe with only its host-specific ROOT/OUT relocated."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REVIEWS = ROOT/"docs/research/replay_v4/pr19_2026-11-11/reviews"
PROBES = {"sqlite":"probe_sqlite_second_review.py", "wal":"probe_wal_recovery.py",
    "followups":"probe_followup_review.py", "runner":"probe_runner_review.py",
    "permissions":"probe_permission_contract.py", "runner-permissions":"probe_runner_permissions_review.py"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind",choices=PROBES)
    parser.add_argument("--target",type=Path,default=ROOT)
    parser.add_argument("--output-dir",type=Path,required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True,exist_ok=True)
    lines = (REVIEWS/PROBES[args.kind]).read_text().splitlines()
    for i,line in enumerate(lines):
        if line.startswith("ROOT = Path("):
            lines[i] = "ROOT = Path("+repr(str(args.target.resolve()))+")"
        elif line.startswith("OUT = Path("):
            lines[i] = "OUT = Path("+repr(str(args.output_dir.resolve()))+")"
    with tempfile.TemporaryDirectory(prefix="cerberus-review-probe-") as directory:
        script = Path(directory)/PROBES[args.kind]
        script.write_text("\n".join(lines)+"\n")
        return subprocess.run([sys.executable,str(script)],cwd=args.target.resolve()).returncode


if __name__ == "__main__":
    raise SystemExit(main())
