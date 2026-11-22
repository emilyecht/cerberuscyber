# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Restore the exact local measurement commit objects after connector publication.

This writes immutable Git objects only; it never changes a checkout or branch.
Published commits retain identical trees but connector-generated commit metadata.
"""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT/"docs/research/replay_v4/pr19_2026-11-11/local_commit_objects.json"


def main():
    objects = json.loads(MANIFEST.read_text())["commits"]
    for commit in objects:
        value = subprocess.check_output(["git","-C",str(ROOT),"hash-object","-t","commit","-w","--stdin"],
            input=commit["raw_commit"].encode()).decode().strip()
        if value != commit["sha"]:
            raise ValueError("original commit hash does not match")
        tree = subprocess.check_output(["git","-C",str(ROOT),"rev-parse",value+"^{tree}"]).decode().strip()
        subprocess.run(["git","-C",str(ROOT),"cat-file","-e",tree],check=True)
    print(json.dumps({"restored_local_commit_objects":len(objects),"checkout_or_branch_changed":False}))


if __name__ == "__main__":
    main()
