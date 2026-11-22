# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Run immutable v1 instrument tests against the pinned v1 source tree offline."""

import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
TREE = "01ecf6493d4aec1f2a5bfb3963523e68d705a099"


def verify():
    archive = subprocess.check_output(["git", "-C", str(ROOT), "archive", TREE])
    with TemporaryDirectory(prefix="cerberus-v1-history-") as temporary:
        # This archive is the exact trusted Git tree, not a supplied tarball.
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            for member in source.getmembers():
                if not (member.isfile() or member.isdir()) or Path(member.name).is_absolute() or ".." in Path(member.name).parts:
                    raise RuntimeError("unexpected historical archive entry")
            for member in source.getmembers():
                path = Path(temporary) / member.name
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(source.extractfile(member).read())
                    path.chmod(member.mode & 0o777)
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        result = subprocess.run([sys.executable, "-m", "pytest", "-q", "--tb=no",
            "-p", "no:cacheprovider", "tests/test_replay_v1.py"],
            cwd=temporary, env=environment, text=True, capture_output=True, timeout=120)
    gate = "FAILED tests/test_replay_v1.py::test_replay_has_zero_safety_invariant_violations"
    if result.returncode != 1 or "1 failed, 14 passed" not in result.stdout or gate not in result.stdout:
        raise RuntimeError("historical v1 result changed:\n" + result.stdout + result.stderr)
    return {"tree": TREE, "historical_status": "FAIL", "instrument_checks_passed": 14,
            "safety_gates_failed": 1, "stdout": result.stdout}


if __name__ == "__main__":
    value = verify()
    print(value["stdout"])
    print("Verified historical v1 FAIL without changing its tests or implementation.")
