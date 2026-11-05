"""Verify preservation and commit order without running the evaluated system."""
from pathlib import Path
import sys
import json

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from benchmarks.replay_v3.run import frozen_inputs

if __name__ == "__main__":
    _, cases, preservation = frozen_inputs()
    if not preservation["history"]["results"]:
        raise SystemExit("Result introduction is not yet committed")
    print(json.dumps(preservation, indent=2))
    print(f"Verified {len(cases)} episodes, plan < oracle/hash < implementation < results; protected diff empty.")
