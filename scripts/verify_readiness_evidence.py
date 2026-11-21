# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Verify additive readiness artifacts; do not alter historical labels or gates."""
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "results/readiness_2026-11-21"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def main():
    manifest = json.loads((BASE / "manifest.json").read_text())
    for relative, expected in manifest["sha256"].items():
        path = ROOT / relative
        require(path.is_relative_to(ROOT) and ".." not in Path(relative).parts, "unsafe manifest path")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, "artifact digest mismatch: " + relative)
    result = json.loads(gzip.decompress((BASE / "v4_fresh/results.json.gz").read_bytes()))
    summary = result["summaries"]["overall_descriptive_only"]["cerberus"]
    require(result["target_commit"] == "6fe417400ff4844d7647dddd9435288c3485ffc0", "wrong v4 target")
    require(result["gate"] == "PASS" and result["exit_code"] == 0, "fresh v4 gate mismatch")
    require(len(result["observations"]) == 1100, "incomplete v4 observations")
    require((summary["false_allows"]["numerator"], summary["false_allows"]["denominator"]) == (0, 878), "v4 false-allow mismatch")
    require((summary["false_denies"]["numerator"], summary["false_denies"]["denominator"]) == (0, 200), "v4 false-deny mismatch")
    ambiguous = [r for r in result["observations"] if r["expected"] == "doc-ambiguous"]
    require(len(ambiguous) == 22, "ambiguities lost")
    violations = Counter(v for r in ambiguous for v in r["systems"]["cerberus"].get("violations", []))
    require(violations == Counter(REPLAY_HISTORY_VIOLATION=5, OUT_OF_SCOPE_SIMULATOR_MUTATION=5), "known history failures lost")
    old = json.loads(gzip.decompress((BASE / "v3-functional.json.gz").read_bytes()))
    require(old["exit_code"] == 1, "historical v3 failure lost")
    require(old["overall"]["cerberus"]["false_allow"]["numerator"] == 9, "historical v3 score changed")
    print(json.dumps({"manifest_entries_verified": len(manifest["sha256"]), "v4_scored": 1078,
                      "v4_ambiguous": 22, "known_duplicate_receipts_retained": 5,
                      "v3_functional_gate": "FAIL", "independent_validation": False}, sort_keys=True))


if __name__ == "__main__":
    main()
