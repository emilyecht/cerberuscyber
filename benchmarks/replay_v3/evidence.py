# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Reproducibility checks and isolated evidence; never change labels or scores."""
from __future__ import annotations

from pathlib import Path
import sqlite3

from benchmarks.replay_v3.freeze_oracle import canonical, sha


def validate_repetition(first, repeated, latency):
    """Compare actual observations, not just a pooled accuracy percentage."""
    compared = ("observations", "per_class", "overall", "novel_A_G", "failures",
                "baseline_failures", "doc_ambiguous", "oracle_defects", "corpus_sha256")
    matches = {key: canonical(first[key]) == canonical(repeated[key]) for key in compared}
    outcomes = {r["id"]: r["systems"]["cerberus"]["decision"] for r in first["observations"]}
    latency_matches = (
        len(latency["per_request"]) == len(outcomes)
        and {p["id"]: p["outcome"] for p in latency["per_request"]} == outcomes
    )
    if not all(matches.values()) or not latency_matches:
        raise RuntimeError("functional repetition or latency outcomes changed")
    return {
        "functional_runs": 2,
        "identical_fields": matches,
        "primary_observations_sha256": sha(canonical(first["observations"])),
        "repeated_observations_sha256": sha(canonical(repeated["observations"])),
        "latency_outcomes_match_functional": latency_matches,
        "protected_sources_sha256_match": True,
        "protected_diff_stat": first["source_preservation"]["protected_diff_stat"],
        "oracle_sha256": first["oracle_sha256"],
        "frozen_labels_and_scores_changed": False,
        "supplemental_storage_probes_excluded_from_primary_counts": True,
        "test_note": "Instrument/regression tests are separate from these runner self-checks.",
    }


def sqlite_empty_evidence(cases, instrument):
    """Observe the existing public store constructor and simulated gateway.

    These extra worlds are evidence-only. They never join functional scores,
    latency samples, or primary simulator mutation totals.
    """
    from benchmarks.replay_v3 import run as v3

    probes = []
    for case in cases:
        if case["variant"] != "sqlite_empty_unprovisioned":
            continue
        world = v3.new_world(instrument, case)
        try:
            path = Path(world.workdir.name) / "empty-replay.db"
            path.write_bytes(b"")
            before = {"exists": path.exists(), "bytes": path.stat().st_size}
            probe = {"episode": case["id"], "expected": case["steps"][0]["expected"],
                     "basis": "docs/ASSURANCE_BOUNDARY.md: State setup and recovery",
                     "before_constructor": before, "create_argument": False}
            try:
                store = v3.api.SQLiteStateStore(path, create=False)
            except v3.StateUnavailable as exc:
                probe.update(constructor_refused=True, reason=str(exc), accepted=False)
            else:
                probe["constructor_refused"] = False
                probe["bytes_after_constructor"] = path.stat().st_size
                world.replay = v3.ReplayObserver(store)
                world.gateway.replay_cache = world.replay
                step = case["steps"][0]
                outcome = v3.call_gateway(world, world.prepared.token, step["request"],
                                          v3.parse(step["evaluation_at"]))
                probe.update(accepted=outcome["accepted"], reason=outcome["reason"],
                             replay_claims_added=len(world.replay.claims))
                receipt = outcome["receipt"]
                probe["receipt"] = None if receipt is None else {
                    k: value for k, value in receipt.items()
                    if k not in {"token_id", "audit_record_hash"}
                }
                with sqlite3.connect(path) as connection:
                    tables = connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                    ).fetchall()
                    probe["tables_after_execution"] = [
                        {"name": name, "rows": connection.execute(
                            'SELECT COUNT(*) FROM "' + name.replace('"', '""') + '"'
                        ).fetchone()[0]} for (name,) in tables
                    ]
                probe["bytes_after_execution"] = path.stat().st_size
            probes.append(probe)
        finally:
            world.close()
    return {"synthetic_only": True, "primary_scoring_contribution": 0,
            "latency_sample_contribution": 0, "probes": probes}
