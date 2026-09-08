"""The reviewer receives complete typed requests, ground truth, and honest replay status."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "reviewer_packet", ROOT / "benchmarks/guardian_authorization_v1/reviewer_packet.py")
packet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packet)


def test_packet_includes_every_unsafe_request_and_eligible_control():
    exported = packet.build_packet()
    corpus = packet.bench.load_corpus()
    source_ids = [case["id"] for case in corpus["cases"] if case["kind"] in {"unsafe", "valid"}]
    assert [case["definition"]["id"] for case in exported["cases"]] == source_ids
    assert len(source_ids) == 41
    assert sum(case["definition"]["kind"] == "unsafe" for case in exported["cases"]) == 33
    assert sum(case["definition"]["kind"] == "valid" for case in exported["cases"]) == 8


def test_export_preserves_wrong_types_missing_fields_and_external_facts():
    rows = {case["definition"]["id"]: case for case in packet.build_packet()["cases"]}
    assert rows["I01"]["request"]["reversibility_flag"] == "false"
    assert type(rows["I02"]["request"]["confidence"]) is bool
    assert rows["I03"]["request"]["confidence"] == "0.99"
    assert "digest" not in rows["I05"]["request"]["evidence_refs"][0]
    assert rows["I06"]["request"]["privileged_override"] is True
    assert "human_approvals" not in rows["I07"]["request"]
    assert rows["H04"]["external_fact"] == "The approval belongs to a different action and target."
    assert rows["E03"]["external_fact"] == "All three observations and claimed origins are fabricated."
    assert rows["H04"]["definition"]["patches"] == []
    assert rows["E03"]["definition"]["patches"] == []


def test_all_historical_observations_are_preserved_without_synthesizing_tokens():
    exported = packet.build_packet()
    for version in ("baseline", "repaired"):
        saved = json.loads((packet.RESULTS / f"{version}.json").read_text())
        rows = {row["id"]: row for row in saved["cases"]}
        for case in exported["cases"]:
            assert case["observations"][version] == rows[case["definition"]["id"]]
            assert "decision_token" not in case["observations"][version]
            assert packet.bench.digest(packet.bench.canonical(case["request"])) == rows[case["definition"]["id"]]["input_sha256"]


@pytest.mark.parametrize("filename", ["requests/A01.json", "cases/H04.md", "packet.json"])
def test_tampered_request_or_context_cannot_pass_packet_verification(tmp_path, filename):
    files = packet.generated_files()
    for name, content in files.items():
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8", newline="")
    assert packet.check_packet(tmp_path) == len(files)
    (tmp_path / filename).write_text("{}\n")
    with pytest.raises(ValueError, match="packet content mismatch"):
        packet.check_packet(tmp_path)


def test_replay_rejects_an_unpinned_target_before_execution(tmp_path, monkeypatch):
    monkeypatch.setattr(packet.bench, "target_metadata", lambda target: {"commit": "wrong"})
    with pytest.raises(ValueError, match="exact clean pinned target"):
        packet.replay("A01", tmp_path, tmp_path, tmp_path / "output.json")
    assert not (tmp_path / "output.json").exists()


def test_committed_packet_matches_the_frozen_source():
    assert packet.check_packet() == 85
