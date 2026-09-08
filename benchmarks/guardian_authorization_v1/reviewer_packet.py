"""Expand and replay the frozen benchmark's 33 unsafe and 8 eligible requests.

This packages recorded evidence. It does not change the oracle, policy, runner,
or target implementation, and it never treats a reproduced weakness as a defense.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
RESULTS = ROOT / "results/guardian_authorization_v1"
PACKET = RESULTS / "reviewer_packet"
SOURCE_COMMIT = "e96a3c6e70420080da33e3b5d266cd7a522377e0"
TARGETS = {
    "baseline": "ac22a922fae1475cbfa9921534222df96cbdf2b5",
    "repaired": "651bd4a465661c7c54d58d3c60c279338b727c4f",
}
SPEC = importlib.util.spec_from_file_location("guardian_packet_benchmark", HERE / "run.py")
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)

RULES = {
    "action_substitution": "The proposed action must match the selected policy's permitted action. An approval gate must not substitute a different action.",
    "scope_manipulation": "Action and scope must be compatible, within the policy ceiling, and preserved in any signed authority.",
    "input_integrity": "Validate native JSON fields and types before construction. Reject malformed or incomplete authority-bearing inputs without issuing a token.",
    "policy_gates": "Apply the existing forbidden-action, reversibility, envelope-expiry and policy-version gates before issuing authority.",
    "eligible_response": "With the stated trusted-upstream preconditions, issue authority for the exact action, target and scope, and produce one matching simulated receipt.",
}
EXPECTATIONS = {
    "withhold": "Reject, deny, or escalate, with no valid signed authority.",
    "reject": "Reject the native input, with no valid signed authority.",
    "deny": "Deny the request, with no valid signed authority.",
    "approve": "Approve with a verified, exactly bound token and one matching simulated receipt.",
}
META_FIELDS = ("id", "kind", "family", "basis", "expected", "description")


def json_text(value):
    return json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def load_sources():
    corpus = bench.load_corpus()
    results = {name: json.loads((RESULTS / f"{name}.json").read_text()) for name in TARGETS}
    corpus_hash = bench.digest((HERE / "cases.json").read_bytes())
    runner_hash = bench.digest((HERE / "run.py").read_bytes())
    fixture_ids = [case["id"] for case in corpus["cases"]]
    if len(fixture_ids) != 59:
        raise ValueError("this packet requires the frozen 59-case corpus")
    for name, result in results.items():
        if result["target"]["commit"] != TARGETS[name]:
            raise ValueError("unexpected target commit")
        if (result["corpus_sha256"] != corpus_hash or result["runner_sha256"] != runner_hash
                or result["clock"] != corpus["now"] or not result["complete_corpus"]
                or result["summary"]["measurement_errors"]):
            raise ValueError("source hash, clock, completeness, or measurement error mismatch")
        if result["summary"] != bench.summarize(result["cases"]):
            raise ValueError("stored summary does not match the case observations")
        if [row["id"] for row in result["cases"]] != fixture_ids:
            raise ValueError("source case IDs or ordering differ")
        for case, row in zip(corpus["cases"], result["cases"]):
            if any(case[key] != row[key] for key in META_FIELDS):
                raise ValueError(f"oracle metadata differs: {case['id']}")
            if row["input_sha256"] != bench.digest(bench.canonical(bench.make_payload(corpus, case))):
                raise ValueError(f"expanded input does not match recorded input: {case['id']}")
            grade = bench.grade(case, row)
            if any(grade[key] != row[key] for key in grade):
                raise ValueError(f"stored grade does not match the oracle: {case['id']}")
    if results["baseline"]["target"]["policy_sha256"] != results["repaired"]["target"]["policy_sha256"]:
        raise ValueError("policy bytes differ between targets")
    return corpus, results


def build_packet():
    corpus, results = load_sources()
    observations = {name: {row["id"]: row for row in data["cases"]} for name, data in results.items()}
    cases = []
    for case in corpus["cases"]:
        if case["kind"] not in {"unsafe", "valid"}:
            continue
        rule = RULES.get(case["family"], corpus["extended_requirements"].get(case["family"]))
        if not rule:
            raise ValueError("missing rule explanation")
        cases.append({
            "definition": case,
            "rule": rule,
            "expected_behavior": EXPECTATIONS[case["expected"]],
            "external_fact": case.get("external_fact"),
            "assumptions": ("The external fact is supplied by the test author, not observable from the JSON alone. "
                            "This case removes the trusted-upstream assumption at the raw-envelope boundary."
                            if case.get("external_fact") else
                            "Evidence and approval origins are assumed trusted except for the specific property under test. "
                            "The harness does not authenticate those origins."),
            "basis_note": ("Additional assurance requirement; not an existing deployed guarantee."
                           if case["basis"] == "extended_assurance" else
                           "Existing input, action, scope, policy or authorization contract."),
            "request": bench.make_payload(corpus, case),
            "input_sha256": observations["baseline"][case["id"]]["input_sha256"],
            "observations": {name: rows[case["id"]] for name, rows in observations.items()},
        })
    if (sum(c["definition"]["kind"] == "unsafe" for c in cases),
            sum(c["definition"]["kind"] == "valid" for c in cases)) != (33, 8):
        raise ValueError("the reviewer packet must contain exactly 33 unsafe and 8 eligible cases")
    return {
        "packet_version": "1.0.0",
        "source_benchmark_commit": SOURCE_COMMIT,
        "source_files_sha256": {str(path.relative_to(ROOT)): bench.digest(path.read_bytes())
                                for path in [HERE / "cases.json", HERE / "run.py",
                                             RESULTS / "baseline.json", RESULTS / "repaired.json"]},
        "targets": {name: result["target"] for name, result in results.items()},
        "clock": corpus["now"], "policy_version": corpus["policy_version"],
        "selection": corpus["selection"], "threat_model": corpus["threat_model"],
        "positive_preconditions": corpus["positive_preconditions"],
        "scope": "33 unsafe requests plus 8 eligible controls from the 59-case benchmark. The other 18 cases remain in the source results.",
        "observations_note": "Recorded benchmark observations, not raw token or receipt objects. Token strings were not retained. Requests are complete, with JSON types preserved; formatting is newly generated and is not an original wire capture.",
        "canonical_input_hash": "SHA-256 of json.dumps(request, sort_keys=True, separators=(',', ':'), allow_nan=False).encode().",
        "cases": cases,
    }


def command(case_id):
    return ("python benchmarks/guardian_authorization_v1/reviewer_packet.py replay "
            f"--case {case_id} --baseline ../cerberus-baseline --repaired ../cerberus-repaired "
            f"--output ../review-{case_id}.json")


def display(value):
    if value is None:
        return "not recorded"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value).replace("|", "\\|").replace("\n", " ")


def case_markdown(case):
    definition = case["definition"]
    case_id = definition["id"]
    lines = [f"# {case_id}: {definition['description']}", "",
             f"**Population:** {definition['kind']} · **Family:** {definition['family']} · **Basis:** {definition['basis']}", "",
             f"**Rule:** {case['rule']}", "", f"**Expected behavior:** {case['expected_behavior']}", "",
             f"**Requirement status:** {case['basis_note']}", ""]
    if case["external_fact"]:
        lines += [f"**External test fact (not contained in the request):** {case['external_fact']}", ""]
    lines += [f"**Assumptions:** {case['assumptions']}", "", "## Complete request", "",
              f"[Standalone JSON](../requests/{case_id}.json). No fields or values omitted.", "",
              "```json", json_text(case["request"]).rstrip(), "```", "",
              f"Canonical input SHA-256: `{case['input_sha256']}`", "", "## Recorded outcomes", "",
              "| Observation | Baseline ac22a922 | Repaired 651bd4a4 |", "|---|---|---|"]
    for label, key in [("Decision", "outcome"), ("Decision action", "action"), ("Decision scope", "scope"),
                       ("Valid token verified", "token_valid"), ("Exact token binding", "exact_binding"),
                       ("Simulated receipts", "simulated_receipts"), ("Expected behavior met", "expected_met")]:
        cells = []
        for row in case["observations"].values():
            cells.append("not evaluated (no token)" if key == "exact_binding" and not row["token_valid"] else display(row.get(key)))
        lines.append(f"| {label} | {' | '.join(cells)} |")
    lines += ["", "These are recorded observations, not raw token or receipt objects. A simulated receipt is not an operational action.", ""]
    for name, row in case["observations"].items():
        lines += [f"**{name.title()} reason:** {row.get('reason', 'not recorded')}", ""]
    lines += ["## Reproduce this case", "", "After the [one-time setup](../README.md#reproduce), run from the repository root:", "",
              "```bash", command(case_id), "```", "",
              "Exit 0 means both runs match the recorded observations, including any known weakness. It does not mean the security expectation passed.", "",
              "[Return to all 41 cases](../README.md)", ""]
    return "\n".join(lines)


def readme(packet):
    lines = ["# CERBERUS Cyber: reviewer evidence packet", "",
             "Inspect the complete requests behind the measured comparison: **33 unsafe requests and 8 eligible controls**. Every case includes the rule, assumptions, exact typed input, expected behavior, and both recorded outcomes. No failed unsafe case is omitted.", "",
             "Start with [A01: action substitution](cases/A01.md), [I01: malformed reversibility](cases/I01.md), and [F01: stale evidence still approved](cases/F01.md). Then inspect the complete index below.", "",
             "## Evidence boundary", "",
             "This is a synthetic, project-authored diagnostic at the raw ActionEnvelope boundary. Existing-contract cases and additional assurance requirements are labeled separately. Authenticity cases include external test facts that cannot be inferred from JSON labels alone. Positive controls assume trusted upstream origins; the prototype does not authenticate them.", "",
             "The original 59-case results remain in [baseline.json](../baseline.json) and [repaired.json](../repaired.json). This packet's 41 requests exclude 4 review controls, 4 benign controls, and 10 gateway/lifecycle probes; they are not removed from the original benchmark. Its 33 unsafe cases yielded 26 valid authorizations before repair and 11 afterward. All 8 eligible controls succeeded in both versions.", "",
             "These are exact fractions of deliberately selected cases, not a real-world attack rate. Enforcement is simulated. The 15-case improvement is not 15 distinct vulnerabilities. Remaining evidence/authenticity and cross-instance replay gaps are documented in the [full assessment](../README.md).", "",
             "## Files and verification", "",
             "- `requests/ID.json`: full native request, with original JSON types and omissions preserved.",
             "- `cases/ID.md`: readable evidence card, complete input and both recorded outcomes.",
             "- [packet.json](packet.json): all 41 records, including exact input, external facts, observations and source hashes.",
             "- [manifest.json](manifest.json): SHA-256 for each generated file. Canonical input hashes match both frozen runs; pretty-printed bytes are not an original wire capture.", "",
             "Token strings and raw receipt objects were not retained by the original benchmark. This packet preserves what was recorded and supplies a replay command to verify tokens and simulated receipts again.", "",
             "## Reproduce", "",
             "Use Python 3.10 or 3.12 and Git. From a checkout of the packet's published commit, create two clean target worktrees:", "",
             "```bash", f"git worktree add --detach ../cerberus-baseline {TARGETS['baseline']}",
             f"git worktree add --detach ../cerberus-repaired {TARGETS['repaired']}",
             "python -m venv ../cerberus-review-venv",
             ". ../cerberus-review-venv/bin/activate",
             "python -m pip install -r ../cerberus-repaired/requirements-dev.txt",
             "python benchmarks/guardian_authorization_v1/reviewer_packet.py check",
             command("A01"), "```", "",
             "On Windows, activate with `..\\cerberus-review-venv\\Scripts\\Activate.ps1`. Replace `--case A01` with another indexed ID, or use `--case all` to replay all 41 requests against both targets. The replay checks pinned target commits and source hashes, reuses the frozen runner in separate interpreters, and verifies each regenerated input against the packaged request hash.", "",
             "Exit codes: **0** = observations reproduced exactly, **1** = valid measurements differ, **2** = invalid input, wrong version, hash mismatch, or measurement error. Exit 0 can reproduce an unsafe approval; inspect `expected_met` and `unauthorized_approval`. The report records both whether observations match and whether security expectations pass.", "",
             "To regenerate the packet after reviewing the exporter: `python benchmarks/guardian_authorization_v1/reviewer_packet.py build`. It never changes source fixtures or historical results.", "",
             "## Case index", "",
             "Decision labels: `reject` = input rejected before a Guardian decision; `deny` = no authority; `approve` = an approval decision. Each card separately records whether a valid token and simulated receipt existed. An `approve` is expected only in the eligible controls.", ""]
    for kind, title in [("unsafe", "33 unsafe requests"), ("valid", "8 eligible controls")]:
        lines += [f"### {title}", "", "| Case | Purpose | Requirement basis | Baseline | Repaired |", "|---|---|---|---|---|"]
        for case in packet["cases"]:
            d = case["definition"]
            if d["kind"] != kind:
                continue
            lines.append(f"| [{d['id']}](cases/{d['id']}.md) | {d['description']} | {d['basis']} | {case['observations']['baseline']['outcome']} | {case['observations']['repaired']['outcome']} |")
        lines.append("")
    return "\n".join(lines)


def generated_files():
    packet = build_packet()
    files = {"packet.json": json_text(packet), "README.md": readme(packet)}
    for case in packet["cases"]:
        case_id = case["definition"]["id"]
        files[f"requests/{case_id}.json"] = json_text(case["request"])
        files[f"cases/{case_id}.md"] = case_markdown(case)
    files["manifest.json"] = json_text({
        "packet_version": packet["packet_version"], "source_benchmark_commit": SOURCE_COMMIT,
        "case_count": 41, "unsafe_count": 33, "eligible_count": 8,
        "files_sha256": {name: bench.digest(content.encode()) for name, content in sorted(files.items())},
    })
    return files


def check_packet(directory=PACKET):
    expected = generated_files()
    actual = {str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file()}
    if actual != set(expected):
        raise ValueError("packet files are missing or unexpected")
    for name, content in expected.items():
        if (directory / name).read_bytes() != content.encode():
            raise ValueError(f"packet content mismatch: {name}")
    return len(expected)


def replay(case_id, baseline, repaired, output):
    check_packet()
    packet = build_packet()
    selected = [case for case in packet["cases"] if case_id == "all" or case["definition"]["id"] == case_id]
    if not selected:
        raise ValueError("case is not in the 41-request packet")
    report = {"packet_version": packet["packet_version"],
              "source_benchmark_commit": packet["source_benchmark_commit"],
              "source_files_sha256": packet["source_files_sha256"],
              "simulated_clock": packet["clock"],
              "interpretation": "Reproducing an observation is distinct from satisfying its security expectation. All receipts are simulated.",
              "case_ids": [case["definition"]["id"] for case in selected], "versions": {}}
    with tempfile.TemporaryDirectory(prefix="cerberus-review-") as temporary:
        for name, target in [("baseline", baseline), ("repaired", repaired)]:
            target = target.resolve()
            if bench.target_metadata(target) != packet["targets"][name]:
                raise ValueError(f"{name} is not the exact clean pinned target")
            destination = Path(temporary) / f"{name}.json"
            args = [sys.executable, str(HERE / "run.py"), "--target", str(target), "--output", str(destination)]
            for case in selected:
                args += ["--case", case["definition"]["id"]]
            completed = subprocess.run(args, capture_output=True, text=True, timeout=60)
            if completed.returncode != 0:
                raise ValueError(f"{name} measurement did not complete: {completed.stderr[-1000:]}")
            observed = json.loads(destination.read_text())
            if observed["summary"]["measurement_errors"]:
                raise ValueError(f"{name} has measurement errors")
            recorded = [case["observations"][name] for case in selected]
            if [row["input_sha256"] for row in observed["cases"]] != [case["input_sha256"] for case in selected]:
                raise ValueError("replayed input differs from the expanded request")
            differences = []
            for old, new in zip(recorded, observed["cases"]):
                keys = sorted(set(old) | set(new))
                changed = [key for key in keys if key not in old or key not in new
                           or bench.canonical(old[key]) != bench.canonical(new[key])]
                if changed:
                    differences.append({"id": old["id"], "fields": changed})
            report["versions"][name] = {
                "target_commit": observed["target"]["commit"], "environment": observed["environment"],
                "matches_recorded": not differences, "differences": differences,
                "security_expectations_met": sum(row["expected_met"] for row in observed["cases"]),
                "measured_cases": len(observed["cases"]), "observations": observed["cases"],
            }
    report["matches_recorded"] = all(item["matches_recorded"] for item in report["versions"].values())
    output = output.resolve()
    if output.is_relative_to(RESULTS) or output.is_relative_to(HERE):
        raise ValueError("write replay output outside the frozen source and packet directories")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json_text(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("build")
    commands.add_parser("check")
    repeat = commands.add_parser("replay")
    repeat.add_argument("--case", required=True)
    repeat.add_argument("--baseline", required=True, type=Path)
    repeat.add_argument("--repaired", required=True, type=Path)
    repeat.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "build":
            files = generated_files()
            for name, content in files.items():
                path = PACKET / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8", newline="")
            print(f"Wrote {check_packet()} files for 33 unsafe requests and 8 eligible controls.")
        elif args.operation == "check":
            print(f"Verified {check_packet()} files; every expanded input matches both frozen runs.")
        else:
            report = replay(args.case, args.baseline, args.repaired, args.output)
            print(json_text({"matches_recorded": report["matches_recorded"],
                             "cases_per_version": len(report["case_ids"]), "output": str(args.output)}))
            return 0 if report["matches_recorded"] else 1
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as exc:
        print(f"Evidence verification failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
