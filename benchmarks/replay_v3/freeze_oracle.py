"""Data-only pre-registration. No imports from the evaluated implementation.

Labels and transforms are frozen before reading/executing Kernel or gateway.
Existing oracle rows supply only H's source identities and input hashes.
"""
from __future__ import annotations

import copy
import hashlib
import json
import random
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = "2b4d992fb0ef05ed7b95950d14e4195c1e440ac7"
SEED = 87160329
CLOCK = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
FIELDS = [
    "schema_version", "envelope_id", "incident_id", "actor", "threat", "action",
    "target", "scope", "evidence_refs", "confidence", "freshness",
    "idempotency_key", "reversibility_flag", "required_approval_mode",
    "policy_version", "mission_impact", "human_approvals",
    "evidence_refs.0.source_id", "evidence_refs.0.digest",
    "evidence_refs.0.signal", "evidence_refs.0.observed_at",
    "freshness.timestamp", "freshness.expires_at", "freshness.nonce",
]
RULES = {
    "binding": {"expected": "deny", "document": "docs/ASSURANCE_BOUNDARY.md",
        "section": "Strict gateway execution context and live token status",
        "rule": "Actual complete request digest must equal the signed envelope digest; scalar fields must agree. Changed requests have no authority under the original token."},
    "schema": {"expected": "deny", "document": "docs/ACTION_ENVELOPE_V1.md",
        "section": "Strict input boundary; Fail-closed behavior",
        "rule": "Reject unsupported versions, missing required or unknown fields and malformed original decoded input; no coercion/defaulting."},
    "replay": {"expected": "deny", "document": "docs/ASSURANCE_BOUNDARY.md",
        "section": "State setup and recovery",
        "rule": "Atomically consume token ID and execution idempotency key before a receipt; consumption survives audit failure; no retry by erasing state."},
    "revocation": {"expected": "deny", "document": "docs/ASSURANCE_BOUNDARY.md",
        "section": "Strict gateway execution context and live token status",
        "rule": "Unknown, revoked, mismatched, wrongly purposed or unavailable live authority must refuse. Registry lock orders revocation before or after receipt commit."},
    "expiry": {"expected": "deny", "document": "docs/ASSURANCE_BOUNDARY.md",
        "section": "Time boundary; Strict gateway execution context and live token status",
        "rule": "Execution at or beyond the earliest evidence/envelope/approval/token deadline refuses; expiry is rechecked at commit."},
    "evidence_age": {"expected": "deny", "document": "docs/ASSURANCE_BOUNDARY.md",
        "section": "Time boundary", "rule": "Observation age must be less than 60 seconds; exactly 60 is expired; future skew greater than 5 seconds is invalid."},
    "state": {"expected": "deny", "document": "docs/ASSURANCE_BOUNDARY.md",
        "section": "State setup and recovery", "rule": "Missing, corrupt or locked SQLite state fails closed; explicit provisioning required; no fallback."},
    "conflict": {"expected": "escalate", "document": "docs/adr/0004-evidence-conflict-escalation.md",
        "section": "Decision 4-7", "rule": "cross_signal_inconsistency triggers GLOBAL-EVIDENCE-CONFLICT before policy-specific authorization, returns escalate with no token."},
    "valid": {"expected": "approve", "document": "policies/policies.json",
        "section": "CYBER-ID-001, CYBER-RW-001, CYBER-EX-001, CYBER-EA-001",
        "rule": "Exact allowed action/scope, configured confidence, required signals, authenticated independent sources, reversibility and required independent approvals satisfy the selected approving policy.",
        "also": "docs/ASSURANCE_BOUNDARY.md: Trust and authority; Time boundary"},
    "canonical": {"expected": "approve", "document": "docs/ACTION_ENVELOPE_V1.md",
        "section": "Canonical serialization and signing", "rule": "Sorted object keys and insignificant JSON whitespace do not change canonical bytes; array order and opaque identifier strings are not normalized by this rule."},
    "fresh_intent": {"expected": "approve", "document": "docs/ASSURANCE_BOUNDARY.md",
        "section": "Residual risks and evidence limits", "rule": "New request IDs can express repeated semantic intent; semantic deduplication is not supplied. A fully freshly attested, authorized, in-scope request remains eligible."},
    "no_maximum": {"expected": "approve", "document": "schemas/action-envelope.schema.json",
        "section": "properties.target/actor/evidence_refs; docs/ACTION_ENVELOPE_V1.md Supported action scopes",
        "rule": "Opaque identifiers have minimum lengths but no maxLength; evidence digest allows 16 through 128 lowercase hex characters. Matching trusted allowlists and all other approval requirements still apply."},
    "partial_audit": {"expected": "deny", "document": "docs/ASSURANCE_BOUNDARY.md",
        "section": "State setup and recovery", "rule": "Injected audit failure after replay consumption cannot produce a successful receipt; the consumed attempt stays consumed and its retry refuses."},
    "rollback_undefined": {"expected": "doc-ambiguous", "document": "docs/ASSURANCE_BOUNDARY.md",
        "section": "Time boundary", "rule": "Operators must supply a trustworthy clock; rollback is not independently detected. A deliberately rolled-back clock has no documented safe decision.",
        "ambiguity": "No enforceable monotonic-clock or allowed rollback tolerance is specified; observe without inventing a label."},
    "optional_undefined": {"expected": "doc-ambiguous", "document": "schemas/action-envelope.schema.json",
        "section": "required; docs/ACTION_ENVELOPE_V1.md Canonical fields",
        "rule": "All 17 current wire fields are required and additionalProperties is false.",
        "ambiguity": "There is no optional envelope metadata field to omit. Probe unchanged input with absent nonexistent metadata, disclose this coverage gap, and do not invent an optional-field contract."},
    "sidecar_optional": {"expected": "doc-ambiguous", "document": "docs/ASSURANCE_BOUNDARY.md",
        "section": "Trust and authority", "rule": "Sidecar contains evidence and approvals arrays, but optional omission/default behavior of an empty approvals array is not expressly specified.",
        "ambiguity": "Omit empty approvals on a policy needing no approval; docs do not distinguish empty array from absent optional sidecar array."},
}


def stamp(seconds=0):
    return (CLOCK + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def changed(raw, field, salt=1):
    """Frozen single-field transform; never uses system outputs or labels."""
    out = copy.deepcopy(raw)
    parts = field.split(".")
    obj = out
    for part in parts[:-1]:
        obj = obj[int(part)] if isinstance(obj, list) else obj[part]
    key = parts[-1]
    old = obj[key]
    if key == "schema_version":
        val = "1.0.1"
    elif key == "action":
        val = "isolate_endpoint" if old != "isolate_endpoint" else "revoke_sessions"
    elif key == "scope":
        val = "enterprise" if old != "enterprise" else "single_segment"
    elif key == "confidence":
        val = 1.0 if old != 1.0 else 0.0
    elif key == "reversibility_flag":
        val = not old
    elif key == "required_approval_mode":
        val = "dual" if old != "dual" else "none"
    elif key == "policy_version":
        val = "0.5.1"
    elif key == "mission_impact":
        val = "critical" if old != "critical" else "low"
    elif key == "idempotency_key":
        val = str(uuid.UUID(int=uuid.UUID(old).int ^ (salt + 1)))
    elif key == "digest":
        val = ("f" if old[0] != "f" else "e") + old[1:]
    elif key in {"observed_at", "timestamp", "expires_at"}:
        val = (datetime.fromisoformat(old.replace("Z", "+00:00")) + timedelta(microseconds=salt)).isoformat().replace("+00:00", "Z")
    elif key == "freshness":
        val = dict(old, nonce=old["nonce"] + f":mutation:{salt}")
    elif key == "evidence_refs":
        val = old + [dict(old[0], source_id=old[0]["source_id"] + f":extra:{salt}")]
    elif key == "human_approvals":
        val = old + [f"mutation-approval-{salt}"]
    else:
        val = old + f":mutation:{salt}"
    assert val != old, field
    obj[key] = val
    return out


def build():
    rng = random.Random(SEED)
    policy = json.loads((ROOT / "policies/policies.json").read_text())
    profiles = [p for p in policy["policies"] if p["id"] in {"CYBER-ID-001", "CYBER-RW-001", "CYBER-EX-001", "CYBER-EA-001"}]
    cases = []

    def envelope(case_id, index):
        p = profiles[index % len(profiles)]
        evidence = [{"source_id": f"v3:{case_id}:observer:{j}",
            "digest": sha(f"fabricated:{SEED}:{case_id}:{j}".encode()),
            "signal": signal, "observed_at": stamp()}
            for j, signal in enumerate(p["match"]["required_signals"])]
        count = p["required_approval_count"]
        return {"schema_version": "1.0.0", "envelope_id": f"v3:{case_id}",
            "incident_id": f"synthetic:{case_id}:{rng.getrandbits(32):08x}",
            "actor": "sentinel:v3-frozen-fixture", "threat": p["match"]["threat"],
            "action": p["allowed_action"], "target": f"sandbox:v3:{case_id}:{rng.getrandbits(64):016x}",
            "scope": p["max_scope"], "evidence_refs": evidence,
            "confidence": round(rng.uniform(max(.93, p["match"]["min_confidence"]), 1), 6),
            "freshness": {"timestamp": stamp(), "expires_at": stamp(120),
                "nonce": f"v3-nonce:{rng.getrandbits(128):032x}"},
            "idempotency_key": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "reversibility_flag": True, "required_approval_mode": ["none", "single", "dual"][count],
            "policy_version": policy["version"], "mission_impact": ["low", "medium", "high", "critical"][index % 4],
            "human_approvals": [f"v3-approver-{j}" for j in range(count)]}

    def step(request, rule="binding", **kw):
        return {"request": request, "rule": rule, "expected": RULES[rule]["expected"], **kw}

    def add(family, variant, index, make):
        cid = f"{family}-{index+1:03d}"
        setup = envelope(cid, index)
        steps = make(copy.deepcopy(setup), index)
        cases.append({"id": cid, "class": family, "variant": variant, "setup": setup,
            "steps": steps, "case_sha256": sha(canonical({"setup": setup, "steps": steps}))})

    av = ["expired_widened", "revoked_wrong_incident", "stale_injected", "expired_revoked_target",
        "revoked_impact_scope", "stale_nonce", "revoked_poisoned_evidence", "conflict_missing_signal"]
    for i in range(40):
        variant = av[i % len(av)]
        def make(s, k, v=variant):
            if v == "expired_widened":
                return [step(changed(s, "scope"), "expiry", execute_offset=60)]
            if v == "revoked_wrong_incident":
                return [step(changed(s, "incident_id"), "revocation", event="revoke_token")]
            if v == "stale_injected":
                r = copy.deepcopy(s)
                r["evidence_refs"][0]["observed_at"] = stamp(-61)
                r["threat"] = "prompt_injection"
                r["evidence_refs"][0]["signal"] = "untrusted_instruction"
                return [step(r, "evidence_age")]
            if v == "expired_revoked_target":
                return [step(changed(s, "target"), "expiry", execute_offset=60, event="revoke_token")]
            if v == "revoked_impact_scope":
                return [step(changed(changed(s, "mission_impact"), "scope"), "revocation", event="revoke_authority")]
            if v == "stale_nonce":
                r = changed(s, "freshness.nonce")
                r["evidence_refs"][0]["observed_at"] = stamp(-60)
                return [step(r, "evidence_age")]
            if v == "revoked_poisoned_evidence":
                return [step(changed(s, "evidence_refs.0.digest"), "revocation", event="revoke_authority")]
            r = copy.deepcopy(s)
            r["evidence_refs"][0]["signal"] = "cross_signal_inconsistency"
            return [step(r, "conflict", mode="guardian")]
        add("A", variant, i, make)

    bv = ["exact_second_use", "cross_envelope_then_valid", "partial_audit_then_retry",
        "used_then_cross_envelope", "mid_token_revocation", "mid_dependency_revocation",
        "shared_gateway_reuse", "failed_binding_then_valid"]
    for i in range(40):
        variant = bv[i % len(bv)]
        def make(s, k, v=variant):
            if v == "partial_audit_then_retry":
                return [step(s, "partial_audit", event="audit_failure"), step(s, "replay")]
            if v == "cross_envelope_then_valid":
                return [step(changed(s, "envelope_id")), step(s, "valid")]
            if v == "used_then_cross_envelope":
                return [step(s, "valid"), step(changed(s, "target")), step(s, "replay")]
            if v in {"mid_token_revocation", "mid_dependency_revocation"}:
                return [step(changed(s, "scope")), step(s, "revocation", event="revoke_token" if "token" in v else "revoke_authority")]
            if v == "failed_binding_then_valid":
                return [step(changed(s, "actor")), step(s, "valid")]
            return [step(s, "valid"), step(s, "replay", new_gateway=v == "shared_gateway_reuse")]
        add("B", variant, i, make)

    cv = ["revoke_between_authorize_enforce", "receipt_then_revocation", "revocation_wins_order",
        "enforcement_wins_order", "reordered_bad_good_duplicate", "reordered_other_envelope",
        "overlapping_duplicates", "duplicate_guardian_request"]
    for i in range(40):
        variant = cv[i % len(cv)]
        def make(s, k, v=variant):
            if v in {"revoke_between_authorize_enforce", "revocation_wins_order"}:
                return [step(s, "revocation", event="revoke_token", threaded=v == "revocation_wins_order")]
            if v in {"receipt_then_revocation", "enforcement_wins_order"}:
                return [step(s, "valid", event="revoke_during_commit" if v == "enforcement_wins_order" else "none"),
                    step(s, "revocation", event="revoke_token")]
            if v == "reordered_bad_good_duplicate":
                return [step(changed(s, "freshness.nonce")), step(s, "valid"), step(s, "replay")]
            if v == "reordered_other_envelope":
                return [step(changed(s, "envelope_id")), step(s, "valid")]
            if v == "overlapping_duplicates":
                return [step(s, "valid", event="duplicate_during_commit"), step(s, "replay", use_pending_duplicate=True)]
            return [step(s, "valid", mode="fresh"), step(s, "replay", mode="fresh")]
        add("C", variant, i, make)

    dv = ["expiry_before", "expiry_exact", "expiry_after", "evidence_age_before", "evidence_age_exact",
        "evidence_age_after", "skew_before", "skew_exact", "skew_after", "clock_rollback"]
    for i in range(40):
        variant = dv[i % len(dv)]
        def make(s, k, v=variant):
            if v.startswith("expiry"):
                delta = {"expiry_before": 59.999999, "expiry_exact": 60, "expiry_after": 60.000001}[v]
                return [step(s, "valid" if v.endswith("before") else "expiry", execute_offset=delta)]
            if v.startswith("evidence_age"):
                age = {"evidence_age_before": 59.999999, "evidence_age_exact": 60, "evidence_age_after": 60.000001}[v]
                for e in s["evidence_refs"]:
                    e["observed_at"] = stamp(-age)
                return [step(s, "valid" if v.endswith("before") else "evidence_age", mode="fresh")]
            if v.startswith("skew"):
                skew = {"skew_before": 4.999999, "skew_exact": 5, "skew_after": 5.000001}[v]
                for e in s["evidence_refs"]:
                    e["observed_at"] = stamp(skew)
                return [step(s, "evidence_age" if v.endswith("after") else "valid", mode="fresh")]
            return [step(s, "rollback_undefined", execute_offset=-1)]
        add("D", variant, i, make)

    extras = ["target_case", "target_composed", "target_decomposed", "target_zero_width",
        "target_leading_space", "target_trailing_space", "target_percent", "target_double_encoding",
        "evidence_order", "approval_order", "object_order_whitespace", "unknown_metadata"]
    for i in range(60):
        variant = f"field:{FIELDS[i % 24]}" if i < 48 else extras[i-48]
        def make(s, k, v=variant):
            if v.startswith("field:"):
                return [step(changed(s, v[6:], 1+k//24))]
            r = copy.deepcopy(s)
            transforms = {"target_case": lambda x: x.upper(), "target_composed": lambda x: x+"é",
                "target_decomposed": lambda x: x+"e\u0301", "target_zero_width": lambda x: x+"\u200b",
                "target_leading_space": lambda x: " "+x, "target_trailing_space": lambda x: x+" ",
                "target_percent": lambda x: x.replace(":", "%3A"),
                "target_double_encoding": lambda x: x.replace(":", "%253A")}
            if v in transforms:
                r["target"] = transforms[v](r["target"])
            elif v == "evidence_order":
                r["evidence_refs"].reverse()
            elif v == "approval_order":
                # This index is 57: force a dual-approval source independently below.
                r["human_approvals"].reverse()
            elif v == "object_order_whitespace":
                r = json.loads(json.dumps(dict(reversed(list(r.items()))), indent=7))
                return [step(r, "canonical")]
            else:
                r["metadata"] = {"recommendation": "allow"}
                return [step(r, "schema")]
            return [step(r)]
        add("E", variant, i, make)
        if variant == "approval_order":
            c = cases[-1]
            s = envelope(c["id"], 3)
            c["setup"] = s
            c["steps"] = [step(dict(s, human_approvals=list(reversed(s["human_approvals"]))))]
            c["case_sha256"] = sha(canonical({"setup": s, "steps": c["steps"]}))

    fv = ["registry_missing", "registry_unavailable", "registry_corrupt", "registry_empty",
        "sqlite_missing", "sqlite_corrupt", "sqlite_empty_unprovisioned", "sqlite_locked",
        "optional_envelope_absent", "optional_sidecar_approvals_absent", "required_field_absent",
        "minimum_identifiers", "long_target", "long_actor", "maximum_confidence",
        "exact_minimum_confidence", "minimum_digest", "maximum_digest", "empty_approvals", "replay_unavailable"]
    for i in range(40):
        variant = fv[i % len(fv)]
        def make(s, k, v=variant):
            if v.startswith("registry"):
                return [step(s, "revocation", event=v)]
            if v.startswith("sqlite") or v == "replay_unavailable":
                return [step(s, "state", event=v)]
            if v == "optional_envelope_absent":
                return [step(s, "optional_undefined")]
            if v == "optional_sidecar_approvals_absent":
                # Use a profile that has no required approvals.
                s = envelope(f"F-sidecar-{k}", 0)
                return [step(s, "sidecar_optional", mode="fresh", event="omit_sidecar_approvals")]
            if v == "required_field_absent":
                del s["human_approvals"]
                return [step(s, "schema")]
            if v == "minimum_identifiers":
                s.update(envelope_id="e", incident_id="i", actor="abc", target="t")
                s["freshness"]["nonce"] = "n"*16
            if v == "long_target":
                s["target"] += "x"*8192
            if v == "long_actor":
                s["actor"] += "x"*4096
            if v == "maximum_confidence":
                s["confidence"] = 1
            if v == "exact_minimum_confidence":
                s["confidence"] = next(p for p in profiles if p["match"]["threat"] == s["threat"])["match"]["min_confidence"]
            if v in {"minimum_digest", "maximum_digest"}:
                for e in s["evidence_refs"]:
                    e["digest"] = "a"*(16 if v == "minimum_digest" else 128)
            if v == "empty_approvals":
                s = envelope(f"F-noapprovals-{k}", 0)
            return [step(s, "no_maximum" if v in {"long_target", "long_actor", "minimum_digest", "maximum_digest"} else "valid", mode="fresh")]
        add("F", variant, i, make)

    gv = ["critical_with_approval", "exact_scope_ceiling", "exact_independence", "exact_confidence",
        "last_live_microsecond", "maximum_valid_future_skew", "canonical_wire_equivalent", "fresh_repeated_intent"]
    for i in range(40):
        variant = gv[i % len(gv)]
        def make(s, k, v=variant):
            if v == "critical_with_approval":
                s = envelope(f"G-critical-{k}", 3)
                s["mission_impact"] = "critical"
            if v == "exact_confidence":
                s["confidence"] = next(p for p in profiles if p["match"]["threat"] == s["threat"])["match"]["min_confidence"]
            if v == "last_live_microsecond":
                for e in s["evidence_refs"]:
                    e["observed_at"] = stamp(-59.999999)
            if v == "maximum_valid_future_skew":
                for e in s["evidence_refs"]:
                    e["observed_at"] = stamp(5)
            if v == "canonical_wire_equivalent":
                return [step(json.loads(json.dumps(dict(reversed(list(s.items()))), indent=3)), "canonical")]
            if v == "fresh_repeated_intent":
                return [step(s, "valid"), step(changed(changed(s, "idempotency_key"), "envelope_id"), "fresh_intent", mode="fresh")]
            return [step(s, "valid", mode="fresh")]
        add("G", variant, i, make)

    original = json.loads((ROOT / "benchmarks/replay_v1/oracle.json").read_text())
    assert len(original["cases"]) == 135
    for source in original["cases"]:
        for field in FIELDS:
            cases.append({"id": f"H-{source['id']}-{field}", "class": "H",
                "variant": f"mutate:{field}", "source_id": source["id"],
                "source_case_sha256": source["case_sha256"], "field": field,
                "salt": 1, "rule": "binding", "expected": "deny",
                "recipe": "original raw v2 request; changed(raw,field,1); original unmodified setup grant and original proofs only"})
    assert len(cases) == 3540
    return {"instrument": "replay_v3-held-out", "base_commit": BASE, "seed": SEED,
        "clock": stamp(), "fields": FIELDS, "rules": RULES,
        "policy_sha256": sha((ROOT / "policies/policies.json").read_bytes()),
        "source_oracle_sha256": sha((ROOT / "benchmarks/replay_v1/oracle.json").read_bytes()),
        "new_cases": 300, "derived_mutation_cases": 3240,
        "cases": cases, "recipes_sha256": sha(canonical(cases)),
        "label_source": "Repository documents/policies/schema only; no implementation or observed v2 decision used."}


def main():
    path = HERE / "oracle.json"
    if path.exists():
        raise SystemExit("Refusing to replace frozen oracle")
    data = (json.dumps(build(), ensure_ascii=False, sort_keys=True, indent=2)+"\n").encode()
    path.write_bytes(data)
    (HERE / "oracle.sha256").write_text(f"{sha(data)}  benchmarks/replay_v3/oracle.json\n")
    paths = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", BASE], cwd=ROOT, text=True).splitlines()
    protected = {p: sha((ROOT/p).read_bytes()) for p in paths if p != "README.md"}
    (HERE / "protected_sources.json").write_text(json.dumps({"base_commit": BASE,
        "note": "Byte hashes only; implementation contents were not inspected during pre-registration.",
        "sha256": protected}, sort_keys=True, indent=2)+"\n")
    print(json.dumps({"oracle_sha256": sha(data), "cases": 3540,
        "protected_paths": len(protected), "bytes": len(data)}))


if __name__ == "__main__":
    main()
