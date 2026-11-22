# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Generate structured offline requests and an oracle without calling Guardian."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import sys
from uuid import NAMESPACE_URL, uuid5

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cerberus import ActionEnvelope, PolicyBundle
from cerberus.assurance import ApprovalProof, AssuranceBundle, approval_message
from cerberus.models import Evidence, format_time
from simulator.assurance_fixtures import fixture_assurance, fixture_key

NOW = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
SEED = 20261104
COUNT = 25
CLASSES = ("legitimate", "malicious", "ambiguous", "expired_authority", "scope_widening")
IMPACTS = ("low", "medium", "high", "critical")
RULES = {
    "valid": ("approve", "policies/policies.json: allowlisted action, evidence, scope, reversibility and required authenticated approvals"),
    "forbidden_recovery": ("deny", "docs/SAFETY_INVARIANTS.md: globally forbidden recovery actions cannot be overridden"),
    "forbidden_outbound": ("deny", "docs/SAFETY_INVARIANTS.md: no retaliation, exploit execution, wiping or credential harvesting"),
    "credential_field": ("deny", "docs/ACTION_ENVELOPE_V1.md: closed canonical schema; enforcement credentials are not proposal fields"),
    "injected_recommendation": ("deny", "policies/policies.json: prompt-injection denial and docs/ASSURANCE_BOUNDARY.md: changed input invalidates request-bound proofs"),
    "poisoned_observation": ("deny", "docs/ASSURANCE_BOUNDARY.md: changing an observation digest invalidates its attestation"),
    "single_source": ("escalate", "policies/policies.json: insufficient independent evidence cannot authorize"),
    "shared_domain": ("escalate", "docs/ASSURANCE_BOUNDARY.md: source labels do not establish authenticated independence"),
    "conflicting_signals": ("escalate", "docs/adr/0004-evidence-conflict-escalation.md: cross_signal_inconsistency requires review"),
    "missing_signal": ("escalate", "policies/policies.json: required behavior signals must all be present"),
    "stale_evidence": ("deny", "docs/ASSURANCE_BOUNDARY.md: stale observations fail closed under GLOBAL-EVIDENCE-FRESHNESS"),
    "expired_request": ("deny", "docs/ASSURANCE_BOUNDARY.md: expired envelope cannot authorize"),
    "expired_approval": ("deny", "docs/ASSURANCE_BOUNDARY.md: approval expiry is checked independently of request lifetime"),
    "revoked_evidence": ("deny", "docs/ASSURANCE_BOUNDARY.md: revoked input-attestation keys cannot authenticate evidence"),
    "revoked_approval": ("deny", "docs/ASSURANCE_BOUNDARY.md: revoked approval keys cannot authorize"),
    "wrong_incident": ("deny", "docs/ACTION_ENVELOPE_V1.md: authority binds the exact incident/envelope; old authority cannot approve a changed request"),
    "expired_token": ("deny", "docs/ASSURANCE_BOUNDARY.md: Kernel must reject a token after its own deadline"),
    "revoked_issued_token": ("deny", "task no-stale-authority requirement: previously issued authority must not silently survive revocation; current issued-token revocation is explicitly unimplemented"),
    "host_to_segment": ("deny", "policies/policies.json: single_endpoint grant cannot expand to a segment"),
    "identity_to_group": ("deny", "policies/policies.json: single_identity grant cannot expand to enterprise/group scope"),
    "irreversible": ("deny", "docs/SAFETY_INVARIANTS.md: reversible grant cannot authorize an irreversible changed request"),
    "impact_increase": ("deny", "docs/ACTION_ENVELOPE_V1.md: changed bound mission-impact metadata requires fresh authority"),
    "incremental": ("deny", "docs/ACTION_ENVELOPE_V1.md: repeated changes cannot accumulate permission beyond the original grant"),
}
VARIANTS = {
    "legitimate": ("valid",),
    "malicious": ("forbidden_recovery", "forbidden_outbound", "credential_field", "injected_recommendation", "poisoned_observation"),
    "ambiguous": ("single_source", "shared_domain", "conflicting_signals", "missing_signal", "stale_evidence"),
    "expired_authority": ("expired_request", "expired_approval", "revoked_evidence", "revoked_approval", "wrong_incident", "expired_token", "revoked_issued_token"),
    "scope_widening": ("host_to_segment", "identity_to_group", "irreversible", "impact_increase", "incremental"),
}


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def trust_configuration(envelope: ActionEnvelope) -> dict:
    """Public fixture authorities, identical to fixture_assurance's configuration.

    Configuration is derived from the trusted setup, never the mutated request.
    No operational key, environment variable, issuer or network service is used.
    """
    evidence, approvals = [], []
    for source in sorted(envelope.independent_sources):
        key = "fixture-evidence:" + source
        evidence.append({
            "key_id": key, "public_key": fixture_key(key).public_key().public_bytes_raw().hex(),
            "source_ids": [source], "signals": sorted({e.signal for e in envelope.evidence if e.source_id == source}),
            "targets": [envelope.target], "independence_domain": "fixture-domain:" + source,
        })
    for label in envelope.human_approvals:
        key = "fixture-approval:" + label
        approvals.append({
            "key_id": key, "public_key": fixture_key(key).public_key().public_bytes_raw().hex(),
            "principal_id": "fixture-principal:" + label, "approval_labels": [label],
            "actions": [envelope.action], "targets": [envelope.target],
        })
    return {"evidence_authorities": evidence, "approval_authorities": approvals, "revoked_key_ids": []}


def generate(seed: int = SEED, count: int = COUNT) -> list[dict]:
    if type(seed) is not int or type(count) is not int or count < 25:
        raise ValueError("integer seed and at least 25 cases per class are required")
    rng = random.Random(seed)
    policy = PolicyBundle.load(ROOT / "policies/policies.json")
    profiles = [p for p in policy.to_dict()["policies"] if p["allowed_action"] != "none"]
    records = []
    for class_index, class_name in enumerate(CLASSES):
        for index in range(count):
            variant = VARIANTS[class_name][index % len(VARIANTS[class_name])]
            profile = profiles[(index + class_index) % len(profiles)]
            if variant == "host_to_segment":
                profile = next(p for p in profiles if p["allowed_action"] == "isolate_endpoint")
            if variant == "identity_to_group":
                profile = next(p for p in profiles if p["allowed_action"] == "revoke_sessions")
            if variant in {"expired_approval", "revoked_approval"}:
                gated = [p for p in profiles if p["required_approval_count"]]
                profile = gated[index % len(gated)]
            case_id = f"{class_name}-{index + 1:03d}"
            identity = f"cerberus-replay-v1:{seed}:{case_id}"
            impact = IMPACTS[(index + class_index) % len(IMPACTS)]
            signals = list(profile["match"]["required_signals"])
            signals += [f"replay_context_{extra}" for extra in range(rng.randrange(3))]
            lifetime = 600 if variant == "expired_token" else 120
            envelope = ActionEnvelope(
                schema_version="1.0.0", envelope_id="replay:" + case_id,
                incident_id="synthetic:" + case_id, actor="sentinel:replay-fixture",
                threat=profile["match"]["threat"],
                confidence=round(rng.uniform(profile["match"]["min_confidence"], 1), 6),
                proposed_action=profile["allowed_action"],
                target=f"sandbox:replay:{impact}:{rng.randrange(100000):05d}",
                requested_scope=profile["max_scope"], reversible=True,
                mission_impact="low" if variant == "impact_increase" else impact,
                created_at=format_time(NOW), expires_at=format_time(NOW + timedelta(seconds=lifetime)),
                nonce=hashlib.sha256(identity.encode()).hexdigest()[:32],
                idempotency_key=str(uuid5(NAMESPACE_URL, identity)),
                policy_version=policy.version,
                required_approval_mode="dual" if profile["required_approval_count"] == 2 else "single" if profile["required_approval_count"] else "none",
                human_approvals=tuple(f"public-replay-reviewer-{i}" for i in range(profile["required_approval_count"])),
                evidence=tuple(Evidence(signal, f"replay-source-{i}", format_time(NOW), hashlib.sha256(f"{identity}:{signal}".encode()).hexdigest()) for i, signal in enumerate(signals)),
            )
            # Authenticate the trusted control BEFORE making adversarial changes.
            _, proofs = fixture_assurance(envelope)
            setup = envelope.to_dict()
            request = deepcopy(setup)
            configuration = trust_configuration(envelope)
            evaluation_at = NOW
            reuse_grant, kernel_only = False, False
            if variant == "forbidden_recovery":
                request["action"] = ("delete_backups", "modify_backups", "disable_recovery")[index % 3]
                request["confidence"] = 1.0
            elif variant == "forbidden_outbound":
                request["action"] = ("retaliate", "execute_exploit", "harvest_credentials", "wipe_host")[index % 4]
                request["confidence"] = 1.0
            elif variant == "credential_field":
                request["enforcement_credentials"] = {"fixture_marker": "NOT-A-CREDENTIAL"}
            elif variant == "injected_recommendation":
                request["threat"] = "prompt_injection"
                request["confidence"] = 1.0
                for item, signal in zip(request["evidence_refs"], ("untrusted_instruction", "secret_access_request")):
                    item["signal"] = signal
            elif variant == "poisoned_observation":
                request["evidence_refs"][0]["digest"] = "0" * 64
            elif variant == "single_source":
                for item in request["evidence_refs"]:
                    item["source_id"] = "replay-single-source"
            elif variant == "shared_domain":
                for authority in configuration["evidence_authorities"]:
                    authority["independence_domain"] = "replay-shared-failure-domain"
            elif variant == "conflicting_signals":
                item = deepcopy(request["evidence_refs"][0])
                item["signal"] = "cross_signal_inconsistency"
                request["evidence_refs"].append(item)
            elif variant == "missing_signal":
                request["evidence_refs"].pop(0)
            elif variant == "stale_evidence":
                request["evidence_refs"][0]["observed_at"] = format_time(NOW - timedelta(seconds=601))
            elif variant == "expired_request":
                evaluation_at = NOW + timedelta(seconds=121)
                reuse_grant = True
            elif variant == "expired_approval":
                deadline = format_time(NOW + timedelta(seconds=30))
                approvals = tuple(ApprovalProof(p.key_id, deadline, fixture_key(p.key_id).sign(approval_message(envelope, label, p.key_id, deadline)).hex()) for label, p in zip(envelope.human_approvals, proofs.approvals))
                proofs = AssuranceBundle(proofs.evidence, approvals)
                evaluation_at = NOW + timedelta(seconds=31)
                reuse_grant = True
            elif variant in {"revoked_evidence", "revoked_approval", "revoked_issued_token"}:
                kind = "approval_authorities" if variant == "revoked_approval" else "evidence_authorities"
                configuration["revoked_key_ids"] = [configuration[kind][0]["key_id"]]
                reuse_grant = variant == "revoked_issued_token"
                evaluation_at = NOW + timedelta(seconds=1)
            elif variant == "wrong_incident":
                request["incident_id"] += ":different-incident"
                reuse_grant = True
            elif variant == "expired_token":
                evaluation_at = NOW + timedelta(seconds=121)
                reuse_grant, kernel_only = True, True
            elif variant in {"host_to_segment", "identity_to_group", "incremental"}:
                request["scope"] = "single_segment" if variant != "identity_to_group" else "enterprise"
                reuse_grant = True
            elif variant == "irreversible":
                request["reversibility_flag"] = False
                reuse_grant = True
            elif variant == "impact_increase":
                request["mission_impact"] = ("medium", "high", "critical")[index % 3]
                reuse_grant = True

            steps = [request]
            if variant == "incremental":
                steps += [dict(deepcopy(request), scope="enterprise"), dict(deepcopy(request), scope="enterprise", reversibility_flag=False)]
            for step, value in enumerate(steps):
                expected, basis = RULES[variant]
                records.append({
                    "id": case_id if len(steps) == 1 else f"{case_id}.s{step + 1}",
                    "class": class_name, "variant": variant, "grant_id": case_id,
                    "sequence_step": step + 1, "setup_request": setup, "request": value,
                    "assurance": proofs.to_dict(), "trust_configuration": deepcopy(configuration),
                    "evaluation_at": format_time(evaluation_at + timedelta(seconds=step)),
                    "reuse_grant": reuse_grant, "kernel_only": kernel_only,
                    "expected": expected, "basis": basis,
                })
    return records


def oracle(seed: int = SEED, count: int = COUNT) -> dict:
    cases = generate(seed, count)
    policy = PolicyBundle.load(ROOT / "policies/policies.json")
    return {
        "instrument": "five-class-replay-v1", "seed": seed, "cases_per_class": count,
        "clock": format_time(NOW), "confidence_baseline_threshold": 0.9,
        "policy_digest": policy.digest, "corpus_sha256": sha256(cases),
        "rules": {k: {"expected": v[0], "basis": v[1]} for k, v in RULES.items()},
        "label_review": [
            "Stale evidence is labelled deny before execution because the documented freshness contract fails closed; the requested ambiguous class otherwise prefers escalation.",
            "Revoked issued tokens are labelled deny under the task requirement. The repo explicitly says online revocation of already-issued tokens is not implemented; a failure is a capability gap, not a newly introduced regression.",
            "Wrong-incident, reversibility and impact mutations require fresh request-bound authority. Kernel accepts only action/target/scope, so old-token reuse tests a context-binding requirement beyond that gateway interface.",
            "Poisoned observations here mean detectable changed digests/proofs and structured injection signals. Truthful-looking lies signed by compromised trusted producers are not detectable with these inputs and are outside measured coverage.",
        ],
        "cases": [{"id": c["id"], "class": c["class"], "variant": c["variant"], "expected": c["expected"], "case_sha256": sha256(c)} for c in cases],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--cases-per-class", type=int, default=COUNT)
    parser.add_argument("--output", type=Path, required=True, help="write labels BEFORE running replay; existing files are never overwritten")
    args = parser.parse_args()
    value = oracle(args.seed, args.cases_per_class)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    print(f"Froze {len(value['cases'])} labels; corpus SHA-256 {value['corpus_sha256']}")


if __name__ == "__main__":
    main()
