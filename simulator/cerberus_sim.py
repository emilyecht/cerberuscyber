#!/usr/bin/env python3
"""CERBERUS Cyber defensive policy simulator.

This prototype reads a simulated incident and evaluates it against deterministic
Guardian policies. It performs no real containment and has no external effects.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICIES = ROOT / "policies" / "policies.json"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def evaluate(incident: dict[str, Any], policy_set: dict[str, Any]) -> dict[str, Any]:
    proposed_action = incident.get("proposed_action", "none")
    forbidden = set(policy_set.get("forbidden_actions", []))

    if proposed_action in forbidden:
        return {
            "incident_id": incident.get("incident_id", "unknown"),
            "guardian_decision": "deny",
            "reason": "proposed action is globally forbidden",
            "policy": "GLOBAL-INVARIANT",
            "proposed_action": proposed_action,
            "authorized_action": "none",
        }

    incident_signals = set(incident.get("signals", []))
    confidence = float(incident.get("confidence", 0.0))
    threat = incident.get("threat")

    for policy in policy_set.get("policies", []):
        match = policy.get("match", {})
        required = set(match.get("required_signals", []))

        if threat != match.get("threat"):
            continue
        if confidence < float(match.get("min_confidence", 1.0)):
            continue
        if not required.issubset(incident_signals):
            continue

        allowed_action = policy.get("allowed_action", "none")
        if proposed_action != allowed_action and policy.get("decision") == "approve":
            return {
                "incident_id": incident.get("incident_id", "unknown"),
                "guardian_decision": "deny",
                "reason": "proposed action does not match the policy allowlist",
                "policy": policy.get("id"),
                "proposed_action": proposed_action,
                "authorized_action": "none",
            }

        return {
            "incident_id": incident.get("incident_id", "unknown"),
            "threat": threat,
            "confidence": confidence,
            "guardian_decision": policy.get("decision"),
            "policy": policy.get("id"),
            "proposed_action": proposed_action,
            "authorized_action": allowed_action,
            "scope": policy.get("max_scope"),
            "reversible": policy.get("reversible"),
            "human_approval_required": policy.get("human_approval_required"),
            "evidence": sorted(incident_signals),
        }

    return {
        "incident_id": incident.get("incident_id", "unknown"),
        "guardian_decision": "escalate",
        "reason": "no policy satisfied the evidence and confidence requirements",
        "policy": None,
        "proposed_action": proposed_action,
        "authorized_action": "none",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="CERBERUS Cyber policy simulator")
    parser.add_argument("scenario", type=Path, help="Path to a scenario JSON file")
    parser.add_argument("--policies", type=Path, default=DEFAULT_POLICIES)
    args = parser.parse_args()

    result = evaluate(load_json(args.scenario), load_json(args.policies))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
