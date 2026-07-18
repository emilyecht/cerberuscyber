#!/usr/bin/env python3
"""Run synthetic embedded-agent telemetry through all three CERBERUS layers.

The program is defensive, read-only, and side-effect free. It does not contact a network,
inspect a real host, attribute a state sponsor, or perform containment.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from cerberus import DecisionTokenSigner, EnforcementGateway, Guardian
from cerberus.hunt import EmbeddedAgentHunter, TelemetryEvent

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICIES = ROOT / "policies" / "policies.json"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CERBERUS synthetic embedded AI-agent hunt simulation"
    )
    parser.add_argument("telemetry", type=Path, help="Synthetic telemetry JSON file")
    parser.add_argument("--policies", type=Path, default=DEFAULT_POLICIES)
    parser.add_argument(
        "--approval",
        action="append",
        default=[],
        help="Named human approval; repeat twice to satisfy the mission-workload policy",
    )
    parser.add_argument(
        "--simulate-enforcement",
        action="store_true",
        help="demonstrate signed, one-time, side-effect-free enforcement",
    )
    args = parser.parse_args()

    scenario = load_json(args.telemetry)
    policies = load_json(args.policies)
    events = tuple(TelemetryEvent.from_dict(item) for item in scenario.get("events", []))
    asset = str(scenario.get("asset", ""))
    incident_id = str(scenario.get("incident_id", "CRB-EMBEDDED-AGENT"))

    hunter = EmbeddedAgentHunter()
    finding = hunter.hunt(events, asset=asset)
    if finding is None:
        print(
            json.dumps(
                {
                    "sentinel": {
                        "status": "no_finding",
                        "reason": "insufficient correlated signals or independent sources",
                    }
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    envelope = hunter.build_action_envelope(
        finding,
        incident_id=incident_id,
        human_approvals=args.approval,
        policy_version=str(policies.get("version", "0.0.0-legacy")),
    )

    signing_key: bytes | None = None
    if args.simulate_enforcement:
        key_text = os.environ.get("CERBERUS_PROTOTYPE_SIGNING_KEY")
        if key_text is None or len(key_text.encode("utf-8")) < 32:
            parser.error(
                "CERBERUS_PROTOTYPE_SIGNING_KEY must be set to at least 32 bytes "
                "when --simulate-enforcement is used"
            )
        signing_key = key_text.encode("utf-8")

    signer = DecisionTokenSigner(signing_key) if signing_key is not None else None
    decision = Guardian(policies, signer=signer).evaluate(envelope)
    output: dict[str, Any] = {
        "sentinel": finding.to_dict(),
        "action_envelope": envelope.to_dict(),
        "guardian": decision.to_dict(),
    }

    if args.simulate_enforcement and decision.guardian_decision == "approve":
        gateway = EnforcementGateway(DecisionTokenSigner(signing_key or b""))
        output["enforcement"] = gateway.authorize_and_simulate(
            decision.decision_token or "",
            action=decision.authorized_action,
            target=decision.target,
            scope=decision.scope,
        )

    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
