#!/usr/bin/env python3
"""CERBERUS Cyber defensive policy simulator.

The CLI remains side-effect free. It can optionally demonstrate the complete signed
Guardian-to-Enforcement path using an explicit environment-supplied prototype key.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from cerberus import (
    ActionEnvelope,
    DecisionTokenSigner,
    EnforcementGateway,
    Guardian,
    PolicyBundle,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICIES = ROOT / "policies" / "policies.json"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def evaluate(
    incident: dict[str, Any],
    policy_set: PolicyBundle | dict[str, Any],
    *,
    signing_key: bytes | None = None,
) -> dict[str, Any]:
    """Backward-compatible simulator entry point backed by ActionEnvelope v1.0.0."""

    bundle = (
        policy_set
        if isinstance(policy_set, PolicyBundle)
        else PolicyBundle.from_dict(policy_set)
    )
    envelope = ActionEnvelope.from_legacy_incident(
        incident,
        policy_version=bundle.version,
        ttl_seconds=int(bundle.to_dict()["decision_ttl_seconds"]),
    )
    signer = DecisionTokenSigner(signing_key) if signing_key is not None else None
    result = Guardian(bundle, signer=signer).evaluate(envelope)
    return result.to_dict()


def main() -> None:
    parser = argparse.ArgumentParser(description="CERBERUS Cyber policy simulator")
    parser.add_argument("scenario", type=Path, help="Path to a scenario JSON file")
    parser.add_argument("--policies", type=Path, default=DEFAULT_POLICIES)
    parser.add_argument(
        "--simulate-enforcement",
        action="store_true",
        help="demonstrate signed, one-time, side-effect-free enforcement",
    )
    args = parser.parse_args()

    policy_set = PolicyBundle.load(args.policies)
    signing_key: bytes | None = None
    if args.simulate_enforcement:
        key_text = os.environ.get("CERBERUS_PROTOTYPE_SIGNING_KEY")
        if key_text is None or len(key_text.encode("utf-8")) < 32:
            parser.error(
                "CERBERUS_PROTOTYPE_SIGNING_KEY must be set to at least 32 bytes "
                "when --simulate-enforcement is used"
            )
        signing_key = key_text.encode("utf-8")

    result = evaluate(load_json(args.scenario), policy_set, signing_key=signing_key)
    output: dict[str, Any] = {"guardian": result}

    if args.simulate_enforcement and result["guardian_decision"] == "approve":
        signer = DecisionTokenSigner(signing_key or b"")
        gateway = EnforcementGateway(signer)
        output["enforcement"] = gateway.authorize_and_simulate(
            result["decision_token"],
            action=result["authorized_action"],
            target=result["target"],
            scope=result["scope"],
        )

    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
