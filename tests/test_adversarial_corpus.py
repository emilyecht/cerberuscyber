from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from cerberus import DecisionTokenSigner, EnforcementGateway, Guardian
from cerberus.hunt import EmbeddedAgentHunter, TelemetryEvent
from simulator.scenarios.embedded_agent_adversarial_corpus import SCENARIOS


ROOT = Path(__file__).resolve().parents[1]
TEST_KEY = b"cerberus-adversarial-corpus-test-key-material-32-bytes-minimum"


@pytest.fixture(scope="module")
def policy_set() -> dict[str, Any]:
    return json.loads(
        (ROOT / "policies" / "policies.json").read_text(encoding="utf-8")
    )


@pytest.fixture(scope="module")
def signer() -> DecisionTokenSigner:
    return DecisionTokenSigner(TEST_KEY)


@pytest.fixture()
def hunter() -> EmbeddedAgentHunter:
    return EmbeddedAgentHunter()


@pytest.fixture(
    params=SCENARIOS,
    ids=[scenario["id"] for scenario in SCENARIOS],
)
def scenario(request: pytest.FixtureRequest) -> dict[str, Any]:
    return request.param


def _evaluate_scenario(
    scenario: dict[str, Any],
    *,
    hunter: EmbeddedAgentHunter,
    signer: DecisionTokenSigner,
    policy_set: dict[str, Any],
) -> dict[str, Any]:
    events = tuple(TelemetryEvent.from_dict(item) for item in scenario["events"])
    finding = hunter.hunt(events, asset=scenario["asset"])

    sentinel_expectation = scenario["sentinel_expectation"]
    assert (finding is not None) is sentinel_expectation["finding_present"]

    result: dict[str, Any] = {
        "finding": finding,
        "decision": None,
        "receipt": None,
    }
    if finding is None:
        return result

    finding_overrides = scenario.get("finding_overrides", {})
    if finding_overrides:
        finding = replace(finding, **finding_overrides)
        result["finding"] = finding

    required_signals = set(sentinel_expectation.get("required_signals", []))
    missing_signals = set(sentinel_expectation.get("missing_signals", []))
    assert required_signals.issubset(set(finding.signals))
    assert missing_signals.isdisjoint(set(finding.signals))

    if "confidence_min" in sentinel_expectation:
        assert finding.confidence >= sentinel_expectation["confidence_min"]
    if "confidence_exact" in sentinel_expectation:
        assert finding.confidence == sentinel_expectation["confidence_exact"]

    envelope = hunter.build_action_envelope(
        finding,
        incident_id=f"CRB-CORPUS-{scenario['id'].upper()}",
        human_approvals=tuple(scenario.get("human_approvals", [])),
    )
    envelope_overrides = scenario.get("envelope_overrides", {})
    if envelope_overrides:
        envelope = replace(envelope, **envelope_overrides)
        envelope.validate()

    decision = Guardian(policy_set, signer=signer).evaluate(envelope)
    result["decision"] = decision

    guardian_expectation = scenario["guardian_expectation"]
    assert decision.guardian_decision == guardian_expectation["decision"]
    assert decision.policy == guardian_expectation["policy"]
    assert guardian_expectation.get("reason_contains", "") in decision.reason

    enforcement_expectation = scenario["enforcement_expectation"]
    if decision.guardian_decision != "approve":
        assert decision.decision_token is None
        assert enforcement_expectation["status"] == "not_invoked"
        return result

    assert decision.decision_token is not None
    receipt = EnforcementGateway(signer).authorize_and_simulate(
        decision.decision_token,
        action=decision.authorized_action,
        target=decision.target,
        scope=decision.scope,
    )
    result["receipt"] = receipt
    assert receipt["status"] == enforcement_expectation["status"]
    assert receipt["side_effects"] is enforcement_expectation["side_effects"]
    return result


def test_corpus_metadata_is_fabricated_reproducible_and_sandboxed(
    scenario: dict[str, Any],
) -> None:
    assert scenario["telemetry_classification"] == "fabricated"
    assert scenario["side_effects"] is False
    assert "sandbox" in scenario["asset"]
    assert scenario["events"]
    assert scenario["adversarial_intent"].strip()

    event_ids = [event["event_id"] for event in scenario["events"]]
    assert len(event_ids) == len(set(event_ids))
    assert all(event["asset"] == scenario["asset"] for event in scenario["events"])
    assert all(len(event["attributes"]["digest"]) == 64 for event in scenario["events"])


def test_each_adversarial_scenario_matches_its_expected_authority_path(
    scenario: dict[str, Any],
    hunter: EmbeddedAgentHunter,
    signer: DecisionTokenSigner,
    policy_set: dict[str, Any],
) -> None:
    result = _evaluate_scenario(
        scenario,
        hunter=hunter,
        signer=signer,
        policy_set=policy_set,
    )
    expected_decision = scenario["guardian_expectation"]["decision"]
    if expected_decision == "not_evaluated":
        assert result["decision"] is None
    else:
        assert result["decision"] is not None


def test_invariant_integrity_has_zero_tolerated_forbidden_action_violations(
    signer: DecisionTokenSigner,
    policy_set: dict[str, Any],
) -> None:
    candidates = [
        item for item in SCENARIOS if item["category"] == "invariant_boundary"
    ]
    assert candidates

    violations = 0
    for candidate in candidates:
        result = _evaluate_scenario(
            candidate,
            hunter=EmbeddedAgentHunter(),
            signer=signer,
            policy_set=policy_set,
        )
        decision = result["decision"]
        assert decision is not None
        if decision.guardian_decision == "approve" or decision.decision_token is not None:
            violations += 1

    assert violations == 0


def test_false_containment_rate_is_zero_for_benign_conditions(
    signer: DecisionTokenSigner,
    policy_set: dict[str, Any],
) -> None:
    benign = [
        item for item in SCENARIOS if item["category"] == "benign_false_positive"
    ]
    assert benign

    false_containments = 0
    for candidate in benign:
        result = _evaluate_scenario(
            candidate,
            hunter=EmbeddedAgentHunter(),
            signer=signer,
            policy_set=policy_set,
        )
        decision = result["decision"]
        receipt = result["receipt"]
        if (
            decision is not None
            and decision.guardian_decision == "approve"
        ) or receipt is not None:
            false_containments += 1

    false_containment_rate = false_containments / len(benign)
    assert false_containment_rate == 0.0


def test_escalation_accuracy_is_complete_when_requirements_are_partial(
    signer: DecisionTokenSigner,
    policy_set: dict[str, Any],
) -> None:
    partial = [
        item
        for item in SCENARIOS
        if item["category"] in {"approval_boundary", "partial_evidence"}
    ]
    assert partial

    correct = 0
    for candidate in partial:
        result = _evaluate_scenario(
            candidate,
            hunter=EmbeddedAgentHunter(),
            signer=signer,
            policy_set=policy_set,
        )
        decision = result["decision"]
        assert decision is not None
        if decision.guardian_decision == "escalate":
            correct += 1

    assert correct / len(partial) == 1.0


def test_every_enforcement_receipt_remains_side_effect_free(
    signer: DecisionTokenSigner,
    policy_set: dict[str, Any],
) -> None:
    approved_controls = [
        item for item in SCENARIOS if item["category"] == "positive_control"
    ]
    assert approved_controls

    for candidate in approved_controls:
        result = _evaluate_scenario(
            candidate,
            hunter=EmbeddedAgentHunter(),
            signer=signer,
            policy_set=policy_set,
        )
        assert result["receipt"] is not None
        assert result["receipt"]["status"] == "simulated"
        assert result["receipt"]["side_effects"] is False
