"""Regressions for proposal-to-authorization changes and input coercion."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from cerberus import ActionEnvelope, DecisionTokenSigner, Guardian, ValidationError

ROOT = Path(__file__).resolve().parents[1]
POLICIES = json.loads((ROOT / "policies/policies.json").read_text(encoding="utf-8"))
TEST_KEY = b"cerberus-exact-action-contract-regression-key-32-bytes"


def _envelope(threat: str = "ransomware") -> ActionEnvelope:
    incident = json.loads(
        (ROOT / f"simulator/scenarios/{threat}.json").read_text(encoding="utf-8")
    )
    return ActionEnvelope.from_legacy_incident(incident, policy_version=POLICIES["version"])


@pytest.mark.parametrize("approval_count", [1, 2])
def test_approval_transition_cannot_substitute_another_action(approval_count: int) -> None:
    policies = deepcopy(POLICIES)
    policy = next(p for p in policies["policies"] if p["id"] == "CYBER-EX-001")
    policy["required_approval_count"] = approval_count
    envelope = replace(
        _envelope("data_exfiltration"),
        proposed_action="preserve_evidence",
        human_approvals=tuple(f"reviewer-{i}" for i in range(approval_count)),
        required_approval_mode="single" if approval_count == 1 else "dual",
    )
    decision = Guardian(policies, signer=DecisionTokenSigner(TEST_KEY)).evaluate(envelope)

    assert decision.guardian_decision == "deny"
    assert "action" in decision.reason
    assert decision.authorized_action == "none"
    assert decision.decision_token is None


@pytest.mark.parametrize("scope", ["single_identity", "none"])
def test_scope_order_does_not_make_unrelated_action_scopes_compatible(scope: str) -> None:
    envelope = replace(_envelope(), requested_scope=scope)
    decision = Guardian(POLICIES, signer=DecisionTokenSigner(TEST_KEY)).evaluate(envelope)
    assert decision.guardian_decision == "deny"
    assert "scope" in decision.reason
    assert decision.decision_token is None


def test_broader_policy_ceiling_never_widens_the_approved_scope() -> None:
    policies = deepcopy(POLICIES)
    policy = next(p for p in policies["policies"] if p["id"] == "CYBER-RW-001")
    policy["max_scope"] = "enterprise"
    envelope = _envelope()
    signer = DecisionTokenSigner(TEST_KEY)
    decision = Guardian(policies, signer=signer).evaluate(envelope)

    assert decision.guardian_decision == "approve"
    assert decision.scope == envelope.requested_scope == "single_endpoint"
    payload = signer.verify(decision.decision_token)
    assert (payload["action"], payload["target"], payload["scope"]) == (
        envelope.action, envelope.target, envelope.scope
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorized_action", "preserve_evidence"),
        ("proposed_action", "preserve_evidence"),
        ("target", "endpoint:different-sandbox"),
        ("scope", "enterprise"),
        ("reversible", False),
        ("reversible", 1),
        ("policy_version", "9.9.9"),
        ("actor", "sentinel:different-actor"),
        ("envelope_id", "different-envelope"),
        ("incident_id", "different-incident"),
    ],
)
def test_signer_rejects_divergent_decision_even_with_correct_digest(field, value) -> None:
    envelope = _envelope()
    approved = Guardian(POLICIES).evaluate(envelope)
    assert approved.guardian_decision == "approve"
    changed = replace(approved, **{field: value})
    assert changed.envelope_digest == envelope.digest()
    with pytest.raises(ValueError):
        DecisionTokenSigner(TEST_KEY).issue(changed, envelope, ttl_seconds=120)


@pytest.mark.parametrize("value", ["false", "true", 0, 1, None])
def test_canonical_reversibility_requires_an_actual_boolean(value) -> None:
    payload = _envelope().to_dict()
    payload["reversibility_flag"] = value
    with pytest.raises(ValidationError):
        ActionEnvelope.from_dict(payload)


def test_boolean_false_survives_parsing_and_fails_reversibility_policy() -> None:
    payload = _envelope().to_dict()
    payload["reversibility_flag"] = False
    envelope = ActionEnvelope.from_dict(payload)
    assert envelope.reversible is False
    decision = Guardian(POLICIES, signer=DecisionTokenSigner(TEST_KEY)).evaluate(envelope)
    assert decision.guardian_decision == "deny"
    assert "reversible" in decision.reason
    assert decision.decision_token is None


@pytest.mark.parametrize("value", [True, "0.99", float("nan"), float("inf")])
def test_confidence_requires_a_finite_json_number(value) -> None:
    payload = _envelope().to_dict()
    payload["confidence"] = value
    with pytest.raises(ValidationError):
        ActionEnvelope.from_dict(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("actor",), 123),
        (("target",), None),
        (("human_approvals",), [123]),
        (("unknown_field",), "discarded before validation"),
        (("freshness", "timestamp"), 123),
        (("freshness", "timestamp"), "2026-07-18 20:00:00+00:00"),
        (("freshness", "extra"), True),
        (("evidence_refs", 0, "digest"), None),
        (("evidence_refs", 0, "digest"), "A" * 64),
        (("evidence_refs", 0, "source_id"), 123),
        (("evidence_refs", 0, "extra"), True),
        (("evidence_refs", 0), "not an evidence object"),
    ],
)
def test_original_canonical_fields_are_validated_before_conversion(path, value) -> None:
    payload = _envelope().to_dict()
    parent = payload
    for part in path[:-1]:
        parent = parent[part]
    parent[path[-1]] = value
    with pytest.raises(ValidationError):
        ActionEnvelope.from_dict(payload)


@pytest.mark.parametrize("field", ["human_approvals", "reversibility_flag"])
def test_canonical_parser_does_not_default_missing_required_fields(field: str) -> None:
    payload = _envelope().to_dict()
    del payload[field]
    with pytest.raises(ValidationError):
        ActionEnvelope.from_dict(payload)


def test_canonical_evidence_requires_a_supplied_digest() -> None:
    payload = _envelope().to_dict()
    del payload["evidence_refs"][0]["digest"]
    with pytest.raises(ValidationError):
        ActionEnvelope.from_dict(payload)


@pytest.mark.parametrize("payload", [None, [], "not an envelope"])
def test_non_object_canonical_input_fails_with_validation_error(payload) -> None:
    with pytest.raises(ValidationError):
        ActionEnvelope.from_dict(payload)


def test_signer_refuses_a_self_consistent_but_incompatible_action_scope() -> None:
    envelope = _envelope()
    decision = Guardian(POLICIES).evaluate(envelope)
    incompatible = replace(envelope, requested_scope="single_identity")
    changed = replace(
        decision, scope=incompatible.scope, envelope_digest=incompatible.digest()
    )
    with pytest.raises(ValueError, match="action/scope"):
        DecisionTokenSigner(TEST_KEY).issue(changed, incompatible, ttl_seconds=120)


def test_legacy_envelopes_require_the_explicit_migration_entrypoint() -> None:
    legacy = _envelope().to_legacy_dict()
    with pytest.raises(ValidationError):
        ActionEnvelope.from_dict(legacy)
    migrated = ActionEnvelope.from_legacy_envelope_dict(legacy)
    assert migrated.action == legacy["proposed_action"]
    assert migrated.reversible is legacy["reversible"]


@pytest.mark.parametrize("adapter", ["from_legacy_incident", "from_legacy_envelope_dict"])
def test_explicit_legacy_adapters_do_not_coerce_false_strings(adapter: str) -> None:
    legacy = _envelope().to_legacy_dict()
    legacy["signals"] = ["rapid_file_rewrite", "recovery_deletion_attempt"]
    legacy["reversible"] = "false"
    with pytest.raises(ValidationError):
        getattr(ActionEnvelope, adapter)(legacy)


@pytest.mark.parametrize(
    "changes",
    [
        {"reversible": "false"},
        {"confidence": True},
        {"actor": 123},
        {"evidence": ("not evidence",)},
        {"human_approvals": "reviewer"},
    ],
)
def test_direct_construction_cannot_bypass_input_type_checks(changes) -> None:
    with pytest.raises(ValidationError):
        replace(_envelope(), **changes)


def test_canonical_round_trip_preserves_the_signed_proposal() -> None:
    envelope = _envelope()
    parsed = ActionEnvelope.from_dict(json.loads(envelope.canonical_json()))
    assert parsed.to_dict() == envelope.to_dict()
    assert parsed.digest() == envelope.digest()
    assert Guardian(POLICIES).evaluate(parsed).guardian_decision == "approve"
