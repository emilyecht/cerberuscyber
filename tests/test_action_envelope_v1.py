from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from cerberus import (
    ACTION_ENVELOPE_VERSION,
    ActionEnvelope,
    DecisionTokenSigner,
    Evidence,
    Guardian,
    ValidationError,
)
from cerberus.models import format_time

ROOT = Path(__file__).resolve().parents[1]
POLICIES = json.loads((ROOT / "policies" / "policies.json").read_text(encoding="utf-8"))
SCHEMA = json.loads(
    (ROOT / "schemas" / "action-envelope.schema.json").read_text(encoding="utf-8")
)
TEST_KEY = b"cerberus-action-envelope-v1-test-key-material-32-bytes"


def _envelope() -> ActionEnvelope:
    now = datetime(2026, 7, 18, 20, 0, tzinfo=timezone.utc)
    return ActionEnvelope(
        schema_version=ACTION_ENVELOPE_VERSION,
        envelope_id="env-action-envelope-v1-test",
        incident_id="INC-AE-V1-001",
        threat="ransomware",
        confidence=0.99,
        proposed_action="isolate_endpoint",
        target="endpoint:action-envelope-sandbox-1",
        requested_scope="single_endpoint",
        reversible=True,
        mission_impact="low",
        created_at=format_time(now),
        expires_at=format_time(now + timedelta(minutes=2)),
        nonce="action-envelope-v1-nonce-0001",
        evidence=(
            Evidence(
                "rapid_file_rewrite",
                "edr:sandbox-observer-1",
                format_time(now),
                "a" * 64,
            ),
            Evidence(
                "recovery_deletion_attempt",
                "backup:sandbox-observer-2",
                format_time(now),
                "b" * 64,
            ),
        ),
        actor="sentinel:ransomware-detector-1",
        idempotency_key="20b58d34-26f3-4de9-b3c1-77a28a3b8ec1",
        required_approval_mode="none",
        policy_version=POLICIES["version"],
    )


def test_canonical_payload_validates_against_draft_2020_12_schema() -> None:
    envelope = _envelope()
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(envelope.to_canonical_dict()), key=lambda item: item.path)
    assert errors == []
    assert envelope.schema_version == "1.0.0"
    assert UUID(envelope.idempotency_key).version == 4


def test_canonical_serialization_and_digest_are_stable() -> None:
    envelope = _envelope()
    assert envelope.canonical_json() == envelope.canonical_json()
    assert envelope.digest() == envelope.digest()
    assert len(envelope.digest()) == 64

    changed_target = replace(envelope, target="endpoint:action-envelope-sandbox-2")
    assert changed_target.digest() != envelope.digest()


def test_unknown_action_type_fails_closed_on_construction() -> None:
    with pytest.raises(ValidationError, match="unknown action type"):
        replace(_envelope(), proposed_action="invented_unreviewed_action")


def test_guardian_rejects_policy_version_mismatch() -> None:
    envelope = replace(_envelope(), policy_version="9.9.9")
    decision = Guardian(POLICIES).evaluate(envelope)
    assert decision.guardian_decision == "deny"
    assert decision.policy == "GLOBAL-POLICY-VERSION-INVARIANT"
    assert "requires policy version" in decision.reason


def test_guardian_rejects_reused_idempotency_key() -> None:
    guardian = Guardian(POLICIES)
    envelope = _envelope()
    first = guardian.evaluate(envelope)
    second = guardian.evaluate(envelope)

    assert first.guardian_decision == "approve"
    assert second.guardian_decision == "deny"
    assert second.policy == "GLOBAL-IDEMPOTENCY-INVARIANT"


def test_signed_token_binds_exact_canonical_envelope_digest() -> None:
    signer = DecisionTokenSigner(TEST_KEY)
    envelope = _envelope()
    decision = Guardian(POLICIES, signer=signer).evaluate(envelope)
    assert decision.decision_token is not None

    payload = signer.verify(decision.decision_token)
    assert payload["envelope_digest"] == envelope.digest()
    assert payload["idempotency_key"] == envelope.idempotency_key
    assert payload["actor"] == envelope.actor
    assert payload["policy_version"] == envelope.policy_version


def test_legacy_fixture_adapter_emits_canonical_v1_contract() -> None:
    envelope = ActionEnvelope.from_legacy_incident(
        {
            "incident_id": "LEGACY-001",
            "threat": "ransomware",
            "confidence": 0.99,
            "signals": ["rapid_file_rewrite", "recovery_deletion_attempt"],
            "proposed_action": "isolate_endpoint",
        },
        policy_version=POLICIES["version"],
        now=datetime(2026, 7, 18, 20, 0, tzinfo=timezone.utc),
    )

    canonical = envelope.to_canonical_dict()
    assert canonical["schema_version"] == "1.0.0"
    assert canonical["action"] == "isolate_endpoint"
    assert canonical["scope"] == "single_endpoint"
    assert canonical["policy_version"] == POLICIES["version"]
    assert all(item["digest"] for item in canonical["evidence_refs"])


def test_schema_rejects_missing_actor() -> None:
    payload = _envelope().to_canonical_dict()
    del payload["actor"]
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    assert any(error.validator == "required" for error in validator.iter_errors(payload))
