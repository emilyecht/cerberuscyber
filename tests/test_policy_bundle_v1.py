from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from cerberus import (
    ACTION_ENVELOPE_VERSION,
    ActionEnvelope,
    DecisionTokenSigner,
    EnforcementGateway,
    Evidence,
    Guardian,
    PolicyBundle,
    PolicyBundleError,
)
from cerberus.models import format_time

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "policies.json"
POLICY_SCHEMA = json.loads(
    (ROOT / "schemas" / "policy-bundle.schema.json").read_text(encoding="utf-8")
)
TOKEN_SCHEMA = json.loads(
    (ROOT / "schemas" / "decision-token.schema.json").read_text(encoding="utf-8")
)
TEST_KEY = b"cerberus-policy-bundle-v1-test-key-material-32-bytes"


def _ransomware_envelope(policy_version: str) -> ActionEnvelope:
    now = datetime.now(timezone.utc)
    return ActionEnvelope(
        schema_version=ACTION_ENVELOPE_VERSION,
        envelope_id="env-policy-bundle-v1-test",
        incident_id="INC-POLICY-V1-001",
        threat="ransomware",
        confidence=0.99,
        proposed_action="isolate_endpoint",
        target="endpoint:policy-bundle-sandbox-1",
        requested_scope="single_endpoint",
        reversible=True,
        mission_impact="low",
        created_at=format_time(now),
        expires_at=format_time(now + timedelta(minutes=2)),
        nonce="policy-bundle-v1-nonce-0001",
        evidence=(
            Evidence(
                "rapid_file_rewrite",
                "edr:policy-test-1",
                format_time(now),
                "a" * 64,
            ),
            Evidence(
                "recovery_deletion_attempt",
                "backup:policy-test-2",
                format_time(now),
                "b" * 64,
            ),
        ),
        actor="sentinel:policy-bundle-test-1",
        idempotency_key="0f80f89e-3fe7-4d16-8a0e-b21c5e53c091",
        required_approval_mode="none",
        policy_version=policy_version,
    )


def test_repository_policy_bundle_validates_against_schema() -> None:
    payload = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(POLICY_SCHEMA, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.path))
    assert errors == []

    bundle = PolicyBundle.load(POLICY_PATH)
    assert bundle.schema_version == "1.0.0"
    assert bundle.version == payload["version"]
    assert len(bundle.digest) == 64


def test_canonical_policy_digest_is_stable_across_key_order() -> None:
    payload = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    reversed_payload = dict(reversed(list(payload.items())))

    original = PolicyBundle.from_dict(payload)
    reordered = PolicyBundle.from_dict(reversed_payload)

    assert original.canonical_json == reordered.canonical_json
    assert original.digest == reordered.digest


def test_same_version_with_changed_rules_gets_different_digest() -> None:
    payload = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    changed = deepcopy(payload)
    changed["decision_ttl_seconds"] += 1

    original = PolicyBundle.from_dict(payload)
    modified = PolicyBundle.from_dict(changed)

    assert original.version == modified.version
    assert original.digest != modified.digest


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-policy.json"
    path.write_text(
        '{"schema_version":"1.0.0","schema_version":"1.0.0"}',
        encoding="utf-8",
    )

    with pytest.raises(PolicyBundleError, match="duplicate JSON object key"):
        PolicyBundle.load(path)


def test_order_dependent_duplicate_threat_policies_fail_closed() -> None:
    payload = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    duplicate = deepcopy(payload["policies"][0])
    duplicate["id"] = "CYBER-ID-ORDER-DEPENDENT"
    payload["policies"].append(duplicate)

    with pytest.raises(PolicyBundleError, match="order-dependent first-match"):
        PolicyBundle.from_dict(payload)


def test_policy_cannot_allow_a_globally_forbidden_action() -> None:
    payload = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    payload["policies"][0]["allowed_action"] = "wipe_host"

    with pytest.raises(PolicyBundleError, match="globally forbidden"):
        PolicyBundle.from_dict(payload)


def test_policy_digest_binds_decision_token_and_receipt() -> None:
    bundle = PolicyBundle.load(POLICY_PATH)
    signer = DecisionTokenSigner(TEST_KEY)
    envelope = _ransomware_envelope(bundle.version)

    decision = Guardian(bundle, signer=signer).evaluate(envelope)
    assert decision.guardian_decision == "approve"
    assert decision.policy_digest == bundle.digest
    assert decision.decision_token is not None

    payload = signer.verify(decision.decision_token)
    assert payload["token_version"] == "1.2.0"
    assert payload["policy_version"] == bundle.version
    assert payload["policy_digest"] == bundle.digest

    validator = Draft202012Validator(TOKEN_SCHEMA, format_checker=FormatChecker())
    assert list(validator.iter_errors(payload)) == []

    receipt = EnforcementGateway(signer).authorize_and_simulate(
        decision.decision_token,
        action=decision.authorized_action,
        target=decision.target,
        scope=decision.scope,
    )
    assert receipt["policy_version"] == bundle.version
    assert receipt["policy_digest"] == bundle.digest
    assert receipt["side_effects"] is False
