# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Direct checks of the strict gateway; no benchmark-specific production logic."""

from dataclasses import replace
from datetime import datetime, timedelta
from threading import Event, Thread

import pytest

import cerberus as api
from benchmarks.replay_v1.generate import NOW, generate, trust_configuration
from benchmarks.replay_v1.run import PUBLIC_TEST_KEY, verifier


@pytest.fixture
def granted():
    case = generate()[0]
    envelope = api.ActionEnvelope.from_dict(case["setup_request"])
    signer = api.DecisionTokenSigner(PUBLIC_TEST_KEY)
    decision = api.Guardian(api.PolicyBundle.load("policies/policies.json"), signer=signer,
        assurance_verifier=verifier(trust_configuration(envelope))).evaluate(
            envelope, assurance=api.AssuranceBundle.from_dict(case["assurance"]), now=NOW)
    assert decision.guardian_decision == "approve"
    registry = api.TokenAuthorityRegistry()
    registry.register(decision.decision_token, signer, authority_key_ids=frozenset({"trusted-evidence-key"}), now=NOW)
    gateway = api.EnforcementGateway(signer, replay_cache=api.ReplayCache(), authority_registry=registry)
    return envelope, signer, decision.decision_token, registry, gateway


def enforce(granted, envelope=None, **changes):
    original, _, token, _, gateway = granted
    envelope = original if envelope is None else envelope
    return gateway.authorize_and_simulate(token, expected_envelope=envelope,
        action=envelope.action, target=envelope.target, scope=envelope.scope, now=NOW, **changes)


def test_unchanged_registered_authority_succeeds_once(granted):
    receipt = enforce(granted)
    assert receipt["status"] == "simulated" and receipt["side_effects"] is False
    assert receipt["envelope_digest"] == granted[0].digest()
    with pytest.raises(api.EnforcementDenied, match="replay"):
        enforce(granted)


@pytest.mark.parametrize("field,value", [
    ("incident_id", "different-incident"), ("mission_impact", "critical"),
    ("reversible", False), ("requested_scope", "enterprise"),
    ("actor", "different-actor"), ("policy_version", "99.0.0"),
    ("confidence", 0.1), ("nonce", "different-nonce-000000000000"),
])
def test_every_changed_envelope_field_refuses_without_consuming_original(granted, field, value):
    altered = replace(granted[0], **{field: value})
    assert altered.digest() != granted[0].digest()
    with pytest.raises(api.EnforcementDenied, match="envelope digest"):
        enforce(granted, altered)
    assert enforce(granted)["status"] == "simulated"


def test_changed_evidence_digest_is_not_ignored(granted):
    original = granted[0]
    altered = replace(original, evidence=(replace(original.evidence[0], digest="0" * 64),) + original.evidence[1:])
    with pytest.raises(api.EnforcementDenied, match="envelope digest"):
        enforce(granted, altered)


@pytest.mark.parametrize("expected", [None, {}, [], "not-an-envelope"])
def test_missing_or_malformed_expected_envelope_fails_closed(granted, expected):
    envelope, _, token, _, gateway = granted
    with pytest.raises(api.EnforcementDenied):
        gateway.authorize_and_simulate(token, action=envelope.action, target=envelope.target,
            scope=envelope.scope, expected_envelope=expected, now=NOW)


def test_request_scalar_cannot_disagree_with_full_expected_envelope(granted):
    envelope, _, token, _, gateway = granted
    with pytest.raises(api.EnforcementDenied, match="target"):
        gateway.authorize_and_simulate(token, action=envelope.action, target="another-target",
            scope=envelope.scope, expected_envelope=envelope, now=NOW)


def test_revoked_token_refuses_even_with_valid_signature_and_expiry(granted):
    _, signer, token, registry, _ = granted
    payload = signer.verify(token, now=NOW)
    registry.revoke_token(payload["token_id"])
    with pytest.raises(api.EnforcementDenied, match="revoked"):
        enforce(granted)
    registry.register(token, signer, authority_key_ids=frozenset({"trusted-evidence-key"}), now=NOW)
    with pytest.raises(api.EnforcementDenied, match="revoked"):
        enforce(granted)


@pytest.mark.parametrize("key", ["trusted-evidence-key", "prototype-hmac-v1"])
def test_live_authority_revocation_invalidates_already_issued_tokens(granted, key):
    granted[3].revoke_authority(key)
    with pytest.raises(api.EnforcementDenied, match="revoked authority"):
        enforce(granted)


def test_signature_valid_unknown_token_is_not_admitted(granted):
    envelope, signer, token, _, _ = granted
    gateway = api.EnforcementGateway(signer, replay_cache=api.ReplayCache(), authority_registry=api.TokenAuthorityRegistry())
    with pytest.raises(api.EnforcementDenied, match="not registered"):
        gateway.authorize_and_simulate(token, action=envelope.action, target=envelope.target,
            scope=envelope.scope, expected_envelope=envelope, now=NOW)


def test_wrong_purpose_registration_refuses(granted):
    envelope, signer, token, _, _ = granted
    registry = api.TokenAuthorityRegistry()
    registry.register(token, signer, purpose="audit-only", now=NOW)
    gateway = api.EnforcementGateway(signer, replay_cache=api.ReplayCache(), authority_registry=registry)
    with pytest.raises(api.EnforcementDenied, match="wrong purpose"):
        gateway.authorize_and_simulate(token, action=envelope.action, target=envelope.target,
            scope=envelope.scope, expected_envelope=envelope, now=NOW)


def test_missing_or_unavailable_registry_refuses(granted):
    granted[3].close()
    with pytest.raises(api.EnforcementDenied, match="unavailable"):
        enforce(granted)
    granted[4].authority_registry = None
    with pytest.raises(api.EnforcementDenied, match="not configured"):
        enforce(granted)


def test_expiry_is_rechecked_at_enforcement_commit(granted, monkeypatch):
    import cerberus.enforcement
    import cerberus.token
    class IssueClock:
        @staticmethod
        def now(_):
            return NOW
    class CommitClock:
        @staticmethod
        def now(_):
            return NOW + timedelta(seconds=61)
    monkeypatch.setattr(cerberus.token, "datetime", IssueClock)
    monkeypatch.setattr(cerberus.enforcement, "datetime", CommitClock)
    envelope, _, token, _, gateway = granted
    with pytest.raises(api.EnforcementDenied, match="expired before enforcement commit"):
        gateway.authorize_and_simulate(token, action=envelope.action, target=envelope.target,
            scope=envelope.scope, expected_envelope=envelope)
    assert enforce(granted)["status"] == "simulated"


def test_registry_fault_is_a_controlled_refusal(granted):
    class Unavailable:
        def authorize(self, *args, **kwargs):
            raise OSError("registry unavailable")
    granted[4].authority_registry = Unavailable()
    with pytest.raises(api.EnforcementDenied, match="status cannot be verified"):
        enforce(granted)


def test_ledger_registration_cannot_repurpose_or_change_dependencies(granted):
    _, signer, token, registry, _ = granted
    with pytest.raises(api.AuthorityStatusError, match="cannot be changed"):
        registry.register(token, signer, purpose="audit-only", now=NOW)


def test_revocation_and_enforcement_have_a_serialized_boundary(granted):
    _, signer, token, registry, _ = granted
    entered, revoked = Event(), Event()
    payload = signer.verify(token, now=NOW)
    def revoke():
        entered.set()
        registry.revoke_token(payload["token_id"])
        revoked.set()
    with registry.authorize(token, payload, purpose="cerberus.enforcement"):
        worker = Thread(target=revoke)
        worker.start()
        assert entered.wait(2)
        assert not revoked.is_set()
    worker.join(2)
    assert revoked.is_set()
    with pytest.raises(api.EnforcementDenied, match="revoked"):
        enforce(granted)
