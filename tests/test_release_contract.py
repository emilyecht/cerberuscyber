"""Combined policy/assurance contract and installed-resource regression checks."""

import base64
from dataclasses import replace
import hashlib
import hmac
from importlib.resources import files
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from cerberus import DecisionTokenSigner, Guardian, PolicyBundle, PolicyBundleError, TokenValidationError
from cerberus.evaluation import run_demo
from tests.test_assurance_hardening import NOW, KEY, request, fixture_assurance

ROOT = Path(__file__).resolve().parents[1]
POLICY = PolicyBundle.load(ROOT / "policies/policies.json")


def signed_payload(payload):
    encoded = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=")
    signature = base64.urlsafe_b64encode(hmac.new(KEY, encoded, hashlib.sha256).digest()).rstrip(b"=")
    return (encoded + b"." + signature).decode()


def approved():
    envelope = request()
    verifier, bundle = fixture_assurance(envelope)
    signer = DecisionTokenSigner(KEY)
    decision = Guardian(POLICY, signer=signer, assurance_verifier=verifier).evaluate(envelope, assurance=bundle, now=NOW)
    assert decision.guardian_decision == "approve"
    return signer, signer.verify(decision.decision_token, now=NOW)


def test_combined_token_binds_both_digests_and_matches_single_schema():
    signer, payload = approved()
    assert payload["token_version"] == "1.3.0"
    assert payload["policy_digest"] == POLICY.digest
    assert len(payload["assurance_digest"]) == 64
    schema = json.loads((ROOT / "schemas/decision-token.schema.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)


@pytest.mark.parametrize("missing", ["policy_digest", "assurance_digest"])
def test_partial_branch_contract_cannot_authorize(missing):
    signer, payload = approved()
    del payload[missing]
    with pytest.raises(TokenValidationError, match="missing"):
        signer.verify(signed_payload(payload), now=NOW)


@pytest.mark.parametrize("old_version", ["1.1.0", "1.2.0"])
def test_legacy_token_versions_are_not_guessed_or_upgraded(old_version):
    signer, payload = approved()
    payload["token_version"] = old_version
    with pytest.raises(TokenValidationError, match="unsupported"):
        signer.verify(signed_payload(payload), now=NOW)


@pytest.mark.parametrize("field,value", [
    ("policy_digest", "z"*64), ("policy_digest", True),
    ("assurance_digest", "F"*64), ("policy_id", None), ("extra_authority", "enterprise"),
])
def test_even_authentic_tokens_must_match_the_combined_contract(field, value):
    signer, payload = approved()
    payload[field] = value
    with pytest.raises(TokenValidationError):
        signer.verify(signed_payload(payload), now=NOW)


def test_policy_digest_tampering_and_direct_constructor_bypass_fail():
    with pytest.raises(PolicyBundleError, match="digest"):
        replace(POLICY, digest="0" * 64)
    invalid = POLICY.to_dict()
    invalid["policies"][0]["allowed_action"] = "wipe_host"
    canonical = json.dumps(invalid, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with pytest.raises(PolicyBundleError):
        PolicyBundle(canonical, "forged", hashlib.sha256(canonical.encode()).hexdigest())


def test_external_policy_mutation_cannot_desynchronize_rules_and_digest():
    data = POLICY.to_dict()
    guardian = Guardian(data)
    data["decision_ttl_seconds"] += 1
    guardian.policy_set["policies"][0]["allowed_action"] = "wipe_host"
    assert guardian.policy_digest == POLICY.digest
    assert guardian.policy_set == POLICY.to_dict()
    with pytest.raises(AttributeError):
        guardian.policy_digest = "0" * 64


def test_packaged_resources_match_reviewed_sources():
    assert files("cerberus").joinpath("data/policies.json").read_bytes() == (ROOT / "policies/policies.json").read_bytes()
    for source in (ROOT / "schemas").glob("*.json"):
        assert files("cerberus").joinpath("data/schemas", source.name).read_bytes() == source.read_bytes()


def test_quick_start_is_closed_simulated_and_contains_no_raw_credentials():
    result = run_demo()
    assert result["cases_passed"] == 4
    assert result["mode"] == "simulation-only"
    assert result["receipt"]["side_effects"] is False
    assert result["receipt"]["policy_digest"] == result["policy_digest"]
    assert len(result["refusals"]) == 3
    assert '"decision_token"' not in json.dumps(result)
    assert '"private_key"' not in json.dumps(result)
