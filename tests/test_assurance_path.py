import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cerberus import (
    ACTION_ENVELOPE_VERSION,
    ActionEnvelope,
    AuditLedger,
    DecisionTokenSigner,
    EnforcementDenied,
    EnforcementGateway,
    Evidence,
    Guardian,
)
from cerberus.models import format_time

ROOT = Path(__file__).resolve().parents[1]
POLICIES = json.loads((ROOT / "policies" / "policies.json").read_text(encoding="utf-8"))
TEST_KEY = b"cerberus-prototype-test-key-material-32-bytes-minimum"


class AssurancePathTests(unittest.TestCase):
    def _ransomware_envelope(self) -> ActionEnvelope:
        now = datetime.now(timezone.utc)
        return ActionEnvelope(
            schema_version=ACTION_ENVELOPE_VERSION,
            envelope_id="env-test-ransomware",
            incident_id="INC-TEST-1",
            threat="ransomware",
            confidence=0.99,
            proposed_action="isolate_endpoint",
            target="endpoint:lab-7",
            requested_scope="single_endpoint",
            reversible=True,
            mission_impact="low",
            created_at=format_time(now),
            expires_at=format_time(now + timedelta(minutes=2)),
            nonce="0123456789abcdef0123456789abcdef",
            evidence=(
                Evidence("rapid_file_rewrite", "edr:sensor-1", format_time(now)),
                Evidence("recovery_deletion_attempt", "backup:audit-1", format_time(now)),
            ),
            actor="sentinel:ransomware-test-1",
            required_approval_mode="none",
            policy_version=POLICIES["version"],
        )

    def test_approved_decision_mints_one_time_token(self):
        signer = DecisionTokenSigner(TEST_KEY)
        ledger = AuditLedger()
        envelope = self._ransomware_envelope()
        decision = Guardian(POLICIES, signer=signer, ledger=ledger).evaluate(envelope)

        self.assertEqual(decision.guardian_decision, "approve")
        self.assertIsNotNone(decision.decision_token)
        self.assertEqual(decision.envelope_digest, envelope.digest())
        self.assertTrue(ledger.verify())

        gateway = EnforcementGateway(signer)
        receipt = gateway.authorize_and_simulate(
            decision.decision_token or "",
            action=decision.authorized_action,
            target=decision.target,
            scope=decision.scope,
        )
        self.assertEqual(receipt["status"], "simulated")
        self.assertFalse(receipt["side_effects"])

        with self.assertRaises(EnforcementDenied):
            gateway.authorize_and_simulate(
                decision.decision_token or "",
                action=decision.authorized_action,
                target=decision.target,
                scope=decision.scope,
            )

    def test_target_cannot_change_after_authorization(self):
        signer = DecisionTokenSigner(TEST_KEY)
        decision = Guardian(POLICIES, signer=signer).evaluate(self._ransomware_envelope())
        gateway = EnforcementGateway(signer)
        with self.assertRaises(EnforcementDenied):
            gateway.authorize_and_simulate(
                decision.decision_token or "",
                action=decision.authorized_action,
                target="endpoint:other",
                scope=decision.scope,
            )

    def test_expired_envelope_is_denied(self):
        now = datetime.now(timezone.utc)
        envelope = replace(
            self._ransomware_envelope(),
            created_at=format_time(now - timedelta(minutes=5)),
            expires_at=format_time(now - timedelta(minutes=1)),
        )
        decision = Guardian(POLICIES).evaluate(envelope, now=now)
        self.assertEqual(decision.guardian_decision, "deny")
        self.assertEqual(decision.policy, "GLOBAL-FRESHNESS-INVARIANT")

    def test_same_source_does_not_count_as_independent_evidence(self):
        now = datetime.now(timezone.utc)
        envelope = replace(
            self._ransomware_envelope(),
            evidence=(
                Evidence("rapid_file_rewrite", "edr:shared", format_time(now)),
                Evidence("recovery_deletion_attempt", "edr:shared", format_time(now)),
            ),
        )
        decision = Guardian(POLICIES).evaluate(envelope)
        self.assertEqual(decision.guardian_decision, "escalate")
        self.assertIn("independent", decision.reason)


if __name__ == "__main__":
    unittest.main()
