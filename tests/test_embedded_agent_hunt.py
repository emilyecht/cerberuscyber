import json
import unittest
from pathlib import Path

from cerberus import DecisionTokenSigner, EnforcementGateway, Guardian
from cerberus.hunt import EmbeddedAgentHunter, TelemetryEvent

ROOT = Path(__file__).resolve().parents[1]
POLICIES = json.loads((ROOT / "policies" / "policies.json").read_text(encoding="utf-8"))
SCENARIO = json.loads(
    (ROOT / "simulator" / "scenarios" / "embedded_ai_agent_telemetry.json").read_text(
        encoding="utf-8"
    )
)
TEST_KEY = b"cerberus-embedded-agent-test-key-material-32-bytes-minimum"


class EmbeddedAgentHuntTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hunter = EmbeddedAgentHunter()
        self.events = tuple(
            TelemetryEvent.from_dict(item) for item in SCENARIO["events"]
        )
        self.finding = self.hunter.hunt(self.events, asset=SCENARIO["asset"])
        self.assertIsNotNone(self.finding)

    def test_fixture_is_explicitly_fabricated_and_side_effect_free(self):
        self.assertEqual(SCENARIO["telemetry_classification"], "fabricated")
        self.assertFalse(SCENARIO["side_effects"])
        self.assertIn("sandbox", SCENARIO["asset"])

    def test_sentinel_correlates_requested_behaviors_without_asserting_attribution(self):
        finding = self.finding
        assert finding is not None
        self.assertEqual(finding.threat, "embedded_ai_agent")
        self.assertEqual(finding.recommended_action, "quarantine_workload")
        self.assertEqual(finding.requested_scope, "single_workload")
        self.assertTrue(finding.reversible)
        self.assertEqual(finding.attribution_status, "unverified")
        self.assertGreaterEqual(finding.confidence, 0.9)
        self.assertTrue(
            {
                "anomalous_process_behavior",
                "hidden_persistence",
                "credential_misuse",
                "model_driven_deception",
                "log_tampering",
            }.issubset(set(finding.signals))
        )
        self.assertGreaterEqual(len(finding.independent_sources), 5)

    def test_guardian_escalates_without_two_human_approvals(self):
        finding = self.finding
        assert finding is not None
        envelope = self.hunter.build_action_envelope(
            finding,
            incident_id=SCENARIO["incident_id"],
            human_approvals=("incident-commander",),
        )
        decision = Guardian(POLICIES).evaluate(envelope)
        self.assertEqual(decision.guardian_decision, "escalate")
        self.assertEqual(decision.policy, "CYBER-EA-001")
        self.assertTrue(decision.human_approval_required)

    def test_guardian_refuses_to_authorize_when_a_core_behavior_is_missing(self):
        filtered = tuple(
            event for event in self.events if event.event_type != "model_driven_deception"
        )
        finding = self.hunter.hunt(filtered, asset=SCENARIO["asset"])
        self.assertIsNotNone(finding)
        assert finding is not None
        envelope = self.hunter.build_action_envelope(
            finding,
            incident_id="CRB-2026-MISSING-CORE",
            human_approvals=("incident-commander", "cyber-duty-officer"),
        )
        decision = Guardian(POLICIES).evaluate(envelope)
        self.assertEqual(decision.guardian_decision, "escalate")
        self.assertIsNone(decision.policy)

    def test_two_approvals_allow_only_signed_single_workload_quarantine(self):
        finding = self.finding
        assert finding is not None
        envelope = self.hunter.build_action_envelope(
            finding,
            incident_id=SCENARIO["incident_id"],
            human_approvals=("incident-commander", "cyber-duty-officer"),
        )
        signer = DecisionTokenSigner(TEST_KEY)
        decision = Guardian(POLICIES, signer=signer).evaluate(envelope)
        self.assertEqual(decision.guardian_decision, "approve")
        self.assertEqual(decision.authorized_action, "quarantine_workload")
        self.assertEqual(decision.scope, "single_workload")
        self.assertIsNotNone(decision.decision_token)

        receipt = EnforcementGateway(signer).authorize_and_simulate(
            decision.decision_token or "",
            action="quarantine_workload",
            target=SCENARIO["asset"],
            scope="single_workload",
        )
        self.assertEqual(receipt["status"], "simulated")
        self.assertFalse(receipt["side_effects"])

    def test_weak_or_single_source_telemetry_does_not_create_a_finding(self):
        weak = tuple(
            TelemetryEvent(
                event_id=f"weak-{index}",
                observed_at="2026-07-13T14:40:00Z",
                source_id="single-source:spoofed",
                asset=SCENARIO["asset"],
                event_type=event_type,
                attributes={},
            )
            for index, event_type in enumerate(
                [
                    "anomalous_process_behavior",
                    "hidden_persistence",
                    "credential_misuse",
                    "model_driven_deception",
                    "log_tampering",
                ]
            )
        )
        self.assertIsNone(self.hunter.hunt(weak, asset=SCENARIO["asset"]))


if __name__ == "__main__":
    unittest.main()
