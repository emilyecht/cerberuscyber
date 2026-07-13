import json
import unittest
from pathlib import Path

from simulator.cerberus_sim import evaluate

ROOT = Path(__file__).resolve().parents[1]
POLICIES = json.loads((ROOT / "policies" / "policies.json").read_text(encoding="utf-8"))


class GuardianPolicyTests(unittest.TestCase):
    def test_ransomware_isolation_is_approved(self):
        incident = json.loads((ROOT / "simulator" / "scenarios" / "ransomware.json").read_text(encoding="utf-8"))
        result = evaluate(incident, POLICIES)
        self.assertEqual(result["guardian_decision"], "approve")
        self.assertEqual(result["authorized_action"], "isolate_endpoint")

    def test_prompt_injection_is_denied(self):
        incident = json.loads((ROOT / "simulator" / "scenarios" / "prompt_injection.json").read_text(encoding="utf-8"))
        result = evaluate(incident, POLICIES)
        self.assertEqual(result["guardian_decision"], "deny")

    def test_forbidden_action_is_always_denied(self):
        incident = {
            "incident_id": "TEST-FORBIDDEN",
            "threat": "ransomware",
            "confidence": 1.0,
            "signals": ["rapid_file_rewrite", "recovery_deletion_attempt"],
            "proposed_action": "delete_backups",
        }
        result = evaluate(incident, POLICIES)
        self.assertEqual(result["guardian_decision"], "deny")
        self.assertEqual(result["policy"], "GLOBAL-INVARIANT")

    def test_low_confidence_escalates(self):
        incident = {
            "incident_id": "TEST-LOW-CONFIDENCE",
            "threat": "ransomware",
            "confidence": 0.4,
            "signals": ["rapid_file_rewrite", "recovery_deletion_attempt"],
            "proposed_action": "isolate_endpoint",
        }
        result = evaluate(incident, POLICIES)
        self.assertEqual(result["guardian_decision"], "escalate")

    def test_scope_cannot_expand_beyond_policy(self):
        incident = {
            "incident_id": "TEST-SCOPE",
            "threat": "ransomware",
            "confidence": 0.99,
            "signals": ["rapid_file_rewrite", "recovery_deletion_attempt"],
            "proposed_action": "isolate_endpoint",
            "requested_scope": "enterprise",
        }
        result = evaluate(incident, POLICIES)
        self.assertEqual(result["guardian_decision"], "deny")
        self.assertIn("scope", result["reason"])


if __name__ == "__main__":
    unittest.main()
