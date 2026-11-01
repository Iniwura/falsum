"""Prevent Phase 2X technical source-syntax checks becoming false security accuracy."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class Phase2XEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase2x-2026-11-01.json").read_text(encoding="utf-8"))

    def test_actual_ast_execution_and_adversarial_tests_are_pinned(self):
        e=self.e
        self.assertEqual(e["status"],"PHASE2X_SCOPED_PYTHON_AST_FACT_CHECK_RESEARCH_ONLY")
        self.assertEqual(e["verified_run"],"https://github.com/Iniwura/falsum/actions/runs/41288248962")
        self.assertEqual(e["artifact_id"],13075957276)
        t=e["verified_ci"]
        self.assertEqual(t["total_unit_tests_passed"],49)
        self.assertEqual(t["new_ast_adversarial_tests_passed"],20)
        self.assertEqual(t["original_evidence_gate_tests_passed"],20)
        self.assertEqual(t["original_application_capture_tests_passed"],9)
        self.assertEqual(t["ast_claim_contradictions_detected"],1)
        self.assertEqual(t["exactly_recomputed_ast_packets"],1)
        self.assertEqual(t["final_research_status"],"BLOCKED_AST_SYNTAX_CONFLICT_REQUIRES_HUMAN_REVIEW")
        self.assertEqual(t["ci_conclusion"],"success")

    def test_never_promotes_syntax_to_exploit_or_app_wide_safety(self):
        x=self.e
        self.assertEqual(len(x["implemented"]["supported_python_ast_cases"]),3)
        self.assertFalse(x["constraints"]["call_binding_identity_verified"])
        self.assertFalse(x["constraints"]["call_reachability_verified"])
        self.assertFalse(x["constraints"]["whole_application_absence_proven"])
        self.assertEqual(x["constraints"]["exploits_confirmed"],0)
        self.assertEqual(x["constraints"]["independent_expert_security_labels"],0)
        self.assertEqual(x["constraints"]["real_customer_apps_audited"],0)
        self.assertFalse(x["constraints"]["model_training_performed"])
        self.assertFalse(x["constraints"]["network_eligible"])
        self.assertFalse(x["constraints"]["evaluator_registered"])
        self.assertEqual(x["constraints"]["accepted_Anjoman_evaluation_rows"],0)


if __name__=="__main__":
    unittest.main()
