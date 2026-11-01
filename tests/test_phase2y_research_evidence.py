"""Lock verified Phase2Y code/source status against fabricated expert accuracy."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class Phase2YResearchEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase2y-2026-11-01.json").read_text())

    def test_real_89_test_ci_identity_and_product_working(self):
        e=self.e
        self.assertEqual(e["status"],"PHASE2Y_IMPORT_DECLARATION_CALL_PATH_GUARD_RESEARCH_ONLY")
        self.assertEqual(e["canonical_ci_run"],
                         "https://github.com/Iniwura/falsum/actions/runs/41289002820")
        self.assertEqual(e["canonical_artifact_id"],13076218012)
        v=e["final_ci"]
        self.assertEqual(v["phase2y_static_binding_tests"],28)
        self.assertEqual(v["phase2y_claim_guard_tests"],12)
        self.assertEqual(v["phase2x_ast_tests"],20)
        self.assertEqual(v["phase2w_evidence_tests"],20)
        self.assertEqual(v["phase2w_capture_tests"],9)
        self.assertEqual(sum(v[k] for k in ("phase2y_static_binding_tests",
                           "phase2y_claim_guard_tests","phase2x_ast_tests",
                           "phase2w_evidence_tests","phase2w_capture_tests")),89)
        self.assertEqual(v["total_focused_tests_passed"],89)
        self.assertEqual(v["import_bound_local_false_assertion_review_flags"],1)
        self.assertEqual(v["unbound_fake_lookalike_false_flags"],0)
        self.assertEqual(v["unbound_fake_lookalike_abstentions"],1)
        self.assertEqual(v["final_status"],"success")

    def test_never_fake_runtime_binding_exploits_labels_or_acceptance(self):
        e=self.e
        x=e["program"]
        for field in ("runtime_import_identity_verified","app_execution_verified",
                      "deployed_version_verified","whole_app_security_proven"):
            self.assertFalse(x[field])
        r=e["release_constraints"]
        self.assertTrue(r["research_only"])
        self.assertFalse(r["network_eligible"])
        self.assertFalse(r["registered_evaluator"])
        for field in ("live_security_exploits_verified","production_application_traces",
                      "human_approved_appsec_labels","anjoman_network_eligible_rows"):
            self.assertEqual(r[field],0)


if __name__=="__main__":
    unittest.main()
