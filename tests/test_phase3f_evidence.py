"""Regression against falsely promoting source diversity into certified evaluator data."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class RealDiverseSourceEvidence(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase3f-2026-11-01.json").read_text())

    def test_real_external_commit_test_verification_evidence(self):
        e=self.e
        self.assertEqual(e["verified_workflow_url"],
                         "https://github.com/Iniwura/falsum/actions/runs/41353459211")
        self.assertEqual(e["artifact_id"],13102585762)
        self.assertEqual(e["actual_pinned_source_project_revisions_queried"],8)
        self.assertEqual(e["real_patch_source_and_regression_test_pairs_verified"],8)
        self.assertEqual(e["distinct_non_aiohttp_security_family_review_packets"],7)
        self.assertEqual(e["total_prepared_review_packets_phases_3e_and_3f"],12)
        self.assertEqual(len(e["seven_projects"]),7)
        self.assertEqual(len(set(e["seven_projects"])),7)
        self.assertEqual(e["actual_ci"]["targeted_tests_total"],28)
        self.assertEqual(e["actual_ci"]["pipeline_conclusion"],"success")
        self.assertEqual(e["actual_ci"]["permanent_evidence_integrity_tests_passed"],3)

    def test_reserve_fresh_projects_and_never_claim_deployment_or_exploit(self):
        src=self.e["source_integrity"]
        self.assertTrue(src["fresh_tornado_undici_websockets_projects_excluded"])
        self.assertTrue(src["previous_failed_phase3d_inputs_excluded"])
        self.assertTrue(src["source_pinned_conditions_unreviewed"])
        self.assertTrue(src["no_upstream_code_or_test_executed"])
        self.assertEqual(src["verified_production_deployment_versions"],0)
        self.assertEqual(src["confirmed_application_exploits"],0)

    def test_zero_approved_labels_and_release_veto_still_apply(self):
        d=self.e
        self.assertEqual(d["actual_ci"]["accepted_training_pairs"],0)
        self.assertEqual(d["actual_ci"]["independent_human_approved_labels"],0)
        self.assertEqual(d["actual_ci"]["eligible_anjoman_evaluation_rows"],0)
        self.assertFalse(d["actual_ci"]["network_eligible"])
        self.assertFalse(d["model_status"]["model_retrained_in_this_phase"])
        self.assertFalse(d["model_status"]["model_security_accuracy_independently_certified"])
        self.assertTrue(d["model_status"]["model_release_veto_remains"])
        self.assertFalse(d["model_status"]["registered_evaluator"])
        self.assertEqual(d["model_status"]["existing_model_context_reversal_families_correct"],"0/2")


if __name__=="__main__":
    unittest.main()
